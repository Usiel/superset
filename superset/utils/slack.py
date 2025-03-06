# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.


import logging
from typing import Any, Optional

from flask import current_app
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from superset import cache_manager, feature_flag_manager
from superset.exceptions import SupersetException
from superset.utils.backports import StrEnum

logger = logging.getLogger(__name__)


class SlackChannelTypes(StrEnum):
    PUBLIC = "public_channel"
    PRIVATE = "private_channel"


class SlackClientError(Exception):
    pass


def get_slack_client() -> WebClient:
    token: str = current_app.config["SLACK_API_TOKEN"]
    if callable(token):
        token = token()
    return WebClient(token=token, proxy=current_app.config["SLACK_PROXY"])


def _forced_update_for_channels(forced_update: bool = False) -> bool:
    return forced_update


@cache_manager.cache.memoize(
    timeout=current_app.config["SLACK_CHANNEL_CACHE_TIMEOUT"],
    forced_update=_forced_update_for_channels,
)
def get_channels(forced_update: bool = False) -> list[dict[str, Any]]:
    client = get_slack_client()
    channels = []
    cursor = None
    types = [SlackChannelTypes.PUBLIC, SlackChannelTypes.PRIVATE]
    extra_params = {"types": ",".join(types)}

    while True:
        response = client.conversations_list(
            limit=999, cursor=cursor, exclude_archived=True, **extra_params
        )
        channels.extend(response.data["channels"])
        cursor = response.data.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break

    return channels


def get_channels_with_search(
    search_string: str = "",
    types: Optional[list[SlackChannelTypes]] = None,
    exact_match: bool = False,
) -> list[dict[str, Any]]:
    """
    The slack api is paginated but does not include search, so we need to fetch
    all channels and filter them ourselves
    This will search by slack name or id
    """

    try:
        channels = get_channels()
        if not types or (
            SlackChannelTypes.PUBLIC in types and SlackChannelTypes.PRIVATE in types
        ):
            pass
        elif SlackChannelTypes.PRIVATE in types:
            channels = [c for c in channels if c["is_private"]]
        else:
            channels = [c for c in channels if not c["is_private"]]

        # The search string can be multiple channels separated by commas
        if search_string:
            search_array = [
                search.lower()
                for search in (search_string.split(",") if search_string else [])
            ]

            channels = [
                channel
                for channel in channels
                if any(
                    (
                        search == channel["name"].lower()
                        or search == channel["id"].lower()
                        if exact_match
                        else (
                            search in channel["name"].lower()
                            or search in channel["id"].lower()
                        )
                    )
                    for search in search_array
                )
            ]
        return channels
    except (SlackClientError, SlackApiError) as ex:
        raise SupersetException(f"Failed to list channels: {ex}") from ex


def should_use_v2_api() -> bool:
    if not feature_flag_manager.is_feature_enabled("ALERT_REPORT_SLACK_V2"):
        return False
    try:
        client = get_slack_client()
        client.conversations_list()
        logger.info("Slack API v2 is available")
        return True
    except SlackApiError:
        # use the v1 api but warn with a deprecation message
        logger.warning(
            """Your current Slack scopes are missing `channels:read`. Please add
            this to your Slack app in order to continue using the v1 API. Support
            for the old Slack API will be removed in Superset version 6.0.0."""
        )
        return False


def get_user_avatar(email: str, client: WebClient = None) -> str:
    client = client or get_slack_client()
    try:
        response = client.users_lookupByEmail(email=email)
    except Exception as ex:
        raise SlackClientError(f"Failed to lookup user by email: {email}") from ex

    user = response.data.get("user")
    if user is None:
        raise SlackClientError("No user found with that email.")

    profile = user.get("profile")
    if profile is None:
        raise SlackClientError("User found but no profile available.")

    avatar_url = profile.get("image_192")
    if avatar_url is None:
        raise SlackClientError("Profile image is not available.")

    return avatar_url
