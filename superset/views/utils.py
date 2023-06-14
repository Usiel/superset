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
from collections import defaultdict
from functools import wraps
from typing import Any, Callable, DefaultDict, Optional, Union
from urllib import parse

import msgpack
import pyarrow as pa
import simplejson as json
from flask import flash, g, has_request_context, redirect, request
from flask_appbuilder.security.sqla import models as ab_models
from flask_appbuilder.security.sqla.models import User
from flask_babel import _
from sqlalchemy.orm.exc import NoResultFound
from werkzeug.wrappers.response import Response

import superset.models.core as models
from superset import app, dataframe, db, result_set, viz
from superset.common.db_query_status import QueryStatus
from superset.constants import EXTRA_FORM_DATA_APPEND_KEYS
from superset.datasource.dao import DatasourceDAO
from superset.errors import ErrorLevel, SupersetError, SupersetErrorType
from superset.exceptions import (
    CacheLoadError,
    SerializationError,
    SupersetException,
    SupersetSecurityException,
)
from superset.extensions import cache_manager, feature_flag_manager, security_manager
from superset.legacy import update_time_range
from superset.models.core import Database
from superset.models.dashboard import Dashboard
from superset.models.slice import Slice
from superset.models.sql_lab import Query
from superset.superset_typing import FormData
from superset.utils.core import DatasourceType
from superset.utils.dashboard_filter_scopes_converter import (
    convert_filter_scopes_to_native_filters,
)
from superset.utils.decorators import stats_timing
from superset.viz import BaseViz

logger = logging.getLogger(__name__)
stats_logger = app.config["STATS_LOGGER"]

REJECTED_FORM_DATA_KEYS: list[str] = []
if not feature_flag_manager.is_feature_enabled("ENABLE_JAVASCRIPT_CONTROLS"):
    REJECTED_FORM_DATA_KEYS = ["js_tooltip", "js_onclick_href", "js_data_mutator"]


def sanitize_datasource_data(datasource_data: dict[str, Any]) -> dict[str, Any]:
    if datasource_data:
        datasource_database = datasource_data.get("database")
        if datasource_database:
            datasource_database["parameters"] = {}

    return datasource_data


def bootstrap_user_data(user: User, include_perms: bool = False) -> dict[str, Any]:
    if user.is_anonymous:
        payload = {}
        user.roles = (security_manager.find_role("Public"),)
    elif security_manager.is_guest_user(user):
        payload = {
            "username": user.username,
            "firstName": user.first_name,
            "lastName": user.last_name,
            "isActive": user.is_active,
            "isAnonymous": user.is_anonymous,
        }
    else:
        payload = {
            "username": user.username,
            "firstName": user.first_name,
            "lastName": user.last_name,
            "userId": user.id,
            "isActive": user.is_active,
            "isAnonymous": user.is_anonymous,
            "createdOn": user.created_on.isoformat(),
            "email": user.email,
        }

    if include_perms:
        roles, permissions = get_permissions(user)
        payload["roles"] = roles
        payload["permissions"] = permissions

    return payload


def get_permissions(
    user: User,
) -> tuple[dict[str, list[tuple[str]]], DefaultDict[str, list[str]]]:
    if not user.roles:
        raise AttributeError("User object does not have roles")

    data_permissions = defaultdict(set)
    roles_permissions = security_manager.get_user_roles_permissions(user)
    for _, permissions in roles_permissions.items():
        for permission in permissions:
            if permission[0] in ("datasource_access", "database_access"):
                data_permissions[permission[0]].add(permission[1])
    transformed_permissions = defaultdict(list)
    for perm in data_permissions:
        transformed_permissions[perm] = list(data_permissions[perm])
    return roles_permissions, transformed_permissions


def get_viz(
    form_data: FormData,
    datasource_type: str,
    datasource_id: int,
    force: bool = False,
    force_cached: bool = False,
) -> BaseViz:
    viz_type = form_data.get("viz_type", "table")
    datasource = DatasourceDAO.get_datasource(
        db.session,
        DatasourceType(datasource_type),
        datasource_id,
    )
    viz_obj = viz.viz_types[viz_type](
        datasource, form_data=form_data, force=force, force_cached=force_cached
    )
    return viz_obj


def loads_request_json(request_json_data: str) -> dict[Any, Any]:
    try:
        return json.loads(request_json_data)
    except (TypeError, json.JSONDecodeError):
        return {}


def get_form_data(  # pylint: disable=too-many-locals
    slice_id: Optional[int] = None,
    use_slice_data: bool = False,
    initial_form_data: Optional[dict[str, Any]] = None,
) -> tuple[dict[str, Any], Optional[Slice]]:
    form_data: dict[str, Any] = initial_form_data or {}

    if has_request_context():
        # chart data API requests are JSON
        request_json_data = (
            request.json["queries"][0]
            if request.is_json and "queries" in request.json
            else None
        )

        add_sqllab_custom_filters(form_data)

        request_form_data = request.form.get("form_data")
        request_args_data = request.args.get("form_data")
        if request_json_data:
            form_data.update(request_json_data)
        if request_form_data:
            parsed_form_data = loads_request_json(request_form_data)
            # some chart data api requests are form_data
            queries = parsed_form_data.get("queries")
            if isinstance(queries, list):
                form_data.update(queries[0])
            else:
                form_data.update(parsed_form_data)
        # request params can overwrite the body
        if request_args_data:
            form_data.update(loads_request_json(request_args_data))

    # Fallback to using the Flask globals (used for cache warmup and async queries)
    if not form_data and hasattr(g, "form_data"):
        form_data = getattr(g, "form_data")
        # chart data API requests are JSON
        json_data = form_data["queries"][0] if "queries" in form_data else {}
        form_data.update(json_data)

    if has_request_context():
        url_id = request.args.get("r")
        if url_id:
            saved_url = db.session.query(models.Url).filter_by(id=url_id).first()
            if saved_url:
                url_str = parse.unquote_plus(
                    saved_url.url.split("?")[1][10:], encoding="utf-8"
                )
                url_form_data = loads_request_json(url_str)
                # allow form_date in request override saved url
                url_form_data.update(form_data)
                form_data = url_form_data

    form_data = {k: v for k, v in form_data.items() if k not in REJECTED_FORM_DATA_KEYS}

    # When a slice_id is present, load from DB and override
    # the form_data from the DB with the other form_data provided
    slice_id = form_data.get("slice_id") or slice_id
    slc = None

    # Check if form data only contains slice_id, additional filters and viz type
    valid_keys = ["slice_id", "extra_filters", "adhoc_filters", "viz_type"]
    valid_slice_id = all(key in valid_keys for key in form_data)

    # Include the slice_form_data if request from explore or slice calls
    # or if form_data only contains slice_id and additional filters
    if slice_id and (use_slice_data or valid_slice_id):
        slc = db.session.query(Slice).filter_by(id=slice_id).one_or_none()
        if slc:
            slice_form_data = slc.form_data.copy()
            slice_form_data.update(form_data)
            form_data = slice_form_data

    update_time_range(form_data)
    return form_data, slc


def add_sqllab_custom_filters(form_data: dict[Any, Any]) -> Any:
    """
    SQLLab can include a "filters" attribute in the templateParams.
    The filters attribute is a list of filters to include in the
    request. Useful for testing templates in SQLLab.
    """
    try:
        data = json.loads(request.data)
        if isinstance(data, dict):
            params_str = data.get("templateParams")
            if isinstance(params_str, str):
                params = json.loads(params_str)
                if isinstance(params, dict):
                    filters = params.get("_filters")
                    if filters:
                        form_data.update({"filters": filters})
    except (TypeError, json.JSONDecodeError):
        data = {}


def get_datasource_info(
    datasource_id: Optional[int], datasource_type: Optional[str], form_data: FormData
) -> tuple[int, Optional[str]]:
    """
    Compatibility layer for handling of datasource info

    datasource_id & datasource_type used to be passed in the URL
    directory, now they should come as part of the form_data,

    This function allows supporting both without duplicating code

    :param datasource_id: The datasource ID
    :param datasource_type: The datasource type
    :param form_data: The URL form data
    :returns: The datasource ID and type
    :raises SupersetException: If the datasource no longer exists
    """

    # pylint: disable=superfluous-parens
    if "__" in (datasource := form_data.get("datasource", "")):
        datasource_id, datasource_type = datasource.split("__")
        # The case where the datasource has been deleted
        if datasource_id == "None":
            datasource_id = None

    if not datasource_id:
        raise SupersetException(
            _("The dataset associated with this chart no longer exists")
        )

    datasource_id = int(datasource_id)
    return datasource_id, datasource_type


def apply_display_max_row_limit(
    sql_results: dict[str, Any], rows: Optional[int] = None
) -> dict[str, Any]:
    """
    Given a `sql_results` nested structure, applies a limit to the number of rows

    `sql_results` here is the nested structure coming out of sql_lab.get_sql_results, it
    contains metadata about the query, as well as the data set returned by the query.
    This method limits the number of rows adds a `displayLimitReached: True` flag to the
    metadata.

    :param sql_results: The results of a sql query from sql_lab.get_sql_results
    :param rows: The number of rows to apply a limit to
    :returns: The mutated sql_results structure
    """

    display_limit = rows or app.config["DISPLAY_MAX_ROW"]

    if (
        display_limit
        and sql_results["status"] == QueryStatus.SUCCESS
        and display_limit < sql_results["query"]["rows"]
    ):
        sql_results["data"] = sql_results["data"][:display_limit]
        sql_results["displayLimitReached"] = True
    return sql_results


# see all dashboard components type in
# /superset-frontend/src/dashboard/util/componentTypes.js
CONTAINER_TYPES = ["COLUMN", "GRID", "TABS", "TAB", "ROW"]


def get_dashboard_extra_form_data(slice_id: int, dashboard_id: int) -> dict[str, Any]:
    session = db.session()
    dashboard = session.query(Dashboard).filter_by(id=dashboard_id).one_or_none()

    # is chart in this dashboard?
    if (
        dashboard is None
        or not dashboard.json_metadata
        or not dashboard.slices
        or not any(slc for slc in dashboard.slices if slc.id == slice_id)
    ):
        return {}

    try:
        # does this dashboard have default filters?
        json_metadata = json.loads(dashboard.json_metadata)
        default_filters = json.loads(json_metadata.get("default_filters", "null"))
        native_filter_configuration = json_metadata.get(
            "native_filter_configuration", None
        )

        # TODO: Map to native filters
        filter_boxes_by_id = {
            slc.id: slc for slc in dashboard.slices if slc.viz_type == "filter_box"
        }
        native_filter_configuration.extend(
            convert_filter_scopes_to_native_filters(
                json_metadata,
                {},
                filter_boxes=list(filter_boxes_by_id.values()),
            ),
        )

        if not native_filter_configuration:
            return {}

        layout = json.loads(dashboard.position_json or "{}")

        if isinstance(layout, dict) and isinstance(native_filter_configuration, list):
            return build_extra_form_data(layout, native_filter_configuration, slice_id)
    except json.JSONDecodeError:
        pass

    return {}


def build_extra_form_data(  # pylint: disable=too-many-locals,too-many-nested-blocks
    layout: dict[str, dict[str, Any]],
    native_filter_configuration: list[dict[str, Any]],
    slice_id: int,
) -> dict[str, Any]:
    aggregated_extra_form_data: dict[str, Any] = {}

    # do not apply filters if chart is not in filter's scope or chart is excluded
    for native_filter in native_filter_configuration:
        current_field_scopes = native_filter.get("scope", {})
        scoped_container_ids = current_field_scopes.get("rootPath", ["ROOT_ID"])
        excluded_slice_id = current_field_scopes.get("excluded", [])

        # TODO: Use chartsInScope instead? Sometimes it's not set - why is that?
        for container_id in scoped_container_ids:
            if slice_id not in excluded_slice_id and is_slice_in_container(
                layout, container_id, slice_id
            ):
                extra_form_data = native_filter.get("defaultDataMask", {}).get(
                    "extraFormData"
                )

                if extra_form_data:
                    for key, value in extra_form_data.items():
                        if key in EXTRA_FORM_DATA_APPEND_KEYS:
                            if not aggregated_extra_form_data.get(key):
                                aggregated_extra_form_data[key] = []
                            aggregated_extra_form_data[key] += value
                        else:
                            aggregated_extra_form_data[key] = value

    return aggregated_extra_form_data


def is_slice_in_container(
    layout: dict[str, dict[str, Any]], container_id: str, slice_id: int
) -> bool:
    if container_id == "ROOT_ID":
        return True

    node = layout[container_id]
    node_type = node.get("type")
    if node_type == "CHART" and node.get("meta", {}).get("chartId") == slice_id:
        return True

    if node_type in CONTAINER_TYPES:
        children = node.get("children", [])
        return any(
            is_slice_in_container(layout, child_id, slice_id) for child_id in children
        )

    return False


def check_resource_permissions(
    check_perms: Callable[..., Any],
) -> Callable[..., Any]:
    """
    A decorator for checking permissions on a request using the passed-in function.
    """

    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> None:
            # check if the user can access the resource
            check_perms(*args, **kwargs)
            return f(*args, **kwargs)

        return wrapper

    return decorator


def check_explore_cache_perms(_self: Any, cache_key: str) -> None:
    """
    Loads async explore_json request data from cache and performs access check

    :param _self: the Superset view instance
    :param cache_key: the cache key passed into /explore_json/data/
    :raises SupersetSecurityException: If the user cannot access the resource
    """
    cached = cache_manager.cache.get(cache_key)
    if not cached:
        raise CacheLoadError("Cached data not found")

    check_datasource_perms(_self, form_data=cached["form_data"])


def check_datasource_perms(
    _self: Any,
    datasource_type: Optional[str] = None,
    datasource_id: Optional[int] = None,
    **kwargs: Any,
) -> None:
    """
    Check if user can access a cached response from explore_json.

    This function takes `self` since it must have the same signature as the
    the decorated method.

    :param datasource_type: The datasource type
    :param datasource_id: The datasource ID
    :raises SupersetSecurityException: If the user cannot access the resource
    """

    form_data = kwargs["form_data"] if "form_data" in kwargs else get_form_data()[0]

    try:
        datasource_id, datasource_type = get_datasource_info(
            datasource_id, datasource_type, form_data
        )
    except SupersetException as ex:
        raise SupersetSecurityException(
            SupersetError(
                error_type=SupersetErrorType.FAILED_FETCHING_DATASOURCE_INFO_ERROR,
                level=ErrorLevel.ERROR,
                message=str(ex),
            )
        ) from ex

    if datasource_type is None:
        raise SupersetSecurityException(
            SupersetError(
                error_type=SupersetErrorType.UNKNOWN_DATASOURCE_TYPE_ERROR,
                level=ErrorLevel.ERROR,
                message=_("Could not determine datasource type"),
            )
        )

    try:
        viz_obj = get_viz(
            datasource_type=datasource_type,
            datasource_id=datasource_id,
            form_data=form_data,
            force=False,
        )
    except NoResultFound as ex:
        raise SupersetSecurityException(
            SupersetError(
                error_type=SupersetErrorType.UNKNOWN_DATASOURCE_TYPE_ERROR,
                level=ErrorLevel.ERROR,
                message=_("Could not find viz object"),
            )
        ) from ex

    viz_obj.raise_for_access()


def check_slice_perms(_self: Any, slice_id: int) -> None:
    """
    Check if user can access a cached response from slice_json.

    This function takes `self` since it must have the same signature as the
    the decorated method.

    :param slice_id: The slice ID
    :raises SupersetSecurityException: If the user cannot access the resource
    """

    form_data, slc = get_form_data(slice_id, use_slice_data=True)

    if slc and slc.datasource:
        try:
            viz_obj = get_viz(
                datasource_type=slc.datasource.type,
                datasource_id=slc.datasource.id,
                form_data=form_data,
                force=False,
            )
        except NoResultFound as ex:
            raise SupersetSecurityException(
                SupersetError(
                    error_type=SupersetErrorType.UNKNOWN_DATASOURCE_TYPE_ERROR,
                    level=ErrorLevel.ERROR,
                    message="Could not find viz object",
                )
            ) from ex

        viz_obj.raise_for_access()


def _deserialize_results_payload(
    payload: Union[bytes, str], query: Query, use_msgpack: Optional[bool] = False
) -> dict[str, Any]:
    logger.debug("Deserializing from msgpack: %r", use_msgpack)
    if use_msgpack:
        with stats_timing(
            "sqllab.query.results_backend_msgpack_deserialize", stats_logger
        ):
            ds_payload = msgpack.loads(payload, raw=False)

        with stats_timing("sqllab.query.results_backend_pa_deserialize", stats_logger):
            try:
                reader = pa.BufferReader(ds_payload["data"])
                pa_table = pa.ipc.open_stream(reader).read_all()
            except pa.ArrowSerializationError as ex:
                raise SerializationError("Unable to deserialize table") from ex

        df = result_set.SupersetResultSet.convert_table_to_df(pa_table)
        ds_payload["data"] = dataframe.df_to_records(df) or []

        db_engine_spec = query.database.db_engine_spec
        all_columns, data, expanded_columns = db_engine_spec.expand_data(
            ds_payload["selected_columns"], ds_payload["data"]
        )
        ds_payload.update(
            {"data": data, "columns": all_columns, "expanded_columns": expanded_columns}
        )

        return ds_payload

    with stats_timing("sqllab.query.results_backend_json_deserialize", stats_logger):
        return json.loads(payload)


def get_cta_schema_name(
    database: Database, user: ab_models.User, schema: str, sql: str
) -> Optional[str]:
    func: Optional[Callable[[Database, ab_models.User, str, str], str]] = app.config[
        "SQLLAB_CTAS_SCHEMA_NAME_FUNC"
    ]
    if not func:
        return None
    return func(database, user, schema, sql)


def redirect_with_flash(url: str, message: str, category: str) -> Response:
    flash(message=message, category=category)
    return redirect(url)
