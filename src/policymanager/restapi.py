# Copyright (C) 2026 NEC Corporation.

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
#  under the License.
"""policymanager RESTAPI"""

import os
import sys
from datetime import datetime as dt, timezone
from http import HTTPStatus
from typing import Optional

import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, File, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from jsonschema import ValidationError, validate
from psycopg2 import OperationalError, ProgrammingError
from starlette.middleware.cors import CORSMiddleware

from policymanager.common.config_reader import PolicyConfigReader
from policymanager.common.custom_exceptions import (
    DuplicatePolicyException,
    ExportPolicyException,
    IdNotFoundException,
    InvalidOperationException,
    LogInitializationError,
    PluginLoadException,
    SecretInfoGetException,
    SettingFileValidationError,
    LogSettingFileValidationError,
    UnmatchIdException,
)
from policymanager.common.db import DbAccess, GetAllOption
from policymanager.common.export_file import create_file
from policymanager.common.import_file import (
    create_completed_result,
    create_failed_result,
    load_policies,
    validate_duplication,
    validate_policies,
)
from policymanager.common.logger import Logger, initialize_log
from policymanager.common.plugin import Plugin
from policymanager.common.schemas import (
    enabled_schema,
    filename_schema,
    force_schema,
    format_schema,
    policyId_schema,
    policyIdList_schema,
)
from policymanager.common.schemas.category_schema import validate_get_category
from policymanager.common.schemas.combination_schema import validate_category_policy
from policymanager.common.schemas.fields_schema import validate_get_fields
from policymanager.common.schemas.internal_search_parameter_schema import validate_get_internal_search_parameter
from policymanager.common.schemas.limit_schema import validate_limit
from policymanager.common.schemas.offset_schema import validate_offset
from policymanager.common.schemas.sort_shcema import validate_get_sort
from policymanager.plugins.base import BasePolicyPlugin

from policymanager.common.model import InsertPolicies, UpdaterPolicies, IdList, GetAllPoliciesOptions

app = FastAPI()
BASEURL = "/cdim/api/v1/"
DATABASE = None
JSON_RESPONSE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Content-Type": "application/json; charset=utf-8",
}
YAML_RESPONSE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Content-Type": "application/yaml; charset=utf-8",
}


# Measures to bypass CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Settings to allow response
    # Setting to allow credentials(Cookie, authentication headers, client certificates) in CORS requests
    allow_credentials=True,
    allow_methods=["*"],  # Settings to allow request methods during a CORS request
    allow_headers=["*"],  # Settings to allow headers for CORS requests
)


class NoPrametersException(Exception):
    """For custom Exception validation error when all parameters are empty."""


@app.exception_handler(ValidationError)
def jsonschema_validation_handler(_: Request, exc: ValidationError):  # pylint: disable=W0613
    """If a JsonSchema validation error occurs, call a custom error handler and return a response."""
    return _create_error_response("E10001", f"{exc.message}", HTTPStatus.BAD_REQUEST.value)


@app.exception_handler(SecretInfoGetException)
def request_exception_handler(_: Request, exc: SecretInfoGetException):  # pylint: disable=W0613
    """Returning a response if a custom error handler fails to retrieve secret information."""
    return _create_error_response(
        "E10011", f"Failed to retrieve secret store:{exc.message}", HTTPStatus.INTERNAL_SERVER_ERROR.value
    )


@app.exception_handler(NoPrametersException)
def validate_idlist_exception_handler(_: Request, exc: NoPrametersException):  # pylint: disable=W0613
    """Call the custom error handler when all parameters are empty and return the response."""
    return _create_error_response(
        "E10001", "No parameters.Please specify at least one option", HTTPStatus.BAD_REQUEST.value
    )


@app.exception_handler(PluginLoadException)
def plugin_load_exception_handler(_: Request, exc: PluginLoadException):  # pylint: disable=W0613
    """If loading the plugin fails, the error handler is invoked and a response is returned."""
    return _create_error_response("E10010", f"{exc.message}", HTTPStatus.INTERNAL_SERVER_ERROR.value)


@app.exception_handler(RequestValidationError)
def validate_request_handler(_: Request, exc: RequestValidationError):  # pylint: disable=W0613
    """If loading the plugin fails, the error handler is invoked and a response is returned."""
    return _create_error_response("E10001", exc.errors(), HTTPStatus.BAD_REQUEST.value)


@app.exception_handler(ProgrammingError)
def query_error_handler(_: Request, exc: ProgrammingError):  # pylint: disable=W0613
    """Custom error handler Calls when a query error occurs and returns a response"""
    msg = (
        "Query failed:"
        + exc.pgcode
        + " Check PostgreSQL's error code table [https://pgsql-jp.github.io/current/html/errcodes-appendix.html]"
    )
    return _create_error_response("E10004", msg, HTTPStatus.INTERNAL_SERVER_ERROR.value)


@app.exception_handler(OperationalError)
def db_connection_error_handler(_: Request, exc: OperationalError):  # pylint: disable=W0613
    """Custom error handler to be invoked in case of a DB connection error and return a response."""
    return _create_error_response(
        "E10003", f"Could not connect to PolicyDB: {exc}", HTTPStatus.INTERNAL_SERVER_ERROR.value
    )


@app.exception_handler(LogInitializationError)
def log_initialization_error_handler(_: Request, exc: LogInitializationError):  # pylint: disable=W0613
    """Call the custom error handler and return a response if initialization of the log fails."""
    return _create_error_response("E10012", f"{exc.message}", HTTPStatus.INTERNAL_SERVER_ERROR.value)


@app.exception_handler(LogSettingFileValidationError)
def log_setting_validattion_error_handler(_: Request, exc: LogSettingFileValidationError):
    """Call the custom error handler and return a response, if loading the log configuration file fails"""
    return _create_error_response(
        "E10002", f"Failed to load policymanager_log_config.yaml {exc.message}", HTTPStatus.INTERNAL_SERVER_ERROR.value
    )


def _create_error_response(code: str, message: str, status_code: int) -> JSONResponse:
    """Create a standardized error response.

    Args:
        code: Error code (e.g., "E10001")
        message: Error message
        status_code: HTTP status code

    Returns:
        JSONResponse: Standardized error response
    """
    return JSONResponse(
        status_code=status_code,
        content={"code": code, "message": message},
        headers=JSON_RESPONSE_HEADERS,
    )


def _handle_setting_file_error(err: SettingFileValidationError, logger=None) -> JSONResponse:
    """Handle SettingFileValidationError and return standardized response.

    Args:
        err: SettingFileValidationError instance
        logger: Optional logger instance

    Returns:
        JSONResponse: Error response for config file validation error
    """
    err_message = err.message if hasattr(err, "message") else str(err)
    if logger:
        logger.error(f"[E10002]Failed to load policymanager_config.yaml\n{err_message}")
    return _create_error_response(
        "E10002", f"Failed to load policymanager_config.yaml {err_message}", HTTPStatus.INTERNAL_SERVER_ERROR.value
    )


def _handle_id_not_found_error(policyID: str, logger) -> JSONResponse:  # pylint: disable=C0103
    """Handle IdNotFoundException and return standardized response.

    Args:
        policyID: Policy ID that was not found
        logger: Logger instance

    Returns:
        JSONResponse: Error response for ID not found
    """
    logger.error(f"[E10005]Specified {policyID} is not found", stack_info=False)
    return _create_error_response("E10005", f"Specified {policyID} is not found", HTTPStatus.NOT_FOUND.value)


def _handle_invalid_operation_error(policyID: str, logger) -> JSONResponse:  # pylint: disable=C0103
    """Handle InvalidOperationException and return standardized response.

    Args:
        policyID: Policy ID that is not in disabled state
        logger: Logger instance

    Returns:
        JSONResponse: Error response for invalid operation
    """
    logger.error(f"[E10007]Specified {policyID} is not in disabled state", stack_info=False)
    return _create_error_response(
        "E10007", f"Specified {policyID} is not in disabled state", HTTPStatus.BAD_REQUEST.value
    )


def _handle_duplicate_policy_error(err: DuplicatePolicyException, logger) -> JSONResponse:
    """Handle DuplicatePolicyException and return standardized response.

    Args:
        err: DuplicatePolicyException instance
        logger: Logger instance

    Returns:
        JSONResponse: Error response for duplicate policy
    """
    logger.error(f"[E10008]{err.message}", stack_info=False)
    return _create_error_response("E10008", err.message, HTTPStatus.BAD_REQUEST.value)


def _handle_duplicate_policy_error_content_only(err: DuplicatePolicyException, logger) -> JSONResponse:
    """Handle DuplicatePolicyException for import_file (content only format).

    Args:
        err: DuplicatePolicyException instance
        logger: Logger instance

    Returns:
        JSONResponse: Error response with content as err.message
    """
    logger.error(f"[E10008]{err.message}", stack_info=False)
    return JSONResponse(
        status_code=HTTPStatus.BAD_REQUEST.value,
        content=err.message,
        headers=JSON_RESPONSE_HEADERS,
    )


def _handle_unmatch_id_error(err: UnmatchIdException, logger) -> JSONResponse:
    """Handle UnmatchIdException and return standardized response.

    Args:
        err: UnmatchIdException instance
        logger: Logger instance

    Returns:
        JSONResponse: Error response for unmatched IDs
    """
    logger.error(f"[E10006]IDs {err} is not found", stack_info=False)
    return _create_error_response("E10006", f"IDs {err} is not found", HTTPStatus.BAD_REQUEST.value)


def _handle_export_policy_error(err: ExportPolicyException, logger) -> JSONResponse:
    """Handle ExportPolicyException and return standardized response.

    Args:
        err: ExportPolicyException instance
        logger: Logger instance

    Returns:
        JSONResponse: Error response for export failure
    """
    logger.info(f"[E10009]{err.message}")
    return _create_error_response("E10009", err.message, HTTPStatus.INTERNAL_SERVER_ERROR.value)


def validate_idlist(enableIDList, disableIDList):  # pylint: disable=C0103
    """Check if both the enable/disable parameters are empty.

    Args:
        enableIDList (list): enable id list
        disableIDList (list): disable id list

    Raises:
        NoPrametersException: Error if both are empty
    """
    if enableIDList:
        validate(enableIDList, policyIdList_schema.policyIDList_schema)
    if disableIDList:
        validate(disableIDList, policyIdList_schema.policyIDList_schema)
    if not enableIDList and not disableIDList:
        raise NoPrametersException()


def validate_id(policyID):  # pylint: disable=C0103
    """Validation check of policy ID

    Args:
        policyID (str): policy ID. A 10-character random string generated from a hexadecimal string (0123456789abcdef).

    """
    validate(policyID, policyId_schema.policyId_schema)


def validate_no_param(policies):
    """Check if the parameter for enabling the policy update is empty.

    Args:
        policies (UpdaterPolicies): A data model with category, title, and policy fields

    Raises:
        NoPrametersException: Error if both are empty
    """
    if not policies.category and not policies.title and not policies.policy:
        raise NoPrametersException()


def db_connection(logger: Logger):
    """Connection to the database

    Args:
        logger (Logger): Logger object

    Returns:
        class: DBACCESS class
    """
    return DbAccess(logger)


# fmt: off
@app.get(BASEURL + "policies", response_class=JSONResponse)
def all_get_policies(
    options: GetAllPoliciesOptions = Depends(GetAllPoliciesOptions),
    category: list[str] = Query(["all"]), fields: list[str] = Query(None)
):  # fmt: on
    """Refer to policy (bulk retrieval)
    Retrieve all policy from the policy Management DB that match the specified criteria
     - If no matching targets exist, return an empty list

    Args:
        options (GetAllPoliciesOptions): Options for the bulk retrieval function
        category (list[str]): category.If not specified, all category will be retrieved
        fields (list[str]): Specifies the fields to be retrieved
    Returns:
        JSONResponse: Retrieved policy
    """

    logger = None
    validate_get_category(category)
    validate(options.enabled, enabled_schema.enabled_schema)
    validate_get_internal_search_parameter(options.subCategory, options.device)
    validate_get_fields(fields)
    validate_get_sort(options.sortBy, options.orderBy)
    validate_limit(options.limit)
    validate_offset(options.offset)
    try:
        logger = initialize_log()
        logger.info(f"request param {category} {fields} {options}")
        database = db_connection(logger)
        opts_dict = options.__dict__
        opts_dict["category"] = category
        opts_dict["fields"] = fields
        options_inst = GetAllOption(**opts_dict)
        results = database.get_all_policy(options_inst)
        # Retrieve totalCount. Since get_all_policy is also used in the export function,
        # totalCount is not needed in the export function.
        # Therefore, the part to retrieve totalCount is made into a separate method,
        # and after retrieving totalCount, it is added to the results variable.
        results.update(database.get_policy_count(options_inst))
        response = JSONResponse(status_code=HTTPStatus.OK.value, content=results, headers=JSON_RESPONSE_HEADERS)
    except SettingFileValidationError as err:
        response = _handle_setting_file_error(err, logger)

    return response


@app.post(BASEURL + "policies", response_class=JSONResponse)
def register(policies: InsertPolicies):  # pylint: disable=C0103
    """Add policy
    Register policy in the policy DB.

    Args:
        policies (InsertPolicies): Type of category, title, policy, active/inactive status to be registered

    Returns:
        JSONResponse: ID of the registered policy
    """
    logger = None

    try:
        logger = initialize_log()
        # Perform validation through plugin processing.
        plugin = Plugin(BasePolicyPlugin, db_connection(logger))
        plugin.validate_policy(policy=policies.policy)

        validate_category_policy(policies.category, policies.policy)

        plugin.validate_dupliction(policy=policies.policy)

        logger.info(f"request param :{policies}")
        database = db_connection(logger)
        policyID = database.register(  # pylint: disable=C0103
            policies.category, policies.title, policies.policy, policies.enabled
        )
        response = JSONResponse(
            status_code=HTTPStatus.CREATED.value, content={"policyID": policyID}, headers=JSON_RESPONSE_HEADERS,
        )

    except DuplicatePolicyException as err:
        response = _handle_duplicate_policy_error(err, logger)
    except SettingFileValidationError as err:
        response = _handle_setting_file_error(err, logger)

    return response


@app.put(
    BASEURL + "policies/change-enabled",
    response_model=IdList,
)
def change_enabled(idlist: IdList):
    """Enable/Disable policy
        Update the enable/disable flag of the policy stored in the policy DB.
         - Updates are only made for the specified policy condition ID.
         - If both parameter specifications are empty, a validation error will occur.
         - This API allows simultaneous updates of multiple records,
           but if an error occurs even for one record, all updates will be rolled back.

    Args:
        idlist (IdList): List to enable/disable

    Returns:
        JSONResponse: Whether enabling/disabling was successful
    """

    validate_idlist(idlist.enableIDList, idlist.disableIDList)
    logger = None
    try:
        logger = initialize_log()
        logger.info(f"request param {idlist}")
        database = db_connection(logger)
        database.change_enabled(idlist.enableIDList, idlist.disableIDList)
        response = Response(status_code=HTTPStatus.CREATED.value)
    except UnmatchIdException as err:
        response = _handle_unmatch_id_error(err, logger)
    except SettingFileValidationError as err:
        response = _handle_setting_file_error(err, logger)

    return response


def _delete_file(file_path: str):
    """Delete tmp files exported in the background

    Args:
        file_path (str): delete file path
    """
    os.unlink(file_path)


@app.get(BASEURL + "policies/export", response_class=FileResponse)
def export(
    background_tasks: BackgroundTasks,
    format: str,
    fileName: Optional[str] = None,
):  # pylint: disable=C0103,W0622
    """Export Policy
        Export the retrieved policy
    Args:
        format (str): export policy format
        fileName (str): export file name

    Returns:
        FileResponse: export policy
    """
    logger = None
    validate(format, format_schema.api_schema)
    if fileName == "":
        validate(fileName, filename_schema.filename_schema)
    if fileName is None:
        fileName = "export_" + dt.now(timezone.utc).strftime("%Y-%m-%d-%H-%M-%S") + "." + format
    try:
        logger = initialize_log()
        logger.info(f"request param {format},{fileName}")
        database = db_connection(logger)
        results = database.export()

        file_path = create_file(results, format)
        if format.lower() == "json":
            response_header = JSON_RESPONSE_HEADERS
        else:
            response_header = YAML_RESPONSE_HEADERS
        response = FileResponse(
            status_code=HTTPStatus.OK.value,
            path=file_path,
            filename=fileName,
            headers=response_header,
        )
        background_tasks.add_task(_delete_file, file_path)

    except SettingFileValidationError as err:
        response = _handle_setting_file_error(err, logger)

    except ExportPolicyException as err:
        response = _handle_export_policy_error(err, logger)

    return response


@app.post(BASEURL + "policies/import", response_class=JSONResponse)
def import_file(
    format: str,
    input: UploadFile = File(...),
):  # pylint: disable=C0103,W0622
    """Import policy

    Args:
        format (str): file format
        input (UploadFile): policy file

    Returns:
        _type_: _description_
    """
    logger = None
    policy_list = None
    try:
        logger = initialize_log()
        validate(format, format_schema.api_schema)
        logger.info(f"request param policyID:{format},{input}")
        policy_list = _prepare_import_file(input, format)
        database = db_connection(logger)
        try:
            # Import into the policy management database
            import_detail = database.import_policy(policy_list)
            result = create_completed_result(
                len(policy_list), len(import_detail), import_detail
            )
            response = JSONResponse(
                status_code=HTTPStatus.CREATED.value, content=result, headers=JSON_RESPONSE_HEADERS,
            )
        except DuplicatePolicyException as err:
            result = create_failed_result(
                len(policy_list), len(err.message), err.message
            )
            raise DuplicatePolicyException(result) from err

    except SettingFileValidationError as err:
        response = _handle_setting_file_error(err, logger)

    except ValidationError as err:
        code = HTTPStatus.BAD_REQUEST.value
        if (
            err.message.get("details")[0]
            .get("message")
            .startswith("Specified file can not open")
        ):
            code = HTTPStatus.INTERNAL_SERVER_ERROR.value
        response = JSONResponse(status_code=code, content=err.message, headers=JSON_RESPONSE_HEADERS)
    except DuplicatePolicyException as err:
        response = _handle_duplicate_policy_error_content_only(err, logger)

    return response


def _prepare_import_file(import_: UploadFile, format_: str) -> list:
    """Prepare imported policy list to dump

    Args:
        import_ (UploadFile): Imported file data
        format_ (str): File format

    Raises:
        ValidationError: Occurs when imported file not valid
        DuplicatePolicyException: Occurs when policy duplicated within file

    Returns:
        list: policy list
    """
    # Receive the argument "format" and read the "policy" from the file specified in "input".
    policy_list = load_policies(import_, format_)

    # Check for the presence of mandatory keys, data type validation, and value range verification.
    validate_details = validate_policies(policy_list, initialize_log())
    if len(validate_details) > 0:
        result = create_failed_result(
            len(policy_list), len(validate_details), validate_details
        )
        raise ValidationError(result)

    # Check if there are identical subcategories and device types in the file.
    duplicate_details = validate_duplication(policy_list)
    if len(duplicate_details) > 0:
        result = create_failed_result(
            len(policy_list), len(duplicate_details), duplicate_details
        )
        raise DuplicatePolicyException(result)

    return policy_list


@app.get(BASEURL + "policies/{policyID}", response_class=JSONResponse)
def get_policy(policyID: str):  # pylint: disable=C0103
    """Reference policy (ID specified)
        Retrieve specified policy from the policy DB

    Args:
        policyID (str): ID of the policy to be retrieved.
          A 10-character random string generated from hexadecimal (0123456789abcdef)

    Returns:
        JSONResponse: Retrieved policy
    """

    validate_id(policyID)
    logger = None
    try:
        logger = initialize_log()
        logger.info(f"request param policyID:{policyID}")
        database = db_connection(logger)
        policy = database.get_policy(policyID)
        response = JSONResponse(status_code=HTTPStatus.OK.value, content=policy, headers=JSON_RESPONSE_HEADERS)
    except IdNotFoundException:
        response = _handle_id_not_found_error(policyID, logger)
    except SettingFileValidationError as err:
        response = _handle_setting_file_error(err, logger)

    return response


@app.put(
    BASEURL + "policies/{policyID}",
)
def update(
    policyID: str, policies: UpdaterPolicies, force: Optional[bool] = False
):  # pylint: disable=C0103
    """Update policy
        Update the policy stored in the policy database.
         - Only disabled policy are eligible for update

    Args:
        policyID (str): ID of the policy to update.
          A 10-character random string generated from hexadecimal characters (0123456789abcdef)
        policies (UpdaterPolicies): Registration type, title, policy
        force (bool): Force Update Flag

    Returns:
        JSONResponse: Result of whether the update was successful or not
    """

    validate_id(policyID)
    validate_no_param(policies)
    validate(force, force_schema.bool_schema)
    logger = None
    try:
        logger = initialize_log()
        # Perform validation through plugin processing.
        plugin = Plugin(BasePolicyPlugin, db_connection(logger))
        plugin.validate_policy(policy=policies.policy)
        plugin.validate_contradiction(
            category=policies.category,
            policy=policies.policy,
            policyID=policyID,
        )
        plugin.validate_dupliction(policy=policies.policy, policyID=policyID)

        logger.info(f"request param policyID:{policyID}, {policies},{force}")
        database = db_connection(logger)
        database.update(
            policyID, policies.category, policies.title, policies.policy, force
        )
        response = Response(status_code=HTTPStatus.NO_CONTENT.value)

    except InvalidOperationException:
        response = _handle_invalid_operation_error(policyID, logger)
    except IdNotFoundException:
        response = _handle_id_not_found_error(policyID, logger)
    except SettingFileValidationError as err:
        response = _handle_setting_file_error(err, logger)

    except DuplicatePolicyException as err:
        response = _handle_duplicate_policy_error(err, logger)
    return response


@app.delete(BASEURL + "policies/{policyID}")
def delete(policyID: str, force: Optional[bool] = False):  # pylint: disable=C0103
    """Remove policy
        Delete the policy stored in the policy database.
         - Only disabled policy will be targeted for deletion

    Args:
        policyID (str): ID of the policy to be deleted.
          A random string of 10 characters generated from a hexadecimal string (0123456789abcdef)
        force (bool): Force delete flag

    Returns:
        JSONResponse: Result of whether the deletion was successful
    """

    validate_id(policyID)
    validate(force, force_schema.bool_schema)
    logger = None
    try:
        logger = initialize_log()
        logger.info(f"request param policyID:{policyID},{force}")
        database = db_connection(logger)
        database.delete(policyID, force)
        response = Response(status_code=HTTPStatus.NO_CONTENT.value)

    except InvalidOperationException:
        response = _handle_invalid_operation_error(policyID, logger)
    except IdNotFoundException:
        response = _handle_id_not_found_error(policyID, logger)
    except SettingFileValidationError as err:
        response = _handle_setting_file_error(err, logger)

    return response


def main():
    """Entry point"""
    try:

        server_config = PolicyConfigReader().get_server_config

        uvicorn.run(app, **server_config)
    except SettingFileValidationError as err:
        print(
            f"[E10002]Failed to load policymanager_config.yaml\n{err.message}",
            file=sys.stderr,
        )
    except SecretInfoGetException as err:
        print(
            f"[E10011]Failed to retrieve secret store\n{err.message}",
            file=sys.stderr,
        )
    except KeyboardInterrupt:
        pass
