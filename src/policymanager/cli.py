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
"""CLI-related package"""

# flake8: noqa
import json
import os
import sys
from typing import List, Optional

from psycopg2 import OperationalError, ProgrammingError
from jsonschema import ValidationError, validate
from policymanager.common.cli import AbstractBaseCommandLine

sys.path.append(os.path.abspath("."))

# pylint: disable=wrong-import-position
from policymanager.common.const import ExitCode, FileEncode
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
from policymanager.common.schemas import (  # noqa: E402
    category_schema,
    enabled_schema,
    format_schema,
    policyId_schema,
    policyIdList_schema,
    title_schema,
)
from policymanager.common.schemas.category_schema import validate_get_category
from policymanager.common.schemas.combination_schema import validate_category_policy
from policymanager.common.schemas.fields_schema import validate_get_fields
from policymanager.common.schemas.internal_search_parameter_schema import validate_get_internal_search_parameter
from policymanager.common.schemas.limit_schema import validate_limit
from policymanager.common.schemas.offset_schema import validate_offset
from policymanager.common.schemas.sort_shcema import validate_get_sort
from policymanager.plugins.base import BasePolicyPlugin


class PolicyManagerCLI(AbstractBaseCommandLine):
    """CLI for policy management"""

    def __init__(self, description: str, logger: Logger) -> None:
        """Constructor"""

        self.logger = logger
        super().__init__(description)
        self.db_manager = DbAccess(self.logger)
        self.plugin = Plugin(BasePolicyPlugin, self.db_manager)

    def _add_arguments(self):
        """A method to add command line arguments to argparse:
        The implementation of Argparser's add_arguments is as follows:
        self.parser.add_argument('-f', '--file', type=str, help='File path of the migration procedure')
        """

        self.subparsers = self.parser.add_subparsers(dest="command")

        # Add policy command
        insert_command = self.subparsers.add_parser(
            "insert",
            help="Add the policy condition to the policies management database",
        )
        insert_command.add_argument(
            "-c",
            "--category",
            type=str,
            required=True,
            metavar="CATEGORY",
            help="set [nodeConfigurationPolicy | systemOperationPolicy]",
        )
        insert_command.add_argument(
            "-t",
            "--title",
            type=str,
            required=True,
            metavar="TITLE",
            help="set title as a string",
        )
        insert_command.add_argument(
            "-i",
            "--input",
            type=str,
            required=True,
            metavar="POLICY_JSON_PATH",
            help="set policy as a json file path",
        )
        insert_command.add_argument(
            "--enabled",
            action="store_true",
            help="specified, it can be added in enabled state",
        )

        # Policy enable/disable command
        enable_command = self.subparsers.add_parser(
            "change-enabled", help="Enable/disable registered policy conditions"
        )
        enable_command.add_argument(
            "--enable-id-list",
            type=str,
            metavar="POLICY_ID,POLICY_ID,...,POLICY_ID",
            help=(
                "update enable-id-list as a string. \
                specify either enabled-id-list or disable-id-list"
            ),
        )
        enable_command.add_argument(
            "--disable-id-list",
            type=str,
            metavar="POLICY_ID,POLICY_ID,...,POLICY_ID",
            help="update disable-id-list as a string",
        )

        #  Policy reference, bulk fetch command
        get_command = self.subparsers.add_parser("get", help="Retrieve all policy conditions in bulk")
        get_command.add_argument(
            "--policy-id",
            type=str,
            metavar="POLICY_ID",
            help=(
                "get policyID as a string, not allowed with argument \
                category, enabled, sub-category, device, fields, sort-by, order-by"
            ),
        )
        get_command.add_argument(
            "-c",
            "--category",
            metavar="all|CATEGORY,CATEGORY...,CATEGORY",
            type=str,
            # If a policy-id is specified, a validation error needs to be performed
            # The default value is "all", so it is commented out because
            # it cannot be determined whether "all" is specified as an argument
            # In a later process, if no policy-id is specified, the process inputs "all"
            # default="all"
            help=(
                "specify the category for return information. \
                set [nodeConfigurationPolicy | systemOperationPolicy | all]"
            ),
        )
        get_command.add_argument(
            "--enabled",
            metavar="all|ENABLED",
            # If a policy-id is specified, a validation error needs to be triggered
            # Since the default value is "all", it cannot be determined
            # if "all" was specified as an argument, so it is commented out
            # In the subsequent process, if no policy-id is specified, "all" will be entered
            # default="all",
            help="specify the enabled for return information. set [all | true | false]",
        )
        get_command.add_argument(
            "--sub-category",
            metavar="SUB_CATEGORY",
            type=str,
            help=(
                "specify the sub category for return information. \
                set [hardwareConnectionsLimit | useThreshold]"
            ),
        )
        get_command.add_argument(
            "--device",
            metavar="DEVICE",
            help=(
                "specify the device type for return information. \
                set [cpu | memory | storage |  gpu | fpga | accelerator | dsp | \
                virtualMedia | graphicController | networkInterface]"
            ),
        )
        get_command.add_argument(
            "--fields",
            type=str,
            metavar="COLUMN,COLUMN...COLUMN",
            help=(
                "specify the items to be included in the return information. \
                If not specified, that items are not included. \
                set [policyID | category | title | policy | enabled | createdAt | updatedAt]"
            ),
        )
        get_command.add_argument(
            "--sort-by",
            # If a policy-id is specified, a validation error must be performed.
            # It is commented out because if a default value is set,
            # it cannot determine whether an argument other than policy-id is specified.
            # In a later process, if no policy-id is specified, the createdAt value is entered.
            # default="createdAt"
            type=str,
            metavar="SORT_BY",
            help=(
                "specify the items to be sorted. \
                If not specified, that data will be sorted by createdAt. \
                set [createdAt | updatedAt]"
            ),
        )
        get_command.add_argument(
            "--order-by",
            type=str,
            metavar="ORDER_BY",
            help=("specify the order of the return information. set [asc | desc]"),
        )
        get_command.add_argument(
            "--limit",
            # If a policy-id is specified, a validation error needs to be performed.
            # If a default value is set,
            # it is commented out because it cannot be determined whether an argument other than policy-id is specified.
            # In subsequent processing, if no policy-id is specified, the value 20 will be entered.
            # default=20
            type=int,
            metavar="NUMBER",
            help=(
                "specify the number of policy to be retrieve for return information. \
                specify an integer value greater than or equal to 1"
            ),
        )
        get_command.add_argument(
            "--offset",
            # If a policy-id is specified, a validation error needs to be performed
            # Commented out because if a default value is set,
            # we can't determine whether any arguments other than the policy-id were specified
            # If no policy-id is specified in subsequent processing, a value of 0 will be entered
            # default=0
            type=int,
            metavar="NUMBER",
            help=(
                "specify the row of policy to be retrieve for return information. \
                specify an integer value greater than or equal to 0"
            ),
        )

        # policy update command
        update_command = self.subparsers.add_parser(
            "update",
            help="Update specified policy condition.\
                  Only disabled policy conditions are updated",
        )
        update_command.add_argument(
            "--policy-id",
            type=str,
            metavar="POLICY_ID",
            required=True,
            help="specified a policyID to update for",
        )
        update_command.add_argument(
            "-c",
            "--category",
            type=str,
            metavar="CATEGORY",
            help="set [nodeConfigurationPolicy | systemOperationPolicy]",
        )
        update_command.add_argument(
            "-t",
            "--title",
            type=str,
            metavar="TITLE",
            help="set title as a string",
        )
        update_command.add_argument(
            "-i",
            "--input",
            type=str,
            metavar="POLICY_JSON_PATH",
            help="set policy as a json file path",
        )
        update_command.add_argument(
            "--force",
            action="store_true",
            help="specified it, it can be update even in enabled state",
        )

        # policy command
        delete_command = self.subparsers.add_parser("delete", help="Delete policy condition")
        delete_command.add_argument(
            "--policy-id",
            type=str,
            metavar="POLICY_ID",
            required=True,
            help="specified a policyID to delete for",
        )
        delete_command.add_argument(
            "--force",
            action="store_true",
            help="Specified it, it can be delete even in enabled state",
        )

        # policy export command
        export_command = self.subparsers.add_parser("export", help="Export retrieved policy conditions")
        export_command.add_argument(
            "--format",
            type=str,
            metavar="FORMAT",
            required=True,
            help="set [json | yaml | csv]",
        )
        export_command.add_argument(
            "-o",
            "--output",
            type=str,
            required=True,
            metavar="OUTPUT_FILE_PATH",
            help="export policy as a file path",
        )

        # policy import command
        import_command = self.subparsers.add_parser("import", help="Import specified policy conditions")
        import_command.add_argument(
            "--format",
            type=str,
            metavar="FORMAT",
            required=True,
            help="set [json | yaml | csv]",
        )
        import_command.add_argument(
            "-i",
            "--input",
            type=str,
            required=True,
            metavar="IMPORT_FILE_PATH",
            help="set policy as a file path",
        )

    def run(self):
        """Invoke the executed command with the policy."""
        commands_handler_dict = {
            "insert": self._insert,
            "change-enabled": self._change_enabled,
            "get": self._get,
            "update": self._update,
            "delete": self._delete,
            "export": self._export,
            "import": self._import,
        }

        run_command = commands_handler_dict.get(self.args.command, None)

        if run_command is not None:
            run_command()
        else:
            self.parser.print_help()

    def _insert(self):
        """Addition of policy handling"""
        policy = self._get_validate_json_file(self.args.input)
        self._validate_data(category=self.args.category, title=self.args.title)

        # Perform validation through plugin processing.
        self.plugin.validate_policy(policy=policy)
        validate_category_policy(self.args.category, policy)
        self.plugin.validate_dupliction(policy=policy)

        self.logger.info("Insert start running")
        policyID = self.db_manager.register(  # pylint: disable=invalid-name
            self.args.category, self.args.title, policy, self.args.enabled
        )
        self.logger.info("Completed successfully")
        print(json.dumps({"policyID": policyID}))

    def _change_enabled(self):
        """Process for updating the state of policy

        Raises:
            ValidationError: Raise if both enable-id-list and disable-id-list are empty.
        """
        enable_id_list = None
        disable_id_list = None
        if not self.args.enable_id_list and not self.args.disable_id_list:
            raise ValidationError("No parameters.Please specify at least one option")
        if self.args.enable_id_list:
            enable_id_list = self.args.enable_id_list.split(",")
        if self.args.disable_id_list:
            disable_id_list = self.args.disable_id_list.split(",")
        self._validate_data(enableIDList=enable_id_list, disableIDList=disable_id_list)
        self.logger.info("Change state start running")
        self.db_manager.change_enabled(enable_id_list, disable_id_list)
        self.logger.info("Completed successfully")

        print("Completed successfully")

    def _get(self):
        """policy reference processing"""
        # If a policy ID is specified, the search will be performed using the ID specification feature.
        if self.args.policy_id is not None:
            self._validate_policyid_args()
            self._validate_data(policyID=self.args.policy_id)
            self.logger.info("Get start running")
            print(self.db_manager.get_policy(self.args.policy_id))
            self.logger.info("Completed successfully")
        # If a policy ID is not specified, a bulk retrieval function will be used to perform the search.
        else:
            self._add_default_value()
            self._get_policies()

    def _get_policies(self):
        """get policy when policy-id is not specified."""
        category_list = self.args.category.split(",")
        fields_list = None
        validate_get_category(category_list)
        if self.args.fields:
            fields_list = self.args.fields.split(",")
            validate_get_fields(fields_list)
        validate_get_internal_search_parameter(self.args.sub_category, self.args.device)
        validate_get_sort(self.args.sort_by, self.args.order_by)
        validate_limit(self.args.limit)
        validate_offset(self.args.offset)
        self._validate_data(enabled=self.args.enabled)
        self.logger.info("Get start running")
        policy_option = GetAllOption(
            category=category_list,
            enabled=self.args.enabled,
            subCategory=self.args.sub_category,
            device=self.args.device,
            fields=fields_list,
            sortBy=self.args.sort_by,
            orderBy=self.args.order_by,
            limit=self.args.limit,
            offset=self.args.offset,
        )
        results = self.db_manager.get_all_policy(options=policy_option)
        # Get the totalCount. The get_all_policy method is also used in the export function,
        # where totalCount is not required.
        # Therefore, the part that retrieves the totalCount is made into a separate method,
        # and after retrieving the totalCount,it is added to the results variable.
        results.update(self.db_manager.get_policy_count(options=policy_option))
        print(results)
        self.logger.info("Completed successfully")

    def _update(self):
        """Processing to update policy"""
        if not self.args.input and not self.args.category and not self.args.title:
            raise ValidationError("No parameters.Please specify at least one option")
        policy = None
        if self.args.input:
            policy = self._get_validate_json_file(self.args.input)
        self._validate_data(
            policyID=self.args.policy_id,
            category=self.args.category,
            title=self.args.title,
        )
        self.plugin.validate_policy(policy=policy)
        self.plugin.validate_contradiction(category=self.args.category, policy=policy, policyID=self.args.policy_id)
        self.plugin.validate_dupliction(policy=policy, policyID=self.args.policy_id)

        self.logger.info("Update start running")
        self.db_manager.update(
            self.args.policy_id,
            self.args.category,
            self.args.title,
            policy,
            self.args.force,
        )
        self.logger.info("Completed successfully")
        print("Completed successfully")

    def _delete(self):
        """Process of removing policy"""
        self._validate_data(policyID=self.args.policy_id)
        self.logger.info("Delete start running")
        self.db_manager.delete(self.args.policy_id, self.args.force)
        self.logger.info("Completed successfully")
        print("Completed successfully")

    def _export(self):
        """Export Policy"""
        validate(self.args.format, format_schema.format_schema)
        export_policies = self.db_manager.export()

        create_file(
            data=export_policies,
            file_format=self.args.format,
            output_path=self.args.output,
            is_temp_file=False,
        )

        self.logger.info("Completed successfully")
        print("Completed successfully")

    def _import(self):
        "Import Policy"
        validate(self.args.format, format_schema.format_schema)
        policy_list = None

        # Receive an argument "format" and read the "policy" from the file specified in "input".
        try:
            policy_list = load_policies(self.args.input, self.args.format)
        except ValidationError as err:
            print(json.dumps(err.message), file=sys.stderr)
            sys.exit(ExitCode.VALIDATION_ERROR)

        # Check for the presence of required keys, value type, and value range.
        validate_details = validate_policies(policy_list, self.logger)
        if len(validate_details) > 0:
            result = create_failed_result(len(policy_list), len(validate_details), validate_details)
            print(json.dumps(result), file=sys.stderr)
            sys.exit(ExitCode.VALIDATION_ERROR)

        # Check for the presence of the same subcategory and device type within the file.
        duplicate_details = validate_duplication(policy_list)
        if len(duplicate_details) > 0:
            result = create_failed_result(len(policy_list), len(duplicate_details), duplicate_details)
            print(json.dumps(result), file=sys.stderr)
            sys.exit(ExitCode.DUPLICATE_POLICY_ERROR)

        try:
            # Import into the policy management database.
            import_detail = self.db_manager.import_policy(policy_list)
            result = create_completed_result(len(policy_list), len(import_detail), import_detail)
            self.logger.info("Completed successfully")
            print(json.dumps(result))
        except DuplicatePolicyException as err:
            result = create_failed_result(len(policy_list), len(err.message), err.message)
            print(json.dumps(result), file=sys.stderr)
            sys.exit(ExitCode.DUPLICATE_POLICY_ERROR)

    # pylint: disable=C0103
    def _validate_data(
        self,
        policyID: Optional[str] = None,
        category: Optional[str] = None,
        title: Optional[str] = None,
        enabled: Optional[str] = None,
        enableIDList: Optional[List[str]] = None,
        disableIDList: Optional[List[str]] = None,
    ) -> None:
        """Validate the received data."""

        variables_and_schemas = [
            (category, category_schema.category_schema),
            (title, title_schema.title_schema),
            (policyID, policyId_schema.policyId_schema),
            (enabled, enabled_schema.enabled_schema),
            (enableIDList, policyIdList_schema.policyIDList_schema),
            (disableIDList, policyIdList_schema.policyIDList_schema),
        ]

        for var, schema in variables_and_schemas:
            if var:
                validate(var, schema)

    def _get_validate_json_file(self, file) -> dict:
        """Checking for validaty of json file
        Args:
            file (str): File path that has been loaded
        Raises:
            ValidationError: this error gonna be throw when PermissionError or FileFormatError or \n
            FileNotFound has been occured

        Returns:
            dict: json loaded object
        """
        try:
            with open(file, encoding=FileEncode.UTF8) as fh:
                return json.load(fh)
        except json.JSONDecodeError as err:
            raise ValidationError("Specified file not in JSON format") from err
        except FileNotFoundError as err:
            raise ValidationError(f"Specified file not found: {file}") from err
        except Exception as err:
            raise ValidationError(f"Specified file can not open: {file}") from err

    def _validate_policyid_args(self):
        """validate if any options other than policyID are specified

        Raises:
            ValidationError: option other than policyID is specified
        """
        # Check whether any options other than policy-id are specified using self.args.
        for option_key in self.args.__dict__.keys():
            # Since `self.args` also contains `command` (subcommand) and `policy-id`, if we judge by `not None`,
            # it will get caught by `command` and `policy-id`. Therefore, `command` and `policy-id` are skipped.
            if option_key in ("command", "policy_id"):
                continue
            if self.args.__dict__[option_key] is not None:
                msg = (
                    "Option policy-id not allowed with argument "
                    "category, enabled, sub-category, device, fields, sort-by, order-by"
                )
                raise ValidationError(msg)

    def _add_default_value(self):
        """Set default values for get function options"""
        # If you set default values for options that need default values like category and enabled,
        # you cannot determine if there are options specified other than policy-id. Therefore,
        # options requiring default values are not set. If policy-id is not specified and no value is set,
        # the process will input the default value.
        if self.args.category is None:
            self.args.category = "all"
        if self.args.enabled is None:
            self.args.enabled = "all"
        if self.args.sort_by is None:
            self.args.sort_by = "createdAt"
        if self.args.order_by is None:
            self.args.order_by = "desc"
        if self.args.limit is None:
            self.args.limit = 20
        if self.args.offset is None:
            self.args.offset = 0


def main():
    """Entry point."""
    logger = None
    exit_code = ExitCode.NORMAL
    try:
        logger = initialize_log()
        policy_cli = PolicyManagerCLI("", logger)
        policy_cli.run()
    # pylint: disable=broad-except
    except (
        ValidationError,
        SettingFileValidationError,
        LogSettingFileValidationError,
        OperationalError,
        ProgrammingError,
        IdNotFoundException,
        UnmatchIdException,
        InvalidOperationException,
        DuplicatePolicyException,
        ExportPolicyException,
        PluginLoadException,
        SecretInfoGetException,
        LogInitializationError,
        Exception,
    ) as err:
        err_msg, exit_code = _get_error_msg_code(err)
        if (
            not isinstance(err, LogSettingFileValidationError)
            and not isinstance(err, ValidationError)
            and not isinstance(err, SecretInfoGetException)
            and not isinstance(err, LogInitializationError)
        ):
            logger.error(err_msg, stack_info=False)
        print(err_msg, file=sys.stderr)

    sys.exit(exit_code)


def _get_error_msg_code(error: Exception) -> tuple[str, ExitCode]:
    """Get error message and exit code of an occurred exception.

    Args:
        error (Exception): Occurred error object.

    Returns:
        str: Error message.
        ExitCode: Specified exit code for the occurred error.
    """
    error_map = {
        ValidationError: ("[E10001]", ExitCode.VALIDATION_ERROR),
        SettingFileValidationError: (
            "[E10002]Failed to load policymanager_config.yaml\n{error.message}",
            ExitCode.CONFIG_ERROR,
        ),
        LogSettingFileValidationError: (
            "[E10002]Failed to load policymanager_log_config.yaml\n{error.message}",
            ExitCode.CONFIG_ERROR,
        ),
        OperationalError: (
            "[E10003]Could not connect to PolicyDB: {error}",
            ExitCode.DB_CONNECTION_ERROR,
        ),
        ProgrammingError: (
            "[E10004]Query failed: {error.pgcode}\n"
            "Check PostgreSQL's error code table\n"
            "[https://pgsql-jp.github.io/current/html/errcodes-appendix.html]",
            ExitCode.QUERY_ERROR,
        ),
        IdNotFoundException: (
            "[E10005]Specified {error.message} is not found",
            ExitCode.ID_NOT_FOUND_ERROR,
        ),
        UnmatchIdException: (
            "[E10006]IDs {error.message} is not found",
            ExitCode.UNMATCH_ID_ERROR,
        ),
        InvalidOperationException: (
            "[E10007]Specified {error.message} is not in disabled state",
            ExitCode.INVALID_OPERATION_ERROR,
        ),
        DuplicatePolicyException: (
            "[E10008]{error.message}",
            ExitCode.DUPLICATE_POLICY_ERROR,
        ),
        ExportPolicyException: (
            "[E10009]{error.message}",
            ExitCode.EXPORT_POLICY_ERROR,
        ),
        PluginLoadException: ("[E10010]{error.message}", ExitCode.PLUGIN_LOAD_ERROR),
        SecretInfoGetException: (
            "[E10011]Failed to retrieve secret store\n{error.message}",
            ExitCode.SECRET_REQUEST_ERROR,
        ),
        LogInitializationError: (
            "[E10012]{error.message}",
            ExitCode.LOG_INITIALIZATION_FAILED_ERROR,
        ),
    }

    error_class = type(error)

    for err_key in error_map:
        if issubclass(type(error), err_key):
            error_class = err_key

    if error_class in error_map:
        err_msg, err_code = error_map[error_class]
        err_msg = err_msg.format(error=error)
        if isinstance(error, ValidationError):
            err_msg += error.message.split("\n")[-1]
    else:
        err_msg, err_code = f"Unexpected error: {error}", ExitCode.VALIDATION_ERROR

    return err_msg, err_code


if __name__ == "__main__":
    main()  # pragma: no cover
