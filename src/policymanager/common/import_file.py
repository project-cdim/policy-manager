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
"""Policy import function common parts"""

import ast
import csv
import json
from io import StringIO
from typing import Any

import starlette
import yaml
from jsonschema import ValidationError, validate

from policymanager.common.const import FileEncode
from policymanager.common.csv_rule import csv_dialect
from policymanager.common.db import DbAccess
from policymanager.common.plugin import Plugin
from policymanager.common.schemas import (
    category_schema,
    enabled_schema,
    format_schema,
    import_file_schema,
    policyId_schema,
    title_schema,
)
from policymanager.common.schemas.combination_schema import validate_category_policy
from policymanager.plugins.base import BasePolicyPlugin


def load_policies(input_: Any, format_: str):
    """load input policies

    Args:
        input_ (Any): input policies
        format_ (str): file format

    Raises:
        ValidationError: Occurs when data validation has been failed

    Returns:
        list: load policy
    """
    policy_list = None
    try:
        load_data = {}
        if format_ == "json":
            load_data = _read_json_file(input_)
        elif format_ == "yaml":
            load_data = _read_yaml_file(input_)
        elif format_ == "csv":
            load_data = _read_csv_file(input_)
        else:  # pragma: no cover
            # Since the argument format is checked in advance, this code will not pass.
            validate(format_, format_schema.format_schema)

        validate(load_data, import_file_schema.import_file_schema)
        policy_list = load_data.get("policies")
    except ValidationError as err:
        if err.message.startswith("Specified file not in "):
            err.message = "File failed to load because specified format " + "is different from file format"
        result = create_failed_result(0, 0, [{"message": err.message}])
        raise ValidationError(result) from err

    return policy_list


def _create_result(status: str, total_cnt: int, count: int, details: list, count_key: str):
    """Create a result with specified status and count key

    Args:
        status (str): status ("completed" or "failed")
        total_cnt (int): total count
        count (int): completed or failed count
        details (list): detailed Results
        count_key (str): key name for count ("completedCount" or "failedCount")

    Returns:
        dict : result
    """
    return {
        "summary": {
            "status": status,
            "totalCount": total_cnt,
            count_key: count,
        },
        "details": details,
    }


def create_completed_result(total_cnt: int, comp_cnt: int, details: list):
    """Create a completed result

    Args:
        total_cnt (int): total count
        comp_cnt (int): complete count
        details (list): detailed Results

    Returns:
        dict : completed results
    """
    return _create_result("completed", total_cnt, comp_cnt, details, "completedCount")


def create_failed_result(total_cnt: int, failed_cnt: int, details: list):
    """Create a failed result

    Args:
        total_cnt (int): total count
        failed_cnt (int): failed count
        details (_type_): detailed Results
    Returns:
        dict : failed result
    """
    return _create_result("failed", total_cnt, failed_cnt, details, "failedCount")


def validate_policies(policy_list: list, logger):
    """validate input policies

    Args:
        policy_list (list): input policy
        logger: Logger instanse

    Returns:
        list: error results
    """
    validation_error_policies = []

    plugin = Plugin(BasePolicyPlugin, DbAccess(logger))
    for policy_data in policy_list:
        try:
            # Validation check of mandatory keys in file policy
            validate(policy_data, import_file_schema.import_policy_schema)
            # Validation check for key values
            if policy_data.get("policyID"):
                validate(policy_data.get("policyID"), policyId_schema.policyId_schema)
            validate(policy_data.get("category"), category_schema.category_schema)
            validate(policy_data.get("title"), title_schema.title_schema)
            validate(policy_data.get("enabled"), enabled_schema.bool_schema)
            # Perform validation through plugin processing.
            plugin.validate_policy(policy=policy_data.get("policy"))

            validate_category_policy(policy_data.get("category"), policy_data.get("policy"))
        except ValidationError as err:
            validation_error_policies.append(
                {
                    "policyID": policy_data.get("policyID", "-"),
                    "message": err.message,
                }
            )
    return validation_error_policies


def validate_duplication(policy_list: list) -> list:
    """Cheking duplication between polices into file

    Args:
        policy_list (list): Polices list

    Raises:
        DuplicatePolicyException: Occurs when policy duplicated within file
    """

    def _get_properties(policy):
        """Get policyID and category

        Args:
            policy (dict): policy data

        Returns:
            tuple(str,str): policyID and category result
        """
        return policy.get("policyID"), policy.get("category")

    details = []
    dupulicate_policy_list = []
    for main_index, policy in enumerate(policy_list):
        id_, category = _get_properties(policy)
        if policy in dupulicate_policy_list:
            # Skip the IDs that are confirmed to be duplicates.
            continue
        sub_category = "hardwareConnectionsLimit" if category == "nodeConfigurationPolicy" else "useThreshold"

        devices = set(policy.get("policy").get(sub_category).keys())
        for target_index, target_policy in enumerate(policy_list):
            target_id, target_category = _get_properties(target_policy)
            if main_index == target_index or policy in dupulicate_policy_list:
                # Skip self-duplication check.
                continue
            # If the same subCategory and device type exist in the file, a duplicate error will occur.
            if category == target_category:
                target_devices = set(target_policy.get("policy").get(sub_category).keys())
                com_devices = devices & target_devices
                _check_for_common_device(
                    com_devices,
                    target_id,
                    details,
                    dupulicate_policy_list,
                    id_,
                    target_policy,
                    sub_category,
                )

    return details


def _check_for_common_device(
    common_device: list,
    target_id: str,
    details: list,
    dupulicate_policy_list: list,
    id_: str,
    target_policy: str,
    sub_category: str,
):
    """Comparing  common device with target policy

    Args:
        common_device (list): common device list
        target_id (str): target policyID for cheking
        details (list): result detail list
        dupulicate_policy_list (list): duplicated devices list
        id_ (str): source policyID
        target_policy (str): target policy
        sub_category (str): policy's subCategory
    """
    if len(common_device) > 0:
        msg = {}
        msg["policyID"] = id_ if id_ is not None and id_ != "" else "-"
        if target_id is not None:
            msg["message"] = f"Specified policy is duplicated with {target_id} in file"
        else:
            msg["message"] = (
                f"Specified policy {sub_category} and {','.join(common_device)} " + "are duplicates in file"
            )
        details.append(msg)
        # Store the policy that has already been confirmed to be duplicated.
        dupulicate_policy_list.append(target_policy)


def _read_json_file(input_: Any) -> dict:
    """Reading inputed json file
    Args:
        input (Any): File that has been loaded
    Raises:
        ValidationError: this error gonna be throw when PermissionError or FileFormatError

    Returns:
        dict: json loaded object
    """
    try:
        if isinstance(input_, str):
            with open(input_, encoding=FileEncode.UTF8) as fh:
                load_data = json.load(fh)
        elif isinstance(input_, starlette.datastructures.UploadFile):
            load_data = json.load(StringIO(str(input_.file.read(), FileEncode.UTF8)))
        else:  # pragma: no cover
            # The code does not pass because cli is of type str and api is of type UploadFile.
            raise FileNotFoundError
    except json.JSONDecodeError as err:
        raise ValidationError("Specified file not in JSON format") from err
    except FileNotFoundError as err:
        raise ValidationError(f"Specified file not found: {input_}") from err
    except Exception as err:
        raise ValidationError(f"Specified file can not open: {input_}") from err

    return load_data


def _read_yaml_file(input_: Any) -> dict:
    """Reading inputed yaml file
    Args:
        input (Any): File that has been loaded
    Raises:
        ValidationError: this error gonna be throw when PermissionError or FileFormatError

    Returns:
        dict: yaml loaded object
    """
    try:
        if _is_json_content(input_):
            raise yaml.YAMLError

        if isinstance(input_, str):
            with open(input_, encoding=FileEncode.UTF8) as fh:
                load_data = yaml.safe_load(fh)
        elif isinstance(input_, starlette.datastructures.UploadFile):
            load_data = yaml.safe_load(StringIO(str(input_.file.read(), FileEncode.UTF8)))
        else:  # pragma: no cover
            # The code does not pass because cli is of type str and api is of type UploadFile.
            raise FileNotFoundError

        if not isinstance(load_data, dict):
            raise ValidationError("Specified file not in yaml format")

    except (yaml.YAMLError, ValidationError) as err:
        raise ValidationError("Specified file not in yaml format") from err
    except FileNotFoundError as err:
        raise ValidationError(f"Specified file not found: {input_}") from err
    except Exception as err:
        raise ValidationError(f"Specified file can not open: {input_}") from err

    return load_data


def _read_csv_file(input_: Any) -> dict:
    """Reading inputed csv file
    Args:
        input (Any): File that has been loaded
    Raises:
        ValidationError: this error gonna be throw when PermissionError or FileFormatError

    Returns:
        dict: csv loaded object
    """
    try:
        load_data = {}
        policy_header = [
            "policyID",
            "category",
            "title",
            "policy",
            "enabled",
            "createdAt",
            "updatedAt",
        ]

        with open(input_, encoding=FileEncode.UTF8) as fh:
            next(fh)
            csv_reader = csv.DictReader(fh, **csv_dialect)

            if csv_reader.fieldnames != policy_header:
                raise csv.Error

            load_data["policies"] = _normalize_csv_data(csv_reader)

    except (StopIteration, csv.Error) as err:
        raise ValidationError("Specified file not in csv format") from err
    except FileNotFoundError as err:
        raise ValidationError(f"Specified file not found: {input_}") from err
    except Exception as err:
        raise ValidationError(f"Specified file can not open: {input_}") from err

    return load_data


def _normalize_csv_data(csv_reader: csv.DictReader) -> list:
    """Normalize read csv data

    Args:
        csv_reader (csv.DictReader): has read csv data

    Returns:
        list: policy list
    """

    policies_data = []
    for row in csv_reader:
        if row["policyID"] == "":
            del row["policyID"]
        row["policy"] = ast.literal_eval(row.get("policy"))
        row["enabled"] = row.get("enabled").lower() in ["true"]
        policies_data.append(row)
    return policies_data


def _is_json_content(input_: Any):
    """Checking for file content is json format weather not.

    Args:
        input_ (Any): File that has been loaded

    Returns:
        bool: Return True if file content is json format. Otherwise return False.
    """
    try:
        if isinstance(input_, str):
            with open(input_, encoding=FileEncode.UTF8) as fh:
                json.load(fh)
        elif isinstance(input_, starlette.datastructures.UploadFile):
            file_data = str(input_.file.read(), FileEncode.UTF8)
            input_.file.seek(0)
            json.load(StringIO(file_data))
        else:  # pragma: no cover
            # The code does not pass because cli is of type str and api is of type UploadFile.
            raise AttributeError
        return True
    except json.JSONDecodeError:
        return False
