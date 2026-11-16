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
"""Common file generator"""

import csv
import json
import tempfile
from io import TextIOWrapper
from typing import Any

import yaml

from policymanager.common.const import FileEncode
from policymanager.common.csv_rule import csv_dialect
from policymanager.common.custom_exceptions import ExportPolicyException


def create_file(
    data: Any,
    file_format: str = "json",
    output_path: str = "",
    is_temp_file: bool = True,
):
    """Create specified format new file and write data into it

    Args:
        data (Any): Data to write into file
        format (str): File format. Defaults to json
        output_path (str): Specify a file path, if it's not tempfile
        is_temp_file (bool, optional): Create temprary file. Defaults to True

    Raises:
        ExportPolicyException: Occured when had unexpected error while input

    Returns:
        str: File path
    """
    result = None
    try:
        match file_format.lower():
            case "json":
                result = _output_json(data, output_path, is_temp_file)
            case "yaml":
                result = _output_yaml(data, output_path, is_temp_file)
            case "csv":
                result = _output_csv(data, output_path)
            case _:  # pragma: no cover
                # The code does not pass because value range validation is performed,
                # preventing unexpected formats from being specified.
                raise ExportPolicyException("Unexpected format has been specified")

    except Exception as err:
        raise ExportPolicyException(f"Failed to export file: {err}") from err

    return result


def _output_json(data: Any, file_name: str, is_temp_file: bool):
    """Create json format file

    Args:
        data (Any): Output data
        file_name (str): File path
        is_temp_file (bool): Flag for temp file

    Returns:
        str: Path to created file.
    """
    file_path = None
    if is_temp_file:
        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
        ) as export_file:
            json_data = json.dumps(data, indent=4)
            export_file.write(json_data)
            file_path = export_file.name
    else:
        with open(file_name, mode="w", encoding=FileEncode.UTF8) as fh:
            json.dump(data, fh, indent=4)
            file_path = fh.name

    return file_path


def _output_yaml(data: Any, file_name: str, is_temp_file: bool):
    """Create yaml format file

    Args:
        data (Any): Output data
        file_name (str): File path
        is_temp_file (bool): Flag for temp file

    Returns:
        str: Path to created file.
    """
    file_path = None
    if is_temp_file:
        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
        ) as fh:
            file_path = fh.name
            _dump_yaml(data, fh)
    else:
        with open(file_name, mode="w", encoding=FileEncode.UTF8) as fh:
            _dump_yaml(data, fh)
            file_path = fh.name

    return file_path


def _dump_yaml(data: Any, fh: TextIOWrapper):
    """Dump yaml data into the file

    Args:
        data (Any): Data that should be dump
        fh (TextIOWrapper): File handler process
    """
    yaml.safe_dump(
        data,
        fh,
        indent=2,
        allow_unicode=True,
        sort_keys=False,
        explicit_start=True,
        encoding=FileEncode.UTF8,
    )


def _output_csv(data: Any, file_name: str):
    """Create csv format file

    Args:
        data (Any): Output data
        file_name (str): File path

    Returns:
        str: Path to created file.
    """
    file_path = None
    policy_header = [
        "policyID",
        "category",
        "title",
        "policy",
        "enabled",
        "createdAt",
        "updatedAt",
    ]

    with open(file_name, mode="w", encoding=FileEncode.UTF8) as fh:
        fh.write(f"# exportedCount: {data.get('exportedCount')}\n")
        csv_writer = csv.DictWriter(fh, fieldnames=policy_header, restval="", **csv_dialect)
        csv_writer.writeheader()

        # Write each policy to the CSV file
        for policy in data["policies"]:
            csv_writer.writerow(policy)

        file_path = fh.name

    return file_path
