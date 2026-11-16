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

import ast
import csv
import datetime
import json
import os
import tempfile
import uuid

import pytest
import yaml

from policymanager.common.custom_exceptions import ExportPolicyException
from policymanager.common.export_file import create_file


@pytest.fixture
def output_json_file():
    """output file"""

    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            pass
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def output_yaml_file():
    """output file"""

    with tempfile.TemporaryDirectory() as dir_path:
        yaml_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.yaml")
        with open(yaml_file, mode="w", encoding="utf-8") as fh:
            pass
        try:
            yield yaml_file
        finally:
            os.remove(yaml_file)


@pytest.fixture
def output_csv_file():
    """output file"""

    with tempfile.TemporaryDirectory() as dir_path:
        csv_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.csv")
        with open(csv_file, mode="w", encoding="utf-8") as fh:
            pass
        try:
            yield csv_file
        finally:
            os.remove(csv_file)


@pytest.mark.parametrize(
    ("is_tempfile", "file_format"),
    [
        (True, "json"),
        (False, "json"),
        (False, "yaml"),
        (True, "yaml"),
        (None, "csv"),
    ],
)
def test_common_file_is_created(
    is_tempfile,
    file_format,
    output_json_file,
    output_yaml_file,
    output_csv_file,
):
    file_path = None
    data = {
        "exportedCount": 1,
        "policies": [
            {
                "policyID": "a21bc21587",
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": datetime.date.today().strftime("%Y/%m/%d"),
                "updatedAt": datetime.date.today().strftime("%Y/%m/%d"),
            },
        ],
    }

    result = None

    if file_format == "json":
        file_path = output_json_file
    elif file_format == "yaml":
        file_path = output_yaml_file
    elif file_format == "csv":
        file_path = output_csv_file

    if is_tempfile:
        file_path = create_file(data, file_format=file_format)
    else:
        assert file_path == create_file(
            data,
            file_format=file_format,
            is_temp_file=is_tempfile,
            output_path=file_path,
        )

    with open(file_path, mode="r", encoding="utf-8") as fp:
        if file_format == "json":
            result = json.load(fp)
        elif file_format == "yaml":
            result = yaml.safe_load(fp)
        elif file_format == "csv":
            next(fp)
            csv_reader = csv.DictReader(
                fp,
                delimiter=",",
                quotechar='"',
                doublequote=True,
                lineterminator="\n",
                quoting=csv.QUOTE_ALL,
                strict=True,
            )

            policies_data = []
            for row in csv_reader:
                if row["policyID"] == "":
                    del row["policyID"]
                row["policy"] = ast.literal_eval(row.get("policy"))
                row["enabled"] = row.get("enabled").lower() in ["true"]
                policies_data.append(row)

            result = {
                "exportedCount": len(policies_data),
                "policies": policies_data,
            }

    assert result == data


def test_common_failure_when_file_creation_failed():
    file_path = "/tmp/11111111/test.json"

    with pytest.raises(ExportPolicyException):
        create_file('{"test": "data"}', output_path=file_path, is_temp_file=False)
