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
import logging
import os
import random
import re
import sys
import tempfile
import uuid
from random import randint

import psycopg2
import psycopg2.extras
import pytest
import yaml
from jsonschema import ValidationError
from requests.exceptions import ConnectionError, RequestException, Timeout

from policymanager.common.logger import Logger, initialize_log  # noqa: F401
from policymanager.cli import PolicyManagerCLI, main
from policymanager.common.config_reader import PolicyConfigReader, PolicyLogConfigReader  # noqa: F401
from policymanager.common.const import ExitCode
from policymanager.common.custom_exceptions import (
    DuplicatePolicyException,
    ExportPolicyException,
    IdNotFoundException,
    LogSettingFileValidationError,
    UnmatchIdException,
)
from policymanager.common.db import DbAccess, GetAllOption
from policymanager.common.plugin import Plugin
from tests.conftest import BASE_LOGGING_CONFIG

DB_CONNECT = None


@pytest.fixture
def get_db_instance():
    """Get DBAccess instance"""
    config = {
        "version": 1,
        "formatters": {
            "standard": {"format": "%(asctime)s %(levelname)s %(message)s", "datefmt": "%Y/%m/%d %H:%M:%S.%f"}
        },
        "handlers": {
            "file": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "INFO",
                "formatter": "standard",
                "filename": "/var/log/midc/app_layout_apply.log",
                "maxBytes": 100000000,
                "backupCount": 72,
            },
            "console": {
                "class": "logging.StreamHandler",
                "level": "INFO",
                "formatter": "standard",
                "stream": "ext://sys.stdout",
            },
        },
        "root": {"level": "INFO", "handlers": ["file"]},
    }
    logger = Logger(config)
    return DbAccess(logger)


@pytest.fixture
def get_db_policies():
    """Get DBAccess policies"""
    return [
        {
            "policyID": "123456789b",
            "category": "systemOperationPolicy",
            "title": "test",
            "policy": {"useThreshold": {"gpu": {"value": 80, "unit": "percent", "comparision": "gt"}}},
            "enabled": False,
            "createdAt": "2023-09-28T00:00:00Z",
            "updatedAt": "2023-09-28T00:00:00Z",
        },
        {
            "policyID": "123456789d",
            "category": "systemOperationPolicy",
            "title": "test",
            "policy": {"useThreshold": {"dsp": {"value": 80, "unit": "percent", "comparision": "lt"}}},
            "enabled": True,
            "createdAt": "2023-09-28T00:00:00Z",
            "updatedAt": "2023-09-28T00:00:00Z",
        },
        {
            "policyID": "123456789a",
            "category": "nodeConfigurationPolicy",
            "title": "test",
            "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
            "enabled": False,
            "createdAt": "2023-09-21T00:00:00Z",
            "updatedAt": "2023-09-21T00:00:00Z",
        },
        {
            "policyID": "123456789c",
            "category": "nodeConfigurationPolicy",
            "title": "test",
            "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
            "enabled": True,
            "createdAt": "2023-09-21T00:00:00Z",
            "updatedAt": "2023-09-21T00:00:00Z",
        },
    ]


class FakeDBACCESS:
    """Dummy DBAccess class used for testing"""

    def __init__():
        pass

    def get_all_policy(options: GetAllOption):
        if "all" in options.category:
            polices = {
                "count": 2,
                "policies": [
                    {
                        "policyID": "d8eceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "hardwareConnectionsLimit",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                    {
                        "policyID": "abc10dfaa9",
                        "category": "systemOperationPolicy",
                        "title": "useThreshold",
                        "policy": {
                            "useThreshold": {
                                "cpu": {
                                    "value": 80,
                                    "unit": "percent",
                                    "comparison": "lt",
                                }
                            }
                        },
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            }

        elif "nodeConfigurationPolicy" in options.category and not "systemOperationPolicy" in options.category:
            polices = {
                "count": 1,
                "policies": [
                    {
                        "policyID": "d8eceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "hardwareConnectionsLimit",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    }
                ],
            }

        elif not "nodeConfigurationPolicy" in options.category and "systemOperationPolicy" in options.category:
            polices = {
                "count": 1,
                "policies": [
                    {
                        "policyID": "abc10dfaa9",
                        "category": "systemOperationPolicy",
                        "title": "useThreshold",
                        "policy": {
                            "useThreshold": {
                                "cpu": {
                                    "value": 80,
                                    "unit": "percent",
                                    "comparison": "lt",
                                }
                            }
                        },
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            }
        else:
            polices = {
                "count": 2,
                "policies": [
                    {
                        "policyID": "d8eceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "hardwareConnectionsLimit",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                    {
                        "policyID": "abc10dfaa9",
                        "category": "systemOperationPolicy",
                        "title": "useThreshold",
                        "policy": {
                            "useThreshold": {
                                "cpu": {
                                    "value": 80,
                                    "unit": "percent",
                                    "comparison": "lt",
                                }
                            }
                        },
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            }

        return polices

    def register(category: str, title: str, policy: dict, enabled: bool = False):
        return "a21bc21587"

    def change_enabled(enableIdList: list, disableIdList: list):
        return 1

    def get_policy(policyID: str):
        return {
            "policyID": policyID,
            "category": "nodeConfigurationPolicy",
            "title": "hardwareConnectionsLimit",
            "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            "enabled": True,
            "createdAt": "2023-05-10T00:00:00Z",
            "updatedAt": "2023-05-10T00:00:00Z",
        }

    def update(policyID: str, category: str, title: str, policy: dict, force: bool):
        return randint(0, 1)

    def delete(policyID: str, force: bool):
        return randint(0, 1)

    def export():
        policies = [
            {
                "policyID": "d8eceb14da",
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "abc10dfaa9",
                "category": "systemOperationPolicy",
                "title": "useThreshold",
                "policy": {
                    "useThreshold": {
                        "cpu": {
                            "value": 80,
                            "unit": "percent",
                            "comparison": "lt",
                        }
                    }
                },
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
        ]
        exportPoliceis = {"exportedCount": len(policies), "policeis": policies}
        return exportPoliceis

    def close():
        pass

    def open_db_connection():
        pass

    def check_for_duplication_policy(policy: dict, policyID: str = None, assumed_count: int = 1):
        pass

    def get_policy_count(options: GetAllOption):
        return {"totalCount": 1}


@pytest.fixture
def mock_db_connection(mocker):
    mocker.patch(
        "policymanager.cli.DbAccess",
        mocker.MagicMock(return_value=FakeDBACCESS),
    )


class FakeDBACCESSIdNotFoundException:
    """Dummy DBAccess class used to verify IdNotFoundException"""

    def get_policy(policyID: str):  # py;int:disable=E0213,W0613
        """Dummy method for referencing constraints (by ID)"""
        raise IdNotFoundException(policyID)

    def change_enabled(enableIDList: list, disableIDList: list):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for enabling/disabling constraints"""
        raise UnmatchIdException(enableIDList)

    def update(policyID: str, category: str, title: str, policy: dict, force: bool):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for updating constraints"""
        raise IdNotFoundException(policyID)

    def delete(policyID: str, force: bool):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for deleting constraints"""
        raise IdNotFoundException(policyID)

    def get_policy_count(options: GetAllOption):
        """Dummy method to get the count of policies"""
        return {"totalCount": 1}


@pytest.fixture
def mock_db_connection_idnotfoundexception(mocker):
    """restapi.db_connection mock"""
    mocker.patch(
        "policymanager.cli.DbAccess",
        mocker.MagicMock(return_value=FakeDBACCESSIdNotFoundException),
    )


@pytest.fixture
def get_tmp_nodepolicyjson_file():
    """file fixture jsonfile"""
    json_data = {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_nodepolicy_device_uppercase_json_file():
    """file fixture jsonfile"""
    json_data = {"hardwareConnectionsLimit": {"CPU": {"maxNum": 5, "minNum": 1}}}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_nodepolicy_multydevice_uppercase_json_file():
    """file fixture jsonfile"""
    json_data = {
        "hardwareConnectionsLimit": {
            "CPU": {"maxNum": 5, "minNum": 1},
            "Memory": {"maxNum": 3, "minNum": 1},
            "fpga": {"maxNum": 15, "minNum": 3},
            "NetworkInterface": {"maxNum": 2, "minNum": 1},
        }
    }
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_notExitPolicyjson_file():
    """file fixture jsonfile"""
    json_data = {"unknown": {"dpu": {"maxNum": 15, "minNum": 1}}}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_nodepolicyjson_err_file():
    """file fixture jsonfile"""
    json_data = {"hardwareConnectionsLimit": [{"cpu": {"maxNum": 5, "minNum": 1}}]}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_systempolicyjson_file():
    """file fixture jsonfile"""
    json_data = {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparison": "lt"}}}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_systempolicy_device_uppercase_json_file():
    """file fixture jsonfile"""
    json_data = {"useThreshold": {"GRAPHICCONTROLLER": {"value": 80, "unit": "percent", "comparison": "lt"}}}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_systempolicy_multydevice_uppercase_json_file():
    """file fixture jsonfile"""
    json_data = {
        "useThreshold": {
            "GpU": {"value": 80, "unit": "percent", "comparison": "lt"},
            "cpu": {"value": 50, "unit": "percent", "comparison": "gt"},
            "Accelerator": {"value": 30, "unit": "percent", "comparison": "le"},
            "FPGA": {"value": 30, "unit": "percent", "comparison": "le"},
        }
    }
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_node_error_policyjson_file():
    """file fixture jsonfile"""
    json_data = {"hardwareConnectionsLimit": {"cpu": {"maxNum": 1, "minNum": 5}}}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_system_maxerror_policyjson_file():
    """file fixture jsonfile"""
    json_data = {"useThreshold": {"cpu": {"value": 105, "unit": "percent", "comparison": "lt"}}}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_system_subcategory_array_policyjson_file():
    """file fixture jsonfile"""
    json_data = {"useThreshold": [{"cpu": {"value": 95, "unit": "percent", "comparison": "lt"}}]}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_system_minerror_policyjson_file():
    """file fixture jsonfile"""
    json_data = {"useThreshold": {"cpu": {"value": -5, "unit": "percent", "comparison": "lt"}}}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def incorrect_file_format():
    """file fixture jsonfile"""
    json_data = """{
        "useThreshold": {"cpu": {"value":, "unit": "percent", "comparison": "lt"}}
    }"""
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            fh.write(json_data)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def output_json_file():
    """input file fixture"""

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
    """input file fixture"""

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
    """input file fixture"""

    with tempfile.TemporaryDirectory() as dir_path:
        csv_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.csv")
        with open(csv_file, mode="w", encoding="utf-8") as fh:
            pass
        try:
            yield csv_file
        finally:
            os.remove(csv_file)


@pytest.fixture
def get_tmp_system_comminerror_policyjson_file():
    """file fixture jsonfile"""
    json_data = {"useThreshold": {"cpu": {"value": 0, "unit": "percent", "comparison": "lt"}}}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_system_commaxerror_policyjson_file():
    """file fixture jsonfile"""
    json_data = {"useThreshold": {"cpu": {"value": 100, "unit": "percent", "comparison": "gt"}}}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_system_comerror_patern1_policyjson_file():
    """file fixture jsonfile comparison: ="""
    json_data = {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparison": "="}}}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_system_comerror_patern2_policyjson_file():
    """file fixture jsonfile comparison is empty"""
    json_data = {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparison": ""}}}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_system_comerror_patern3_policyjson_file():
    """file fixture jsonfile comparison: >=="""
    json_data = {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparison": ">=="}}}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_system_comerror_patern4_policyjson_file():
    """file fixture jsonfile comparison: =>"""
    json_data = {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparison": "=>"}}}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_system_comerror_patern5_policyjson_file():
    """file fixture jsonfile comparison: <<"""
    json_data = {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparison": "<<"}}}
    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_dummy_policy():
    return [
        {
            "policyID": "a21bc21587",
            "category": "nodeConfigurationPolicy",
            "title": "hardwareConnectionsLimit",
            "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            "enabled": True,
            "createdAt": datetime.date.today().strftime("%Y/%m/%d"),
            "updatedat": datetime.date.today().strftime("%Y/%m/%d"),
        },
    ]


@pytest.fixture
def get_tmp_import_json_file():
    """file fixture jsonfile"""
    json_data = {
        "exportedCount": 5,
        "policies": [
            {
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"GPU": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14da",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"Cpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14db",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 2, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14dc",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"FpGa": {"maxNum": 3, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffc10dfaa9",
                "category": "systemOperationPolicy",
                "title": "test",
                "policy": {
                    "useThreshold": {
                        "cpu": {"value": 80, "unit": "percent", "comparison": "lt"},
                        "MEMORY": {"value": 90, "unit": "percent", "comparison": "gt"},
                        "Dsp": {"value": 20, "unit": "percent", "comparison": "le"},
                    }
                },
                "enabled": False,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
        ],
    }

    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_import_system_json_file():
    """input file fixture systemOperationPolicy"""
    json_data = {
        "exportedCount": 4,
        "policies": [
            {
                "category": "systemOperationPolicy",
                "title": "test",
                "policy": {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparison": "lt"}}},
                "enabled": False,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14da",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14db",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 2, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14dc",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"fpga": {"maxNum": 3, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
        ],
    }

    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_import_json_content_yaml_file():
    """file fixture jsonfile"""
    json_data = {
        "exportedCount": 5,
        "policies": [
            {
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14da",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14db",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 2, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14dc",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"fpga": {"maxNum": 3, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffc10dfaa9",
                "category": "systemOperationPolicy",
                "title": "test",
                "policy": {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparison": "lt"}}},
                "enabled": False,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
        ],
    }

    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.yaml")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def get_tmp_import_yaml_file():
    """file fixture yaml"""
    yaml_data = {
        "exportedCount": 5,
        "policies": [
            {
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14da",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14db",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 2, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14dc",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"fpga": {"maxNum": 3, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffc10dfaa9",
                "category": "systemOperationPolicy",
                "title": "test",
                "policy": {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparison": "lt"}}},
                "enabled": False,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
        ],
    }

    with tempfile.TemporaryDirectory() as dir_path:
        yaml_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.yaml")
        with open(yaml_file, mode="w", encoding="utf-8") as fh:
            yaml.safe_dump(
                yaml_data,
                fh,
                indent=2,
                allow_unicode=True,
                sort_keys=False,
                explicit_start=True,
                encoding="utf-8",
            )
        try:
            yield yaml_file
        finally:
            os.remove(yaml_file)


@pytest.fixture
def get_tmp_import_csv_file():
    """file fixture csv"""
    data = {
        "exportedCount": 5,
        "policies": [
            {
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14da",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14db",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 2, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14dc",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfigurationPolicy",
                "policy": {"hardwareConnectionsLimit": {"fpga": {"maxNum": 3, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffc10dfaa9",
                "category": "systemOperationPolicy",
                "title": "test",
                "policy": {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparison": "lt"}}},
                "enabled": False,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
        ],
    }

    with tempfile.TemporaryDirectory() as dir_path:
        csv_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.csv")
        policy_header = [
            "policyID",
            "category",
            "title",
            "policy",
            "enabled",
            "createdAt",
            "updatedAt",
        ]
        with open(csv_file, "w", newline="", encoding="utf-8") as fh:
            fh.writelines(f"# exportedCount: {len(data['policies'])}\n")
            csv_writer = csv.DictWriter(
                fh,
                fieldnames=policy_header,
                restval="",
                delimiter=",",
                quotechar='"',
                doublequote=True,
                lineterminator="\n",
                quoting=csv.QUOTE_ALL,
                strict=True,
            )
            csv_writer.writeheader()
            for policy in data["policies"]:
                csv_writer.writerow(policy)
        try:
            yield csv_file
        finally:
            os.remove(csv_file)


@pytest.fixture
def get_tmp_import_csv_file_no_header():
    """file fixture csv"""
    with tempfile.TemporaryDirectory() as dir_path:
        csv_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.csv")
        with open(csv_file, mode="w", encoding="utf-8") as fh:
            csv_data = """# exportedCount: 1
"123456789a","nodeConfigurationPolicy","test","{'hardwareConnectionsLimit': {'gpu': {'maxNum': 5, 'minNum': 1}}}","False","2023-09-21T00:00:00Z","2023-09-21T00:00:00Z"
            """
            fh.write(csv_data)
            fh.flush()
        try:
            yield csv_file
        finally:
            os.remove(csv_file)


@pytest.fixture
def get_tmp_import_csv_file_only_header():
    """file fixture csv"""
    with tempfile.TemporaryDirectory() as dir_path:
        csv_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.csv")
        with open(csv_file, mode="w", encoding="utf-8") as fh:
            csv_data = """"policyID","category","title","policy","enabled","createdAt","updatedAt"
            """
            fh.write(csv_data)
            fh.flush()
        try:
            yield csv_file
        finally:
            os.remove(csv_file)


@pytest.fixture
def get_tmp_import_csv_file_only_comment():
    """file fixture csv"""
    with tempfile.TemporaryDirectory() as dir_path:
        csv_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.csv")
        with open(csv_file, mode="w", encoding="utf-8") as fh:
            csv_data = """# exportedCount: 1 """
            fh.write(csv_data)
            fh.flush()
        try:
            yield csv_file
        finally:
            os.remove(csv_file)


@pytest.fixture
def get_tmp_import_csv_file_only_data():
    """file fixture csv"""
    with tempfile.TemporaryDirectory() as dir_path:
        csv_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.csv")
        with open(csv_file, mode="w", encoding="utf-8") as fh:
            csv_data = """"123456789a","nodeConfigurationPolicy","test","{'hardwareConnectionsLimit': {'gpu': {'maxNum': 5, 'minNum': 1}}}","False","2023-09-21T00:00:00Z","2023-09-21T00:00:00Z"
            """
            fh.write(csv_data)
            fh.flush()
        try:
            yield csv_file
        finally:
            os.remove(csv_file)


@pytest.fixture
def get_tmp_import_empty_csv_file():
    """file fixture csv"""
    with tempfile.TemporaryDirectory() as dir_path:
        csv_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.csv")
        with open(csv_file, mode="w", encoding="utf-8") as fh:
            csv_data = ""
            fh.write(csv_data)
            fh.flush()
        try:
            yield csv_file
        finally:
            os.remove(csv_file)


@pytest.fixture
def get_tmp_import_csv_file_no_comment():
    """file fixture csv"""
    with tempfile.TemporaryDirectory() as dir_path:
        csv_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.csv")
        with open(csv_file, mode="w", encoding="utf-8") as fh:
            csv_data = """"policyID","category","title","policy","enabled","createdAt","updatedAt"
"123456789a","nodeConfigurationPolicy","test","{'hardwareConnectionsLimit': {'gpu': {'maxNum': 5, 'minNum': 1}}}","False","2023-09-21T00:00:00Z","2023-09-21T00:00:00Z"
"123456789b","nodeConfigurationPolicy","test2","{'hardwareConnectionsLimit': {'cpu': {'maxNum': 5, 'minNum': 1}}}","True","2023-08-21T00:00:00Z","2023-11-21T00:00:00Z"
"""
            fh.write(csv_data)
            fh.flush()
        try:
            yield csv_file
        finally:
            os.remove(csv_file)


@pytest.fixture
def tmp_import_csv_file_pol0_err():
    """file fixture jsonfile"""
    data = {"exportedCount": 0, "policies": []}

    with tempfile.TemporaryDirectory() as dir_path:
        csv_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.csv")
        policy_header = [
            "policyID",
            "category",
            "title",
            "policy",
            "enabled",
            "createdAt",
            "updatedAt",
        ]
        with open(csv_file, "w", newline="", encoding="utf-8") as fh:
            fh.writelines(f"# exportedCount: {len(data['policies'])}\n")
            csv_writer = csv.DictWriter(
                fh,
                fieldnames=policy_header,
                restval="",
                delimiter=",",
                quotechar='"',
                doublequote=True,
                lineterminator="\n",
                quoting=csv.QUOTE_ALL,
                strict=True,
            )
            csv_writer.writeheader()
            for policy in data["policies"]:
                csv_writer.writerow(policy)
        try:
            yield csv_file
        finally:
            os.remove(csv_file)


@pytest.fixture
def get_policyID():
    return [
        {
            "policyID": "a21bc21587",
            "category": "nodeConfigurationPolicy",
            "title": "hardwareConnectionsLimit",
            "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            "enabled": True,
            "createdAt": datetime.date.today(),
            "updatedat": datetime.date.today(),
        }
    ]


@pytest.fixture
def init_db_instance(docker_services):
    docker_services.wait_until_responsive(timeout=30.0, pause=0.1, check=lambda: is_postgresql_ready())
    yield DB_CONNECT
    DB_CONNECT.close()


def is_postgresql_ready():
    """Cheking docker working

    Returns:
        _type_: _description_
    """
    try:
        db_config = {
            "dbname": "PolicyDB",
            "user": "user01",
            "password": "P@ssw0rd",
            "host": "localhost",
            "port": 5435,
        }
        global DB_CONNECT
        DB_CONNECT = psycopg2.connect(**db_config)
        return True
    except Exception:
        return False


class TestImport:
    def test_cmd_import_success_when_id_key_missing(self, init_db_instance, mocker, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query="Delete from policies")
        init_db_instance.commit()
        test_data = [
            {
                "exportedCount": 1,
                "policies": [
                    {
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where the policy data does not have a policyID (single entry)
                ],
            },
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                    {
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where multiple policy data entries do not have a policyID
                ],
            },
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where the first policy data entry does not have a policyID (multiple entries)
                ],
            },
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                    {
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where the second policy data entry does not have a policyID (multiple entries)
                ],
            },
            {
                "exportedCount": 1,
                "policies": [
                    {
                        "policyID": "123456789a",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"memory": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where the policyID in the input data matches one in the database
                ],
            },
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "123456789a",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"memory": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where the policyID in the input data matches the first entry in the database
                ],
            },
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"memory": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                    {
                        "policyID": "123456789a",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where the policyID in the input data matches the second entry in the database
                ],
            },
        ]

        for json_data in test_data:
            with tempfile.TemporaryDirectory() as dir_path:
                json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
                with open(json_file, mode="w", encoding="utf-8") as fh:
                    json.dump(json_data, fh, indent=4)
                args = ["import", "--format", "json", "--input", json_file]
                sys.argv = ["cli.py", *args]
                with pytest.raises(SystemExit) as excinfo:
                    main()
                assert excinfo.value.code == 0

            out, err = capfd.readouterr()
            res = json.loads(out)
            assert "summary" in res
            assert "details" in res
            assert res.get("summary")["status"] == "completed"
            assert res.get("summary")["totalCount"] == len(json_data["policies"])
            assert res.get("summary")["completedCount"] == len(json_data["policies"])
            assert len(res.get("details")) == len(json_data["policies"])

            cursor.execute(query="SELECT * from policies")
            assert cursor.rowcount == len(json_data["policies"])
            assert err == ""

            cursor.execute(query="Delete from policies")
            init_db_instance.commit()

    def test_cmd_import_success_when_id_key_duplicate(self, init_db_instance, mocker, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query="Delete from policies;")
        insert_query = (
            "INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )
        params = [
            "123456789a",
            "systemOperationPolicy",
            "NodeConfigurationPolicy",
            json.dumps({"useThreshold": {"gpu": {"value": 50, "unit": "percent", "comparison": "gt"}}}),
            False,
            "2023-05-10T00:00:00Z",
            "2023-05-10T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        test_data = [
            {
                "exportedCount": 1,
                "policies": [
                    {
                        "policyID": "123456789a",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"memory": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where the input data's policyID matches an ID already in the database
                ],
            },
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "123456789a",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"memory": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where the first entry in the input data's policyID matches an ID in the database
                ],
            },
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"memory": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                    {
                        "policyID": "123456789a",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where the second entry in the input data's policyID matches an ID in the database
                ],
            },
        ]
        for json_data in test_data:
            with tempfile.TemporaryDirectory() as dir_path:
                json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
                with open(json_file, mode="w", encoding="utf-8") as fh:
                    json.dump(json_data, fh, indent=4)
                args = ["import", "--format", "json", "--input", json_file]
                sys.argv = ["cli.py", *args]
                with pytest.raises(SystemExit) as excinfo:
                    main()
                assert excinfo.value.code == 0

            out, err = capfd.readouterr()
            res = json.loads(out)
            assert "summary" in res
            assert "details" in res
            assert res.get("summary")["status"] == "completed"
            assert res.get("summary")["totalCount"] == len(json_data["policies"])
            assert res.get("summary")["completedCount"] == len(json_data["policies"])
            assert len(res.get("details")) == len(json_data["policies"])

            cursor.execute(query="SELECT * from policies where policyID != '123456789a'")
            assert cursor.rowcount == len(json_data["policies"])
            assert err == ""

            cursor.execute(query="Delete from policies where policyID != '123456789a'")
            init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "import",
                    "--format",
                    "json",
                    "--input",
                ]
            ),
            (
                [
                    "import",
                    "--format",
                    "yaml",
                    "--input",
                ]
            ),
            (
                [
                    "import",
                    "--format",
                    "csv",
                    "--input",
                ]
            ),
        ],
    )
    def test_cmd_import_success(
        self,
        init_db_instance,
        mocker,
        args,
        capfd,
        get_tmp_import_json_file,
        get_tmp_import_yaml_file,
        get_tmp_import_csv_file,
    ):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query="Delete from policies;")
        init_db_instance.commit()
        if args[2] == "json":
            sys.argv = ["cli.py", *args, get_tmp_import_json_file]
        elif args[2] == "yaml":
            sys.argv = ["cli.py", *args, get_tmp_import_yaml_file]
        elif args[2] == "csv":
            sys.argv = ["cli.py", *args, get_tmp_import_csv_file]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 0

        out, err = capfd.readouterr()
        res = json.loads(out)
        assert "summary" in res
        assert "details" in res
        assert res.get("summary")["status"] == "completed"
        assert res.get("summary")["totalCount"] == 5
        assert res.get("summary")["completedCount"] == 5
        assert len(res.get("details")) == 5

        cursor.execute(query="SELECT * from policies")
        assert cursor.rowcount == 5
        assert err == ""

        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

    def test_cmd_import_failure_when_format_error_json(self, init_db_instance, mocker, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query="Delete from policies;")
        init_db_instance.commit()
        with tempfile.TemporaryDirectory() as dir_path:
            json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
            with open(json_file, mode="w", encoding="utf-8") as fh:
                yaml_data = """
                ---
                exportedCount: 1
                policies:
                 - policyID: ffeceb14da
                   category: nodeConfigurationPolicy
                   title: NodeConfigurationPolicy
                   policy:
                    hardwareConnectionsLimit:
                     cpu:
                      maxNum: 5
                      minNum: 1
                   enabled: true
                   createdAt: 2023-05-10T00:00:00Z
                   updatedAt: 2023-05-10T00:00:00Z
                """
                fh.write(yaml_data)
            args = ["import", "--format", "json", "--input", json_file]
            sys.argv = ["cli.py", *args]
            with pytest.raises(SystemExit) as excinfo:
                main()
            assert excinfo.value.code == 1

            out, err = capfd.readouterr()
            assert json.loads(err) == {
                "summary": {"status": "failed", "totalCount": 0, "failedCount": 0},
                "details": [
                    {"message": "File failed to load because specified format is different from file format"},
                ],
            }
            assert out == ""
            cursor.execute(query="SELECT * from policies where policyID = 'ffeceb14da';")
            assert cursor.rowcount == 0
            cursor.execute(query=f"Delete from policies where policyID in ('ffeceb14da');")
            init_db_instance.commit()

    def test_cmd_import_failure_when_format_error_yaml(
        self,
        init_db_instance,
        mocker,
        capfd,
    ):
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query="Delete from policies;")
        init_db_instance.commit()
        with tempfile.TemporaryDirectory() as dir_path:
            yaml_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.yaml")
            with open(yaml_file, mode="w", encoding="utf-8") as fh:
                csv_data = """
                category,title,policy/hardwareConnectionsLimit/gpu/maxNum,policy/hardwareConnectionsLimit/gpu/minNum
                nodeConfigurationPolicy,NodeConfigurationPolicy,5,1
                """
                fh.write(csv_data)
            args = ["import", "--format", "yaml", "--input", yaml_file]
            sys.argv = ["cli.py", *args]
            with pytest.raises(SystemExit) as excinfo:
                main()
            assert excinfo.value.code == 1

            out, err = capfd.readouterr()
            assert json.loads(err) == {
                "summary": {"status": "failed", "totalCount": 0, "failedCount": 0},
                "details": [
                    {"message": "File failed to load because specified format is different from file format"},
                ],
            }
            assert out == ""
            cursor.execute(query="SELECT * from policies where policyID = 'ffeceb14da';")
            assert cursor.rowcount == 0
            cursor.execute(query=f"Delete from policies where policyID in ('ffeceb14da');")
            init_db_instance.commit()

    def test_cmd_import_failure_when_invalid_file_format_yaml(self, init_db_instance, mocker, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query="Delete from policies;")
        init_db_instance.commit()
        with tempfile.TemporaryDirectory() as dir_path:
            yaml_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
            with open(yaml_file, mode="w", encoding="utf-8") as fh:
                # cpu key is missing a colon `:`
                yaml_data = """
                ---
                exportedCount: 1
                policies:
                 - policyID: ffeceb14da
                   category: nodeConfigurationPolicy
                   title: NodeConfigurationPolicy
                   policy:
                    hardwareConnectionsLimit:
                     cpu
                      maxNum: 5
                      minNum: 1
                   enabled: true
                   createdAt: 2023-05-10T00:00:00Z
                   updatedAt: 2023-05-10T00:00:00Z
                """
                fh.write(yaml_data)
                fh.flush()

                args = ["import", "--format", "yaml", "--input", yaml_file]
                sys.argv = ["cli.py", *args]
                with pytest.raises(SystemExit) as excinfo:
                    main()
                assert excinfo.value.code == 1

                out, err = capfd.readouterr()
                assert json.loads(err) == {
                    "summary": {"status": "failed", "totalCount": 0, "failedCount": 0},
                    "details": [
                        {"message": "File failed to load because specified format is different from file format"},
                    ],
                }
                assert out == ""
                cursor.execute(query="SELECT * from policies where policyID = 'ffeceb14da';")
                assert cursor.rowcount == 0
                cursor.execute(query=f"Delete from policies where policyID in ('ffeceb14da');")
                init_db_instance.commit()

    def test_cmd_import_failure_when_missing_required_key_json(self, init_db_instance, mocker, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()
        test_datas = [
            # category incorrect
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "kategory": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            # no category key
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        # "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            # title incorrect
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "titles": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            # # no title key
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            # policy incorrect
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "Policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            # subcategory is array
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": [{"cpu": {"maxNum": 5, "minNum": 1}}]},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            # no policy key
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "titles": "NodeConfigurationPolicy",
                        # "policy": {
                        #     "hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}
                        # },
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            # enabled incorrect
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enable": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            # no enabled key
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        # "enable": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            {"exportedCount": 0, "policies": []},
            # policies empty
        ]

        for json_data in test_datas:
            with tempfile.TemporaryDirectory() as dir_path:
                json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
                with open(json_file, mode="w", encoding="utf-8") as fh:
                    json.dump(json_data, fh, indent=4)
                args = ["import", "--format", "json", "--input", json_file]
                sys.argv = ["cli.py", *args]
                with pytest.raises(SystemExit) as excinfo:
                    main()
                assert excinfo.value.code == 1

                out, err = capfd.readouterr()
                res = json.loads(err)
                policy_numb = len(json_data.get("policies"))

                assert "failed" == res.get("summary").get("status")
                assert policy_numb == res.get("summary").get("totalCount")
                assert policy_numb == res.get("summary").get("failedCount")
                assert 1 == len(res.get("details"))

                cursor.execute(query="SELECT * from policies where policyID = 'ffeceb14da';")
                assert cursor.rowcount == 0
                cursor.execute(query=f"Delete from policies where policyID in ('ffeceb14da');")
                init_db_instance.commit()

    def test_cmd_import_failure_when_missing_required_key_yaml(self, init_db_instance, mocker, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()
        test_datas = [
            # category incorrect
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "kategory": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            # no category key
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        # "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            # title incorrect
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "titles": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            # no title key
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "titles": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            # policy incorrect
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "titles": "NodeConfigurationPolicy",
                        "Policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            # no policy key
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "titles": "NodeConfigurationPolicy",
                        # "policy": {
                        #     "hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}
                        # },
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            # enabled incorrect
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enable": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            # no enabled key
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        # "enable": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            {"exportedCount": 0, "policies": []},
            # policies empty
        ]

        for json_data in test_datas:
            with tempfile.TemporaryDirectory() as dir_path:
                yaml_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.yaml")
                with open(yaml_file, mode="w", encoding="utf-8") as fh:
                    yaml.safe_dump(
                        json_data,
                        fh,
                        indent=2,
                        allow_unicode=True,
                        sort_keys=False,
                        encoding="utf-8",
                    )
                args = ["import", "--format", "yaml", "--input", yaml_file]
                sys.argv = ["cli.py", *args]
                with pytest.raises(SystemExit) as excinfo:
                    main()
                assert excinfo.value.code == 1

                out, err = capfd.readouterr()
                res = json.loads(err)
                policy_numb = len(json_data.get("policies"))

                assert "failed" == res.get("summary").get("status")
                assert policy_numb == res.get("summary").get("totalCount")
                assert policy_numb == res.get("summary").get("failedCount")
                assert 1 == len(res.get("details"))

                cursor.execute(query="SELECT * from policies where policyID = 'ffeceb14da';")
                assert cursor.rowcount == 0
                cursor.execute(query=f"Delete from policies where policyID in ('ffeceb14da');")
                init_db_instance.commit()

    def test_cmd_import_failure_when_duplicate_data_exists(self, init_db_instance, mocker, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()
        json_data = [
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                    {
                        "policyID": "ffeceb14db",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfigurationPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                ],
            },
            {
                "exportedCount": 4,
                "policies": [
                    {
                        "policyID": "123456789a",
                        "category": "nodeConfigurationPolicy",
                        "title": "testTitle",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                    },
                    {
                        "policyID": "123456789b",
                        "category": "nodeConfigurationPolicy",
                        "title": "testTitle",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                    },
                    {
                        "policyID": "123456789c",
                        "category": "nodeConfigurationPolicy",
                        "title": "testTitle",
                        "policy": {"hardwareConnectionsLimit": {"memory": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                    },
                    {
                        "policyID": "123456789d",
                        "category": "nodeConfigurationPolicy",
                        "title": "testTitle",
                        "policy": {"hardwareConnectionsLimit": {"memory": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                    },
                ],
            },
        ]

        for test_data in json_data:
            with tempfile.TemporaryDirectory() as dir_path:
                json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
                with open(json_file, mode="w", encoding="utf-8") as fh:
                    json.dump(test_data, fh, indent=4)
                args = ["import", "--format", "json", "--input", json_file]
                sys.argv = ["cli.py", *args]
                with pytest.raises(SystemExit) as excinfo:
                    main()

                out, err = capfd.readouterr()
                res = json.loads(err)
                policy_numb = len(test_data.get("policies"))
                assert "failed" == res.get("summary").get("status")
                assert policy_numb == res.get("summary").get("totalCount")
                assert res.get("summary").get("failedCount") in [1, 2]
                assert len(res.get("details")) in [1, 2]

    def test_cmd_import_failure_when_duplicate_data_exists_json(self, init_db_instance, mocker, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()
        json_data = {
            "exportedCount": 2,
            "policies": [
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "NodeConfigurationPolicy",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                    "enabled": True,
                    "createdAt": "2023-05-10T00:00:00Z",
                    "updatedAt": "2023-05-10T00:00:00Z",
                },
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "NodeConfigurationPolicy",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                    "enabled": True,
                    "createdAt": "2023-05-10T00:00:00Z",
                    "updatedAt": "2023-05-10T00:00:00Z",
                },
            ],
        }

        with tempfile.TemporaryDirectory() as dir_path:
            json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
            with open(json_file, mode="w", encoding="utf-8") as fh:
                json.dump(json_data, fh, indent=4)
            args = ["import", "--format", "json", "--input", json_file]
            sys.argv = ["cli.py", *args]
            with pytest.raises(SystemExit) as excinfo:
                main()

            out, err = capfd.readouterr()
            assert excinfo.value.code == 8
            assert json.loads(err) == {
                "summary": {"status": "failed", "totalCount": 2, "failedCount": 1},
                "details": [
                    {
                        "policyID": "-",
                        "message": "Specified policy hardwareConnectionsLimit and cpu are duplicates in file",
                    },
                ],
            }

    def test_cmd_import_failure_when_duplicate_data_exists_yaml(self, init_db_instance, mocker, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()
        json_data = {
            "exportedCount": 2,
            "policies": [
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "NodeConfigurationPolicy",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                    "enabled": True,
                    "createdAt": "2023-05-10T00:00:00Z",
                    "updatedAt": "2023-05-10T00:00:00Z",
                },
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "NodeConfigurationPolicy",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                    "enabled": True,
                    "createdAt": "2023-05-10T00:00:00Z",
                    "updatedAt": "2023-05-10T00:00:00Z",
                },
            ],
        }

        with tempfile.TemporaryDirectory() as dir_path:
            yaml_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.yaml")
            with open(yaml_file, mode="w", encoding="utf-8") as fh:
                yaml.safe_dump(
                    json_data,
                    fh,
                    indent=2,
                    allow_unicode=True,
                    sort_keys=False,
                    encoding="utf-8",
                )
            args = ["import", "--format", "yaml", "--input", yaml_file]
            sys.argv = ["cli.py", *args]
            with pytest.raises(SystemExit) as excinfo:
                main()

            out, err = capfd.readouterr()
            assert excinfo.value.code == 8
            assert json.loads(err) == {
                "summary": {"status": "failed", "totalCount": 2, "failedCount": 1},
                "details": [
                    {
                        "policyID": "-",
                        "message": "Specified policy hardwareConnectionsLimit and cpu are duplicates in file",
                    },
                ],
            }

    def test_cmd_import_failure_when_partial_policy_id_in_duplicate_data(self, init_db_instance, mocker, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()
        json_data = {
            "exportedCount": 2,
            "policies": [
                {
                    "policyID": "ffeceb14da",
                    "category": "nodeConfigurationPolicy",
                    "title": "NodeConfigurationPolicy",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                    "enabled": True,
                    "createdAt": "2023-05-10T00:00:00Z",
                    "updatedAt": "2023-05-10T00:00:00Z",
                },
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "NodeConfigurationPolicy",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                    "enabled": True,
                    "createdAt": "2023-05-10T00:00:00Z",
                    "updatedAt": "2023-05-10T00:00:00Z",
                },
            ],
        }

        with tempfile.TemporaryDirectory() as dir_path:
            json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
            with open(json_file, mode="w", encoding="utf-8") as fh:
                json.dump(json_data, fh, indent=4)
            args = ["import", "--format", "json", "--input", json_file]
            sys.argv = ["cli.py", *args]
            with pytest.raises(SystemExit) as excinfo:
                main()

            out, err = capfd.readouterr()
            assert excinfo.value.code == 8
            assert json.loads(err) == {
                "summary": {"status": "failed", "totalCount": 2, "failedCount": 1},
                "details": [
                    {
                        "policyID": "ffeceb14da",
                        "message": "Specified policy hardwareConnectionsLimit and cpu are duplicates in file",
                    },
                ],
            }

    def test_cmd_import_failure_when_invalid_format_argument(self, init_db_instance, mocker, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()
        json_data = {
            "exportedCount": 1,
            "policies": [
                {
                    "policyID": "ffeceb14da",
                    "category": "nodeConfigurationPolicy",
                    "title": "NodeConfigurationPolicy",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                    "enabled": True,
                    "createdAt": "2023-05-10T00:00:00Z",
                    "updatedAt": "2023-05-10T00:00:00Z",
                }
            ],
        }

        with tempfile.TemporaryDirectory() as dir_path:
            json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
            with open(json_file, mode="w", encoding="utf-8") as fh:
                json.dump(json_data, fh, indent=4)
            args = ["import", "--format", "xml", "--input", json_file]
            sys.argv = ["cli.py", *args]
            with pytest.raises(SystemExit) as excinfo:
                main()

            out, err = capfd.readouterr()
            assert excinfo.value.code == 1
            err.startswith("[E10001]")

    def test_cmd_import_failure_when_nonexistent_file_json(self, init_db_instance, mocker, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        json_file = "/tmp/not_existed.json"
        args = ["import", "--format", "json", "--input", json_file]
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()

        out, err = capfd.readouterr()

        assert out == ""
        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        assert json.loads(err) == {
            "summary": {"status": "failed", "totalCount": 0, "failedCount": 0},
            "details": [
                {"message": f"Specified file not found: {json_file}"},
            ],
        }

    def test_cmd_import_failure_when_nonexistent_file_yaml(self, init_db_instance, mocker, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        yaml_file = "/tmp/not_existed.yaml"
        args = ["import", "--format", "yaml", "--input", yaml_file]
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()

        out, err = capfd.readouterr()
        assert out == ""
        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        assert json.loads(err) == {
            "summary": {"status": "failed", "totalCount": 0, "failedCount": 0},
            "details": [
                {"message": f"Specified file not found: {yaml_file}"},
            ],
        }

    def test_cmd_import_failure_when_file_content_mismatch_json_yaml(
        self, init_db_instance, mocker, capfd, get_tmp_import_json_content_yaml_file
    ):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        args = [
            "import",
            "--format",
            "yaml",
            "--input",
            get_tmp_import_json_content_yaml_file,
        ]
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()

        out, err = capfd.readouterr()
        assert out == ""
        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        assert json.loads(err) == {
            "summary": {"status": "failed", "totalCount": 0, "failedCount": 0},
            "details": [
                {"message": "File failed to load because specified format is different from file format"},
            ],
        }

    def test_cmd_import_failure_when_nonexistent_file_csv(self, init_db_instance, mocker, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        csv_file = "/tmp/not_existed.csv"
        args = ["import", "--format", "csv", "--input", csv_file]
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()

        out, err = capfd.readouterr()
        assert out == ""
        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        assert json.loads(err) == {
            "summary": {"status": "failed", "totalCount": 0, "failedCount": 0},
            "details": [
                {"message": f"Specified file not found: {csv_file}"},
            ],
        }

    def test_cmd_import_failure_when_csv_policies_zero(
        self, capfd, init_db_instance, mocker, tmp_import_csv_file_pol0_err
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        args = ["import", "--format", "csv", "--input", tmp_import_csv_file_pol0_err]
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()

        out, err = capfd.readouterr()
        assert out == ""
        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        err_data = json.loads(err)
        assert err_data.get("summary").get("status") == "failed"
        assert err_data.get("summary").get("totalCount") == 0
        assert err_data.get("summary").get("failedCount") == 0

    def test_cmd_import_failure_when_csv_header_missing(
        self, capfd, init_db_instance, mocker, get_tmp_import_csv_file_no_header
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        args = [
            "import",
            "--format",
            "csv",
            "--input",
            get_tmp_import_csv_file_no_header,
        ]
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()

        out, err = capfd.readouterr()
        assert out == ""
        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        err_data = json.loads(err)
        assert err_data.get("summary").get("status") == "failed"
        assert err_data.get("summary").get("totalCount") == 0
        assert err_data.get("summary").get("failedCount") == 0
        assert err_data.get("details")[0].get("message").startswith("File failed to load because specified format")

    def test_cmd_import_failure_when_csv_only_header(
        self, capfd, init_db_instance, mocker, get_tmp_import_csv_file_only_header
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        args = [
            "import",
            "--format",
            "csv",
            "--input",
            get_tmp_import_csv_file_only_header,
        ]
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()

        out, err = capfd.readouterr()
        assert out == ""
        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        err_data = json.loads(err)
        assert err_data.get("summary").get("status") == "failed"
        assert err_data.get("summary").get("totalCount") == 0
        assert err_data.get("summary").get("failedCount") == 0
        assert err_data.get("details")[0].get("message").startswith("File failed to load because specified format")

    def test_cmd_import_failure_when_csv_only_data(
        self, capfd, init_db_instance, mocker, get_tmp_import_csv_file_only_data
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        args = [
            "import",
            "--format",
            "csv",
            "--input",
            get_tmp_import_csv_file_only_data,
        ]
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()

        out, err = capfd.readouterr()
        assert out == ""
        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        err_data = json.loads(err)
        assert err_data.get("summary").get("status") == "failed"
        assert err_data.get("summary").get("totalCount") == 0
        assert err_data.get("summary").get("failedCount") == 0
        assert err_data.get("details")[0].get("message").startswith("File failed to load because specified format")

    def test_cmd_import_failure_when_csv_empty(
        self, capfd, init_db_instance, mocker, get_tmp_import_empty_csv_file
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        args = [
            "import",
            "--format",
            "csv",
            "--input",
            get_tmp_import_empty_csv_file,
        ]
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()

        out, err = capfd.readouterr()
        assert out == ""
        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        err_data = json.loads(err)
        assert err_data.get("summary").get("status") == "failed"
        assert err_data.get("summary").get("totalCount") == 0
        assert err_data.get("summary").get("failedCount") == 0
        assert err_data.get("details")[0].get("message").startswith("File failed to load because specified format")

    def test_cmd_import_failure_when_csv_only_comments(
        self, capfd, init_db_instance, mocker, get_tmp_import_csv_file_only_comment
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        args = [
            "import",
            "--format",
            "csv",
            "--input",
            get_tmp_import_csv_file_only_comment,
        ]
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()

        out, err = capfd.readouterr()
        assert out == ""
        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        err_data = json.loads(err)
        assert err_data.get("summary").get("status") == "failed"
        assert err_data.get("summary").get("totalCount") == 0
        assert err_data.get("summary").get("failedCount") == 0
        assert err_data.get("details")[0].get("message").startswith("File failed to load because specified format")

    def test_cmd_import_failure_when_csv_no_comments(
        self, capfd, init_db_instance, mocker, get_tmp_import_csv_file_no_comment
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        args = [
            "import",
            "--format",
            "csv",
            "--input",
            get_tmp_import_csv_file_no_comment,
        ]
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()

        out, err = capfd.readouterr()
        assert out == ""
        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        err_data = json.loads(err)
        assert err_data.get("summary").get("status") == "failed"
        assert err_data.get("summary").get("totalCount") == 0
        assert err_data.get("summary").get("failedCount") == 0
        assert err_data.get("details")[0].get("message").startswith("File failed to load because specified format")

    def test_cmd_import_failure_when_category_policy_conflict(self, init_db_instance, mocker, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()
        # Node Configuration Schema: Hardware Connection Limit
        json_data = {
            "exportedCount": 1,
            "policies": [
                {
                    "policyID": "ffeceb14da",
                    "category": "systemOperationPolicy",
                    "title": "NodeConfigurationPolicy",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                    "enabled": True,
                    "createdAt": "2023-05-10T00:00:00Z",
                    "updatedAt": "2023-05-10T00:00:00Z",
                }
            ],
        }

        with tempfile.TemporaryDirectory() as dir_path:
            json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
            with open(json_file, mode="w", encoding="utf-8") as fh:
                json.dump(json_data, fh, indent=4)
            args = ["import", "--format", "json", "--input", json_file]
            sys.argv = ["cli.py", *args]
            with pytest.raises(SystemExit) as excinfo:
                main()
            assert excinfo.value.code == 1
            out, err = capfd.readouterr()
            assert json.loads(err) == {
                "summary": {"status": "failed", "totalCount": 1, "failedCount": 1},
                "details": [
                    {
                        "policyID": "ffeceb14da",
                        "message": "There is a contradiction in values set for category and policy.If register, please confirm category and policy you have set.If update, please confirm that category and policy you have set do not contradict those that are already registered",
                    },
                ],
            }
            cursor.execute(query="SELECT * from policies where policyID in ('ffeceb14da');")
            assert cursor.rowcount == 0

    def test_cmd_import_failure_when_import_conflict_update_node_constraint(
        self, mocker, capfd, get_tmp_import_json_file
    ):
        mock_cursor = mocker.MagicMock()
        mock_cursor.rowcount = 0
        mock_cursor.fetchone.side_effect = [
            {
                "policyID": "a21bc21587",
                "category": "nodeConfigurationPolicy",
                "title": "testTitle",
                "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": False,
            }
        ]
        mocker.patch.object(
            DbAccess,
            "check_for_duplication_policy",
            side_effect=[None, DuplicatePolicyException("dubplicated")],
        )

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

        args = ["import", "--format", "json", "--input", get_tmp_import_json_file]

        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 8
        out, err = capfd.readouterr()
        err = json.loads(err)
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert err.get("summary") == {
            "status": "failed",
            "totalCount": 5,
            "failedCount": 1,
        }
        assert err.get("details") == [{"policyID": "-", "message": "dubplicated"}]

    def test_cmd_import_failure_when_import_conflict_update_system_constraint(
        self, mocker, capfd, get_tmp_import_system_json_file
    ):
        mock_cursor = mocker.MagicMock()
        mock_cursor.rowcount = 0
        mock_cursor.fetchone.side_effect = [
            {
                "policyID": "a312bc21583",
                "category": "systemOperationPolicy",
                "title": "testTitle",
                "policy": {"useThreshold": {"cpu": {"value": 90, "unit": "percent", "comparison": "lt"}}},
                "enabled": True,
            }
        ]
        mocker.patch.object(
            DbAccess,
            "check_for_duplication_policy",
            side_effect=[None, DuplicatePolicyException("dubplicated")],
        )

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

        args = [
            "import",
            "--format",
            "json",
            "--input",
            get_tmp_import_system_json_file,
        ]

        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 8
        out, err = capfd.readouterr()
        err = json.loads(err)
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert err.get("summary") == {
            "status": "failed",
            "totalCount": 4,
            "failedCount": 1,
        }
        assert err.get("details") == [{"policyID": "-", "message": "dubplicated"}]

    def test_cmd_import_failure_when_json_read_permission_denied(self, mocker, capfd, get_tmp_import_json_file):
        mocker.patch("json.load", side_effect=[Exception("File has no permission")])

        args = ["import", "--format", "json", "--input", get_tmp_import_json_file]

        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        out, err = capfd.readouterr()
        err = json.loads(err)
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert err.get("summary") == {
            "status": "failed",
            "totalCount": 0,
            "failedCount": 0,
        }
        assert err.get("details") == [
            {
                "message": f"Specified file can not open: {get_tmp_import_json_file}",
            }
        ]

    def test_cmd_import_failure_when_yaml_read_permission_denied(self, mocker, capfd, get_tmp_import_yaml_file):
        settings_side_effect = {
            "version": 1,
            "formatters": {
                "standard": {
                    "format": "%(asctime)s %(levelname)s %(message)s",
                    "datefmt": "%Y/%m/%d %H:%M:%S.%f",
                },
            },
            "handlers": {
                "file": {
                    "class": "logging.handlers.RotatingFileHandler",
                    "level": "INFO",
                    "formatter": "standard",
                    "filename": "/var/log/cdim/app_policy.log",
                    "maxBytes": 100000000,
                    "backupCount": 72,
                    "encoding": "utf-8",
                },
                "console": {
                    "class": "logging.StreamHandler",
                    "level": "INFO",
                    "formatter": "standard",
                    "stream": "ext://sys.stdout",
                },
            },
            "root": {
                "level": "INFO",
                "handlers": ["file", "console"],
            },
        }
        mocker.patch(
            "yaml.safe_load",
            side_effect=[
                settings_side_effect,
                Exception("File has no permission"),
            ],
        )

        args = ["import", "--format", "yaml", "--input", get_tmp_import_yaml_file]

        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        out, err = capfd.readouterr()
        err = json.loads(err)
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert err.get("summary") == {
            "status": "failed",
            "totalCount": 0,
            "failedCount": 0,
        }
        assert err.get("details") == [
            {
                "message": f"Specified file can not open: {get_tmp_import_yaml_file}",
            }
        ]

    def test_cmd_import_failure_when_csv_read_permission_denied(self, mocker, capfd, get_tmp_import_csv_file):
        mocker.patch("csv.DictReader", side_effect=[Exception("File has no permission")])

        args = ["import", "--format", "csv", "--input", get_tmp_import_csv_file]

        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        out, err = capfd.readouterr()
        err = json.loads(err)
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert err.get("summary") == {
            "status": "failed",
            "totalCount": 0,
            "failedCount": 0,
        }
        assert err.get("details") == [
            {
                "message": f"Specified file can not open: {get_tmp_import_csv_file}",
            }
        ]

    def test_cmd_import_failure_when_init_log(
        self,
        mocker,
        get_tmp_import_json_file,
        capfd,
    ):
        mocker.patch.object(
            Logger, "__init__", side_effect=Exception("Internal server error. Failed in log initialization")
        )
        sys.argv = ["cli.py", "import", "--format", "json", "--input", get_tmp_import_json_file]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.LOG_INITIALIZATION_FAILED_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert err == "[E10012]Internal server error. Failed in log initialization\n"


class TestRegister:

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "insert",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_register_success_with_fakedb(
        self,
        mock_db_connection,
        args,
        get_tmp_nodepolicyjson_file,
        capfd,
        init_db_instance,
        mocker,
    ):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        sys.argv = ["cli.py", *args, get_tmp_nodepolicyjson_file]
        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == 0
        out, err = capfd.readouterr()
        # policyID in stdout
        assert json.loads(out.split("\n")[0]) == {"policyID": "a21bc21587"}
        # no error in std
        assert err == ""

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "insert",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                    "-i",
                ]
            ),
            (
                [
                    "insert",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                    "--enabled",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_register_success(
        self, init_db_instance, mocker, args, get_tmp_nodepolicyjson_file, capfd, docker_services
    ):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        sys.argv = ["cli.py", *args, get_tmp_nodepolicyjson_file]
        config = BASE_LOGGING_CONFIG.copy()
        config["root"]["handlers"] = ["file"]
        cli = PolicyManagerCLI("tesst1", Logger(config))
        cli.run()

        out, err = capfd.readouterr()
        inserted_id = json.loads(out).get("policyID")

        cursor.execute(
            query=f"SELECT policyID, category, title, policy, enabled, createdAt, updatedAt from policies WHERE policyID = '{inserted_id}'"
        )
        inserted_policy = cursor.fetchone()

        # Verify that both enabled and disabled states of the newly added constraints are include
        if "--enabled" in sys.argv:
            assert inserted_policy[4] == True
        else:
            assert inserted_policy[4] == False

        assert err == ""

        cursor.execute(query=f"Delete from policies where policyID= '{inserted_id}'")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "insert",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                    "-i",
                ]
            ),
            (
                [
                    "insert",
                    "-c",
                    "systemOperationPolicy",
                    "-t",
                    "Test2",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_register_success_when_device_uppercase(
        self,
        init_db_instance,
        mocker,
        args,
        get_tmp_nodepolicy_device_uppercase_json_file,
        get_tmp_systempolicy_device_uppercase_json_file,
        capfd,
    ):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        if args[2] == "nodeConfigurationPolicy":
            sys.argv = ["cli.py", *args, get_tmp_nodepolicy_device_uppercase_json_file]
        else:
            sys.argv = [
                "cli.py",
                *args,
                get_tmp_systempolicy_device_uppercase_json_file,
            ]
        config = BASE_LOGGING_CONFIG.copy()
        config["root"]["handlers"] = ["file"]
        cli = PolicyManagerCLI("tesst1", Logger(config))
        cli.run()

        out, err = capfd.readouterr()

        inserted_id = json.loads(out).get("policyID")

        cursor.execute(
            query=f"SELECT policyID, category, title, policy, enabled, createdAt, updatedAt from policies WHERE policyID = '{inserted_id}'"
        )
        inserted_policy = cursor.fetchone()

        assert err == ""
        assert inserted_id == inserted_policy[0]
        cursor.execute(query=f"Delete from policies where policyID= '{inserted_id}'")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "insert",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                    "-i",
                ]
            ),
            (
                [
                    "insert",
                    "-c",
                    "systemOperationPolicy",
                    "-t",
                    "Test2",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_register_success_when_multiple_devices_uppercase(
        self,
        init_db_instance,
        mocker,
        args,
        get_tmp_nodepolicy_multydevice_uppercase_json_file,
        get_tmp_systempolicy_multydevice_uppercase_json_file,
        capfd,
    ):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query="Delete from policies")
        init_db_instance.commit()
        if args[2] == "nodeConfigurationPolicy":
            sys.argv = [
                "cli.py",
                *args,
                get_tmp_nodepolicy_multydevice_uppercase_json_file,
            ]
        else:
            sys.argv = [
                "cli.py",
                *args,
                get_tmp_systempolicy_multydevice_uppercase_json_file,
            ]
        config = BASE_LOGGING_CONFIG.copy()
        config["root"]["handlers"] = ["file"]
        cli = PolicyManagerCLI("tesst1", Logger(config))
        cli.run()

        out, err = capfd.readouterr()
        inserted_id = json.loads(out).get("policyID")

        cursor.execute(
            query=f"SELECT policyID, category, title, policy, enabled, createdAt, updatedAt from policies WHERE policyID = '{inserted_id}'"
        )
        inserted_policy = cursor.fetchone()

        assert err == ""
        assert inserted_id == inserted_policy[0]
        cursor.execute(query=f"Delete from policies where policyID= '{inserted_id}'")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "insert",
                    "-c",
                    "systemOperationPolicy",
                    "-t",
                    "Test1",
                    "-i",
                ]
            ),
            (
                [
                    "insert",
                    "-c",
                    "systemOperationPolicy",
                    "-t",
                    "Test2",
                    "--enabled",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_register_success_when_category_system_constraint(
        self, init_db_instance, mocker, args, get_tmp_systempolicyjson_file, capfd
    ):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute("Delete FROM policies")
        init_db_instance.commit()
        sys.argv = ["cli.py", *args, get_tmp_systempolicyjson_file]
        config = BASE_LOGGING_CONFIG.copy()
        config["root"]["handlers"] = ["file"]
        cli = PolicyManagerCLI("tesst1", Logger(config))
        cli.run()

        out, err = capfd.readouterr()
        inserted_id = json.loads(out).get("policyID")

        cursor.execute(
            query=f"SELECT policyID, category, title, policy, enabled, createdAt, updatedAt from policies WHERE policyID = '{inserted_id}'"
        )
        inserted_policy = cursor.fetchone()

        # Verify that both enabled and disabled states of the newly added constraints are include
        if "--enabled" in sys.argv:
            assert inserted_policy[4] == True
        else:
            assert inserted_policy[4] == False

        assert err == ""

        cursor.execute(query=f"Delete from policies where policyID= '{inserted_id}'")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [
            (["insert", "-c", "-t", "hardwareConnectionsLimit", "-i"]),  # no category case
            (["insert", "-c", "nodeConfigurationPolicy", "-t", "-i"]),  # no title case
            (["insert", "-c", "-t", "-i"]),  # no category and title case
            (
                [
                    "insert",
                    "nodeConfigurationPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                    "-i",
                ]
            ),  # no specified category case
            (
                [
                    "insert",
                    "-c" "nodeConfigurationPolicy",
                    "hardwareConnectionsLimit",
                    "-i",
                ]
            ),  # no specified title case
            (
                [
                    "insert",
                    "-c" "nodeConfigurationPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                ]
            ),  # no specified output case
            (
                [
                    "insert",
                    "nodeConfigurationPolicy",
                    "hardwareConnectionsLimit",
                ]
            ),  # no specified category, title and output case
            (
                [
                    "insert",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                    "-enabled",
                    "true",
                    "-i",
                ]
            ),  # enabled is in downcase
        ],
    )
    def test_cmd_register_failure_when_invalid_input_data(self, mock_db_connection, args, get_tmp_nodepolicyjson_file):
        sys.argv = ["cli.py", *args, get_tmp_nodepolicyjson_file]
        with pytest.raises(SystemExit) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    def test_cmd_register_failure_when_invalid_policy_data(self, mock_db_connection, get_tmp_nodepolicyjson_err_file):
        args = [
            "insert",
            "-c",
            "nodeConfigurationPolicy",
            "-t",
            "hardwareConnectionsLimit",
            "-enabled",
            "true",
            "-i",
        ]
        sys.argv = ["cli.py", *args, get_tmp_nodepolicyjson_err_file]
        with pytest.raises(SystemExit) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (["insert", "-c", "systemOperationPolicy", "-t", "testTitle", "-i"]),
        ],
    )
    def test_cmd_register_failure_when_system_constraint_with_node_policy(
        self, mock_db_connection, args, get_tmp_nodepolicyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_nodepolicyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (["insert", "-c", "nodeConfigurationPolicy", "-t", "testTitle", "-i"]),
        ],
    )
    def test_cmd_register_failure_when_missing_subcategory_node_constraint(
        self, mock_db_connection, args, get_tmp_notExitPolicyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_notExitPolicyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "insert",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "testTitle",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_register_failure_when_node_constraint_with_system_policy(
        self, mock_db_connection, args, get_tmp_systempolicyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_systempolicyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (["insert", "-c", "systemOperationPolicy", "-t", "testTitle", "-i"]),
        ],
    )
    def test_cmd_register_failure_when_value_above_maximum(
        self, mock_db_connection, args, get_tmp_system_maxerror_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_maxerror_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (["insert", "-c", "systemOperationPolicy", "-t", "testTitle", "-i"]),
        ],
    )
    def test_cmd_register_failure_when_value_below_minimum(
        self, mock_db_connection, args, get_tmp_system_minerror_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_minerror_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (["insert", "-c", "systemOperationPolicy", "-t", "testTitle", "-i"]),
        ],
    )
    def test_cmd_register_failure_when_comparison_above_maximum(
        self, mock_db_connection, args, get_tmp_system_comminerror_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_comminerror_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (["insert", "-c", "systemOperationPolicy", "-t", "testTitle", "-i"]),
        ],
    )
    def test_cmd_register_failure_when_comparison_below_minimum(
        self, mock_db_connection, args, get_tmp_system_commaxerror_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_commaxerror_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            [
                "insert",
                "-c",
                "systemOperationPolicy",
                "-t",
                "testTitle",
                "-i",
            ]
        ],
    )
    def test_cmd_register_failure_when_comparison_invalid(
        self, mock_db_connection, args, get_tmp_system_comerror_patern1_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_comerror_patern1_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            [
                "insert",
                "-c",
                "systemOperationPolicy",
                "-t",
                "testTitle",
                "-i",
            ]
        ],
    )
    def test_cmd_register_failure_when_comparison_empty(
        self, mock_db_connection, args, get_tmp_system_comerror_patern2_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_comerror_patern2_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            [
                "insert",
                "-c",
                "systemOperationPolicy",
                "-t",
                "testTitle",
                "-i",
            ]
        ],
    )
    def test_cmd_register_failure_when_comparison_unexpected_value(
        self, mock_db_connection, args, get_tmp_system_comerror_patern3_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_comerror_patern3_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            [
                "insert",
                "-c",
                "systemOperationPolicy",
                "-t",
                "testTitle",
                "-i",
            ]
        ],
    )
    def test_cmd_register_failure_when_comparison_disallowed_value_specified(
        self, mock_db_connection, args, get_tmp_system_comerror_patern4_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_comerror_patern4_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            [
                "insert",
                "-c",
                "systemOperationPolicy",
                "-t",
                "testTitle",
                "-i",
            ]
        ],
    )
    def test_cmd_register_failure_when_comparison_unexpected_case_with_operator(
        self, mock_db_connection, args, get_tmp_system_comerror_patern5_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_comerror_patern5_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            [
                "insert",
                "-c",
                "systemOperationPolicy",
                "-t",
                "testTitle",
                "-i",
            ]
        ],
    )
    def test_cmd_register_failure_when_nonexistent_file(self, args):
        sys.argv = ["cli.py", *args, "not_exsist file.json"]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            [
                "insert",
                "-c",
                "systemOperationPolicy",
                "-t",
                "testTitle",
                "-i",
            ]
        ],
    )
    def test_cmd_register_failure_when_invalid_file_format(self, args, incorrect_file_format):
        sys.argv = ["cli.py", *args, incorrect_file_format]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "insert",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "testTitle",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_register_failure_when_invalid_parameters(
        self, mock_db_connection, args, get_tmp_node_error_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_node_error_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            [
                "insert",
                "-c",
                "systemOperationPolicy",
                "-t",
                "testTitle",
                "-i",
            ]
        ],
    )
    def test_cmd_register_failure_when_file_permission_denied(self, args, get_tmp_nodepolicyjson_file, mocker):
        sys.argv = ["cli.py", *args, get_tmp_nodepolicyjson_file]
        mocker.patch("json.load", side_effect=[Exception("File has no permission")])
        # mocker.patch.object(PolicyManagerCLI,"_file_validation", return_value=PermissionError())
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    def test_cmd_register_failure_when_init_log(
        self,
        mocker,
        get_tmp_systempolicyjson_file,
        capfd,
    ):
        mocker.patch.object(Logger, "__init__", side_effect=Exception("Failed in log initialization"))

        sys.argv = [
            "cli.py",
            "insert",
            "-c",
            "systemOperationPolicy",
            "-t",
            "Test2",
            "--enabled",
            "-i",
            get_tmp_systempolicyjson_file,
        ]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.LOG_INITIALIZATION_FAILED_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert err == "[E10012]Internal server error. Failed in log initialization\n"


class TestChangeEnabled:
    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc21587",
                    "--disable-id-list",
                    "321da215ef",
                ]
            ),
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc21587,c11bc215ff",
                    "--disable-id-list",
                    "321da215ef",
                ]
            ),
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc21587",
                    "--disable-id-list",
                    "321da215ef,521da215ee",
                ]
            ),
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc21587,c11bc215ff",
                    "--disable-id-list",
                    "321da215ef,521da215ee",
                ]
            ),
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc21587,c11bc215ff",
                ]
            ),
            (
                [
                    "change-enabled",
                    "--disable-id-list",
                    "321da215ef,521da215ee",
                ]
            ),
        ],
    )
    def test_cmd_change_enabled_success(self, init_db_instance, args: list, mocker):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        cursor.execute(query="Delete from policies")
        init_db_instance.commit()
        device = random.choice(["cpu", "gpu", "fpga", "dsp", "memory", "storage"])

        policies = [
            {
                "hardwareConnectionsLimit": {
                    device: {
                        "maxNum": 5,
                        "minNum": 1,
                    }
                }
            },
            {
                "hardwareConnectionsLimit": {
                    device: {
                        "maxNum": 52,
                        "minNum": 1,
                    }
                }
            },
            {
                "hardwareConnectionsLimit": {
                    device: {
                        "maxNum": 31,
                        "minNum": 1,
                    }
                }
            },
            {
                "hardwareConnectionsLimit": {
                    device: {
                        "maxNum": 3,
                        "minNum": 1,
                    }
                }
            },
        ]

        query = """INSERT into policies (policyID, category,title, policy,enabled,createdAt,updatedAt) VALUES
                    ('a21bc21587', 'nodeConfigurationPolicy','test',%s,False,'2023/09/21' ,'2023/09/21'),
                    ('c11bc215ff', 'nodeConfigurationPolicy','test2',%s,False,'2023/09/21' ,'2023/09/21'),
                    ('321da215ef', 'nodeConfigurationPolicy','test3',%s,True,'2023/09/21' ,'2023/09/21'),
                    ('521da215ee', 'nodeConfigurationPolicy','test4',%s,True,'2023/09/21' ,'2023/09/21')
                """
        cursor.execute(query, vars=[json.dumps(p) for p in policies])
        init_db_instance.commit()
        enabled_ids, disabled_ids = None, None
        if "--enable-id-list" in args:
            enabled_ids = args[args.index("--enable-id-list") + 1].split(",")
        if "--disable-id-list" in args:
            disabled_ids = args[args.index("--disable-id-list") + 1].split(",")

        sys.argv = ["cli.py", *args]
        PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

        after_disabled_policies, after_enabled_policies = [], []
        if enabled_ids:
            cursor.execute("Select * from policies where policyid in %s", vars=[tuple(enabled_ids)])
            after_enabled_policies = cursor.fetchall()
        if disabled_ids:
            cursor.execute(
                "Select * from policies where policyid in %s",
                vars=[tuple(disabled_ids)],
            )
            after_disabled_policies = cursor.fetchall()

        for policy in after_enabled_policies:
            assert policy[4] == True
        for policy in after_disabled_policies:
            assert policy[4] == False

        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [
            (
                ["change-enabled", "-ell", "a21bc21587", "-dl", "ca2b1215ef"]
            ),  # case where an invalid option is entered in the enabled list
            (
                ["change-enabled", "a21bc21587", "-dl", "ca2b1215ef"]
            ),  # case where options for the enabled ID list are not specified
            (["--enable-id-list", "a21bc21587", "--disable-id-list", "ca2b1215ef"]),
            # case where no subcommand is specified
            (["change-enabled", "a21bc21587", "ca2b1215ef"]),
            # case where no options are specified
            (
                [
                    "enaabled",
                    "--enable-id-list",
                    "a21bc21587",
                    "--disable-id-list",
                    "ca2b1215ef",
                ]
            ),  # case where a non-existent subcommand is specified
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc21587",
                    "-dll",
                    "ca2b1215ef",
                ]
            ),  # case where an invalid option is entered in the disabled list
            (
                ["change-enabled", "--enable-id-list", "--disable-id-list"]
            ),  # case where both the enabled and disabled ID lists are empty
            (
                [
                    "changeenabled",
                    "--enable-id-list",
                    "a21bc21587",
                    "--disable-id-list",
                    "321da215ef1",
                ]
            ),  # case where a non-existent subcommand is specified
            (
                [
                    "changeenabled",
                    "--enableIDList",
                    "a21bc21587",
                    "-disableIDList",
                    "321da215ef1",
                ]
            ),  # case where a non-existent subcommand is specified
            (
                [
                    "change-enabled",
                    "-el",
                    "a21bc21587",
                    "-dl",
                    "321da215ef1",
                ]
            ),  # case where the abbreviated form of enabled or disabled commands is specified
        ],
    )
    def test_cmd_change_enabled_failure_when_invalid_command_content(self, mock_db_connection, args):
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc21587a",
                    "--disable-id-list",
                    "ca2b1215ef",
                ]
            ),  # case where the ID in the enable list exceeds the specified character length
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc2158",
                    "--disable-id-list",
                    "ca2b1215ef",
                ]
            ),  # case where the ID in the enabled list is shorter than the specified character count
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "qa21bc21587",
                    "--disable-id-list",
                    "ca2b1215ef",
                ]
            ),  # case where the ID in the enabled list contains characters other than hexadecimal
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc21587,b51b1215cea",
                    "--disable-id-list",
                    "321da215ef1",
                ]
            ),  # case where an invalid ID is included among multiple IDs entered in the enabled list
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc21587",
                    "--disable-id-list",
                    "321da215ef1",
                ]
            ),  # case where the ID in the disabled list exceeds the specified character count
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc21587",
                    "--disable-id-list",
                    "321da5f",
                ]
            ),  # case where the ID in the disabled list is shorter than the specified character count
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc21587",
                    "--disable-id-list",
                    "321da215fz",
                ]
            ),  # case where the ID in the disabled list contains characters other than hexadecimal
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc21587",
                    "--disable-id-list",
                    "321da215ef1,b51b1215cea",
                ]
            ),  # case where an invalid ID is included among multiple IDs entered in the disabled list
            (["change-enabled"]),
            # case where neither options nor IDs are specified
        ],
    )
    def test_cmd_change_enabled_failure_when_invalid_input_data(self, mock_db_connection, args):
        sys.argv = ["cli.py", *args]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    def test_cmd_change_enabled_failure_when_init_log(
        self,
        mocker,
        capfd,
    ):
        mocker.patch.object(
            Logger, "__init__", side_effect=Exception("Internal server error. Failed in log initialization")
        )

        sys.argv = [
            "cli.py",
            "change-enabled",
            "--enable-id-list",
            "a21bc21587,c11bc215ff",
            "--disable-id-list",
            "321da215ef",
        ]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.LOG_INITIALIZATION_FAILED_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert err == "[E10012]Internal server error. Failed in log initialization\n"

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc21587",
                    "--disable-id-list",
                    "321da215ef",
                ]
            ),
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc21587,c11bc215ff",
                    "--disable-id-list",
                    "321da215ef",
                ]
            ),
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc21587",
                    "--disable-id-list",
                    "321da215ef,521da215ee",
                ]
            ),
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "a21bc21587,c11bc215ff",
                    "--disable-id-list",
                    "321da215ef,521da215ee",
                ]
            ),
        ],
    )
    def test_cmd_change_enabled_success_for_main(self, init_db_instance, mocker, args, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        cursor.execute(query="Delete from policies")
        init_db_instance.commit()
        device = random.choice(["cpu", "gpu", "fpga", "dsp", "memory", "storage"])

        policies = [
            {
                "hardwareConnectionsLimit": {
                    device: {
                        "maxNum": 5,
                        "minNum": 1,
                    }
                }
            },
            {
                "hardwareConnectionsLimit": {
                    device: {
                        "maxNum": 52,
                        "minNum": 1,
                    }
                }
            },
            {
                "hardwareConnectionsLimit": {
                    device: {
                        "maxNum": 31,
                        "minNum": 1,
                    }
                }
            },
            {
                "hardwareConnectionsLimit": {
                    device: {
                        "maxNum": 3,
                        "minNum": 1,
                    }
                }
            },
        ]

        query = """INSERT into policies (policyID, category,title, policy,enabled,createdAt,updatedAt) VALUES
                    ('a21bc21587', 'nodeConfigurationPolicy','test',%s,False,'2023/09/21' ,'2023/09/21'),
                    ('c11bc215ff', 'nodeConfigurationPolicy','test2',%s,False,'2023/09/21' ,'2023/09/21'),
                    ('321da215ef', 'nodeConfigurationPolicy','test3',%s,True,'2023/09/21' ,'2023/09/21'),
                    ('521da215ee', 'nodeConfigurationPolicy','test4',%s,True,'2023/09/21' ,'2023/09/21')
                """
        cursor.execute(query, vars=[json.dumps(p) for p in policies])
        init_db_instance.commit()
        enabled_ids, disabled_ids = None, None
        if "--enable-id-list" in args:
            enabled_ids = args[args.index("--enable-id-list") + 1].split(",")
        if "--disable-id-list" in args:
            disabled_ids = args[args.index("--disable-id-list") + 1].split(",")

        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.NORMAL
        out, err = capfd.readouterr()
        # std ouptut is Completed successfully
        assert out == "Completed successfully\n"
        # no error in std
        assert err == ""

        after_disabled_policies, after_enabled_policies = [], []
        if enabled_ids:
            cursor.execute("Select * from policies where policyid in %s", vars=[tuple(enabled_ids)])
            after_enabled_policies = cursor.fetchall()
        if disabled_ids:
            cursor.execute(
                "Select * from policies where policyid in %s",
                vars=[tuple(disabled_ids)],
            )
            after_disabled_policies = cursor.fetchall()

        for policy in after_enabled_policies:
            assert policy[4] == True
        for policy in after_disabled_policies:
            assert policy[4] == False
        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [
            [
                "change-enabled",
                "--enable-id-list",
                "a21bc21587",
                "--disable-id-list",
                "321da215ef",
            ]
        ],
    )
    def test_cmd_change_enabled_failure_when_nonexistent_id(
        self, caplog, mock_db_connection_idnotfoundexception, args, capfd, mocker
    ):
        mocker.patch("logging.config.dictConfig")
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.UNMATCH_ID_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # no error in std
        assert err == "[E10006]IDs ['a21bc21587'] is not found\n"
        assert "[E10006]IDs ['a21bc21587'] is not found" in caplog.text

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "change-enabled",
                    "--enable-id-list",
                    "123456789a",
                    "--disable-id-list",
                    "123456789b",
                ]
            ),
        ],
    )
    def test_cmd_change_enabled_success_when_update_state_validity(
        self, mock_db_connection, args, capfd, init_db_instance, mocker
    ):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.NORMAL
        out, err = capfd.readouterr()
        # std ouptut is Completed successfully
        assert out == "Completed successfully\n"
        # no error in std
        assert err == ""


class TestGet:

    @pytest.mark.parametrize(
        "args",
        [
            (["get", "--policy-id", "a21bc21587"]),
            (["get", "-c", "all", "--enabled", "all"]),
            (["get", "-c", "nodeConfigurationPolicy", "--enabled", "all"]),
            (["get", "-c", "systemOperationPolicy", "--enabled", "all"]),
            (
                [
                    "get",
                    "-c",
                    "nodeConfigurationPolicy,systemOperationPolicy",
                    "--enabled",
                    "all",
                ]
            ),
            (["get", "--enabled", "true"]),
            (["get", "--enabled", "false"]),
            (["get", "--sub-category", "hardwareConnectionsLimit"]),
            (["get", "--sub-category", "useThreshold"]),
            (["get", "--device", "cpu"]),
            (["get", "--device", "memory"]),
            (["get", "--device", "storage"]),
            (["get", "--device", "gpu"]),
            (["get", "--device", "fpga"]),
            (["get", "--device", "accelerator"]),
            (["get", "--device", "dsp"]),
            (["get", "--device", "virtualMedia"]),
            (["get", "--device", "graphicController"]),
            (["get", "--device", "networkInterface"]),
            (["get", "--device", "CPU"]),  # case where device is in uppercase
            (["get", "--device", "Memory"]),
            (["get", "--device", "Storage"]),
            (["get", "--device", "GPU"]),
            (["get", "--device", "FPGA"]),
            (["get", "--device", "Accelerator"]),
            (["get", "--device", "DSP"]),
            (["get", "--device", "VirtualMedia"]),
            (["get", "--device", "GraphicController"]),
            (["get", "--device", "NetworkInterface"]),
            (["get", "--fields", "policyID"]),
            (["get", "--fields", "title"]),
            (["get", "--fields", "category"]),
            (["get", "--fields", "policy"]),
            (["get", "--fields", "createdAt"]),
            (["get", "--fields", "updatedAt"]),
            (["get", "--fields", "policyID,policy"]),
            (["get", "--sub-category", "hardwareConnectionsLimit", "--device", "cpu"]),
            (
                [
                    "get",
                    "--sub-category",
                    "hardwareConnectionsLimit",
                    "--device",
                    "cpu",
                    "--fields",
                    "policyID,policy",
                ]
            ),
            (["get", "--device", "cpu", "--fields", "policyID,policy"]),
            (
                [
                    "get",
                    "--sub-category",
                    "hardwareConnectionsLimit",
                    "--fields",
                    "policyID,policy",
                ]
            ),
            (
                [
                    "get",
                    "--enabled",
                    "false",
                    "--sub-category",
                    "hardwareConnectionsLimit",
                    "--device",
                    "cpu",
                    "--fields",
                    "policyID,policy",
                ]
            ),
            (
                [
                    "get",
                    "-c",
                    "systemOperationPolicy",
                    "--enabled",
                    "all",
                    "--sub-category",
                    "hardwareConnectionsLimit",
                    "--device",
                    "cpu",
                    "--fields",
                    "policyID,policy",
                ]
            ),
        ],
    )
    def test_cmd_get_success(self, init_db_instance, mocker, args, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        cursor.execute(query="Delete from policies")
        init_db_instance.commit()
        # fmt: off
        key_list = [
            "cpu",
            "memory",
            "storage",
            "gpu",
            "fpga",
            "accelerator",
            "dsp",
            "virtualMedia",
            "graphicController",
            "networkInterface",
        ]
        # fmt: on
        normalizer_device_dict = {key.upper(): key for key in key_list}

        device = "cpu"
        if "--device" in args:
            device = normalizer_device_dict[args[args.index("--device") + 1].upper()]

        policies = [
            {
                "hardwareConnectionsLimit": {
                    device: {
                        "maxNum": 5,
                        "minNum": 1,
                    }
                }
            },
            {"useThreshold": {device: {"value": 80, "unit": "percent", "comparision": "gt"}}},
        ]

        query = """INSERT into policies (policyID, category,title, policy,enabled,createdAt,updatedAt)
                    VALUES 
                    ('a21bc21587', 'nodeConfigurationPolicy','test',%s,False,'2023/09/21' ,'2023/09/21'),
                    ('a21bc21589', 'systemOperationPolicy','test2', %s,True,'2023/09/21' ,'2023/09/21')
                """
        cursor.execute(query, vars=[json.dumps(p) for p in policies])
        init_db_instance.commit()
        sys.argv = ["cli.py", *args]

        PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()
        out, err = capfd.readouterr()

        assert err == ""
        assert out
        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

    @pytest.mark.parametrize("args", [["get", "--policy-id", "a21bc21587"]])
    def test_cmd_get_success_when_id_specified(self, init_db_instance, mocker, args, capfd):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        cursor.execute(query="Delete from policies")
        query = """INSERT into policies (policyID, category,title, policy,enabled,createdAt,updatedAt)
                                VALUES ('a21bc21587', 'nodeConfigurationPolicy','test','{"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}}',False,'2023/05/10' ,'2023/05/10')
                    """
        cursor.execute(query)
        init_db_instance.commit()
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.NORMAL
        out, err = capfd.readouterr()

        assert (
            out
            == "{'policyID': 'a21bc21587', 'category': 'nodeConfigurationPolicy', 'title': 'test', 'policy': {'hardwareConnectionsLimit': {'cpu': {'maxNum': 5, 'minNum': 1}}}, 'enabled': False, 'createdAt': '2023-05-10T00:00:00Z', 'updatedAt': '2023-05-10T00:00:00Z'}\n"
        )
        # DB
        cursor.execute("select * from policies where policyid=%s", vars=["a21bc21587"])
        policy = cursor.fetchone()
        assert policy[0] == args[2]
        assert policy[1] == "nodeConfigurationPolicy"
        assert policy[2] == "test"
        assert policy[3] == {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}}

        # no error in std
        assert err == ""

        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [
            (["get", "-c", "all", "--enabled", "all"]),
            (["get", "-c", "nodeConfigurationPolicy", "--enabled", "all"]),
            (["get", "-c", "systemOperationPolicy", "--enabled", "all"]),
            (
                [
                    "get",
                    "-c",
                    "nodeConfigurationPolicy,systemOperationPolicy",
                    "--enabled",
                    "all",
                ]
            ),
        ],
    )
    def test_cmd_get_success_for_main(self, mock_db_connection, args, capfd):
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.NORMAL
        out, err = capfd.readouterr()
        # Verify that the list of constraints is output to standard output
        if args[2] == "all":
            out == " {'count': 2, 'policies': [{'policyID': 'd8eceb14da', 'category': 'nodeConfigurationPolicy', 'title': 'hardwareConnectionsLimit', 'policy': {'hardwareConnectionsLimit': {'cpu': {'maxNum': 5, 'minNum': 1}}}, 'enabled': True, 'createdAt': '2023-05-10T00:00:00Z', 'updatedAt': '2023-05-10T00:00:00Z'}, {'policyID': 'abc10dfaa9', 'category': 'systemOperationPolicy', 'title': 'useThreshold', 'policy': {'useThreshold': {'cpu': {'value': 80, 'unit': 'percent', 'comparison': 'lt'}}}, 'enabled': True, 'createdAt': '2023-05-10T00:00:00Z', 'updatedAt': '2023-05-10T00:00:00Z'}]}\n"

        elif args[2] == "nodeConfigurationPolicy":
            out == "{'count': 1, 'policies': [{'policyID': 'd8eceb14da', 'category': 'nodeConfigurationPolicy', 'title': 'hardwareConnectionsLimit', 'policy': {'hardwareConnectionsLimit': {'cpu': {'maxNum': 5, 'minNum': 1}}}, 'enabled': True, 'createdAt': '2023-05-10T00:00:00Z', 'updatedAt': '2023-05-10T00:00:00Z'}]}\n"
        elif args[2] == "systemOperationPolicy":
            out == "{'count': 1, 'policies': [{'policyID': 'abc10dfaa9', 'category': 'systemOperationPolicy', 'title': 'useThreshold', 'policy': {'useThreshold': {'cpu': {'value': 80, 'unit': 'percent', 'comparison': 'lt'}}}, 'enabled': True, 'createdAt': '2023-05-10T00:00:00Z', 'updatedAt': '2023-05-10T00:00:00Z'}]}\n"
        else:
            out == " {'count': 2, 'policies': [{'policyID': 'd8eceb14da', 'category': 'nodeConfigurationPolicy', 'title': 'hardwareConnectionsLimit', 'policy': {'hardwareConnectionsLimit': {'cpu': {'maxNum': 5, 'minNum': 1}}}, 'enabled': True, 'createdAt': '2023-05-10T00:00:00Z', 'updatedAt': '2023-05-10T00:00:00Z'}, {'policyID': 'abc10dfaa9', 'category': 'systemOperationPolicy', 'title': 'useThreshold', 'policy': {'useThreshold': {'cpu': {'value': 80, 'unit': 'percent', 'comparison': 'lt'}}}, 'enabled': True, 'createdAt': '2023-05-10T00:00:00Z', 'updatedAt': '2023-05-10T00:00:00Z'}]}\n"

        # no error in std
        assert err == ""

    @pytest.mark.parametrize(
        "args",
        [
            (["get", "--limit", "1"]),
            (["get", "--limit", "20"]),
            (["get", "--limit", "100"]),
            (["get", "--offset", "0"]),
            (["get", "--offset", "1"]),
            (["get", "--offset", "20"]),
        ],
    )
    def test_cmd_get_success_when_options_specified_offset_limit(
        self, init_db_instance, mocker, args, capfd
    ):  # pylint: disable=C2401,W0613,W0621
        """Success test"""
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)
        cursor = init_db_instance.cursor()
        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.NORMAL
        out, err = capfd.readouterr()
        out = ast.literal_eval(out)
        assert "count" in out.keys()
        assert "policies" in out.keys()
        assert "totalCount" in out.keys()

    @pytest.mark.parametrize(
        "args",
        [
            (["get", "--sort-by", "createdAt"]),  # Case where only sortBy is specified
            (["get", "--sort-by", "updatedAt"]),  # Case where only sortBy is specified
            (["get", "--sort-by", "createdAt", "--order-by", "asc"]),  # Combination of sortBy and orderBy
            (["get", "--sort-by", "createdAt", "--order-by", "desc"]),  # Combination of sortBy and orderBy
            (["get", "--sort-by", "updatedAt", "--order-by", "asc"]),  # Combination of sortBy and orderBy
            (["get", "--sort-by", "updatedAt", "--order-by", "desc"]),  # Combination of sortBy and orderBy
            (["get", "--order-by", "asc"]),  # Case where orderBy is "asc"
            (["get", "--order-by", "desc"]),  # Case where orderBy is "desc"
        ],
    )
    def test_cmd_get_success_when_options_specified_orderby_sortby(
        self, init_db_instance, mocker, args, capfd
    ):  # pylint: disable=C2401,W0613,W0621
        """Success test"""
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)
        cursor = init_db_instance.cursor()
        cursor.execute(query="Delete from policies")
        init_db_instance.commit()
        insert_query = (
            f"INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )
        params1 = [
            "123456789a",
            "nodeConfigurationPolicy",
            "insert1",
            json.dumps({"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}}),
            True,
            "2023-09-01T00:00:00Z",
            "2023-09-01T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params1)
        init_db_instance.commit()
        params2 = [
            "123456789b",
            "nodeConfigurationPolicy",
            "insert2",
            json.dumps({"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}}),
            False,
            "2023-10-01T00:00:00Z",
            "2023-10-01T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params2)
        init_db_instance.commit()

        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.NORMAL
        out, err = capfd.readouterr()
        out = ast.literal_eval(out)
        assert "count" in out.keys()
        assert "policies" in out.keys()
        assert "totalCount" in out.keys()
        assert 2 == out["totalCount"]

        if "asc" in args:
            policies = out.get("policies")[0]
            assert ("policyID", "123456789a") in policies.items()
            assert ("category", "nodeConfigurationPolicy") in policies.items()
            assert ("title", "insert1") in policies.items()
            assert 5 == policies.get("policy").get("hardwareConnectionsLimit").get("gpu").get("maxNum")
            assert 1 == policies.get("policy").get("hardwareConnectionsLimit").get("gpu").get("minNum")
            assert ("enabled", True) in policies.items()
            assert ("createdAt", "2023-09-01T00:00:00Z") in policies.items()
            assert ("updatedAt", "2023-09-01T00:00:00Z") in policies.items()
            policies = out.get("policies")[1]
            assert ("policyID", "123456789b") in policies.items()
            assert ("category", "nodeConfigurationPolicy") in policies.items()
            assert ("title", "insert2") in policies.items()
            assert 5 == policies.get("policy").get("hardwareConnectionsLimit").get("cpu").get("maxNum")
            assert 1 == policies.get("policy").get("hardwareConnectionsLimit").get("cpu").get("minNum")
            assert ("enabled", False) in policies.items()
            assert ("createdAt", "2023-10-01T00:00:00Z") in policies.items()
            assert ("updatedAt", "2023-10-01T00:00:00Z") in policies.items()
        else:
            policies = out.get("policies")[0]
            assert ("policyID", "123456789b") in policies.items()
            assert ("category", "nodeConfigurationPolicy") in policies.items()
            assert ("title", "insert2") in policies.items()
            assert 5 == policies.get("policy").get("hardwareConnectionsLimit").get("cpu").get("maxNum")
            assert 1 == policies.get("policy").get("hardwareConnectionsLimit").get("cpu").get("minNum")
            assert ("enabled", False) in policies.items()
            assert ("createdAt", "2023-10-01T00:00:00Z") in policies.items()
            assert ("updatedAt", "2023-10-01T00:00:00Z") in policies.items()
            policies = out.get("policies")[1]
            assert ("policyID", "123456789a") in policies.items()
            assert ("category", "nodeConfigurationPolicy") in policies.items()
            assert ("title", "insert1") in policies.items()
            assert 5 == policies.get("policy").get("hardwareConnectionsLimit").get("gpu").get("maxNum")
            assert 1 == policies.get("policy").get("hardwareConnectionsLimit").get("gpu").get("minNum")
            assert ("enabled", True) in policies.items()
            assert ("createdAt", "2023-09-01T00:00:00Z") in policies.items()
            assert ("updatedAt", "2023-09-01T00:00:00Z") in policies.items()

        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

    @pytest.mark.parametrize("args", [["get", "--policy-id", "123456789a"]])
    def test_cmd_get_success_when_id_specified(self, mock_db_connection, args, capfd, init_db_instance, mocker):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.NORMAL
        out, err = capfd.readouterr()

        assert (
            out
            == "{'policyID': '123456789a', 'category': 'nodeConfigurationPolicy', 'title': 'hardwareConnectionsLimit', 'policy': {'hardwareConnectionsLimit': {'cpu': {'maxNum': 5, 'minNum': 1}}}, 'enabled': True, 'createdAt': '2023-05-10T00:00:00Z', 'updatedAt': '2023-05-10T00:00:00Z'}\n"
        )

        # no error in std
        assert err == ""

    @pytest.mark.parametrize(
        "args",
        [
            (["get", "-c", "all", "--enabled", "false"]),
            (["get", "-c", "nodeConfigurationPolicy", "--enabled", "false"]),
            (["get", "-c", "systemOperationPolicy", "--enabled", "false"]),
            (
                [
                    "get",
                    "-c",
                    "nodeConfigurationPolicy,systemOperationPolicy",
                    "--enabled",
                    "false",
                ]
            ),
        ],
    )
    def test_cmd_get_success(self, mock_db_connection, args, capfd, init_db_instance, mocker):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.NORMAL
        out, err = capfd.readouterr()
        # no error in std
        assert err == ""

    @pytest.mark.parametrize(
        "category",
        [
            ([]),
            (["--category", "all"]),
            (["-c", "all"]),
        ],
    )
    @pytest.mark.parametrize(
        "enabled",
        [
            ([]),
            (["--enabled", "all"]),
        ],
    )
    @pytest.mark.parametrize(
        "subcategory",
        [
            ([]),
            (["--sub-category", "hardwareConnectionsLimit"]),
        ],
    )
    @pytest.mark.parametrize(
        "device",
        [
            ([]),
            (["--device", "cpu"]),
        ],
    )
    @pytest.mark.parametrize(
        "sortby",
        [
            ([]),
            (["--sort-by", "createdAt"]),
        ],
    )
    @pytest.mark.parametrize("orderby", [([]), (["--order-by", "asc"])])
    def test_cmd_get_failure_when_id_and_options_specified(
        self,
        capfd,
        mocker,
        orderby,
        sortby,
        device,
        subcategory,
        enabled,
        category,
        init_db_instance,
    ):
        args = [
            "get",
            "--policy-id",
            "123456789a",
        ]
        args.extend(list(orderby))
        args.extend(list(sortby))
        args.extend(list(device))
        args.extend(list(subcategory))
        args.extend(list(enabled))
        args.extend(list(category))
        sys.argv = ["cli.py", *args]
        if (
            not list(orderby)
            and not list(sortby)
            and not list(device)
            and not list(subcategory)
            and not list(enabled)
            and not list(category)
        ):
            mocker.patch("psycopg2.connect", return_value=init_db_instance)
            mocker.patch.object(DbAccess, "close", return_value=None)
            cursor = init_db_instance.cursor()
            cursor.execute(query="Delete from policies")
            init_db_instance.commit()
            insert_query = (
                f"INSERT INTO policies "
                "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s)"
            )
            params1 = [
                "123456789a",
                "nodeConfigurationPolicy",
                "insert1",
                json.dumps({"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}}),
                True,
                "2023-09-01T00:00:00Z",
                "2023-09-01T00:00:00Z",
            ]
            cursor.execute(query=insert_query, vars=params1)
            init_db_instance.commit()
            with pytest.raises(SystemExit) as excinfo:
                main()
            assert excinfo.value.code == ExitCode.NORMAL
            out, err = capfd.readouterr()

            assert (
                out
                == "{'policyID': '123456789a', 'category': 'nodeConfigurationPolicy', 'title': 'insert1', 'policy': {'hardwareConnectionsLimit': {'gpu': {'maxNum': 5, 'minNum': 1}}}, 'enabled': True, 'createdAt': '2023-09-01T00:00:00Z', 'updatedAt': '2023-09-01T00:00:00Z'}\n"
            )
            cursor.execute(query="Delete from policies")
            init_db_instance.commit()
        else:
            with pytest.raises(SystemExit) as excinfo:
                main()

            assert excinfo.value.code == ExitCode.VALIDATION_ERROR
            out, err = capfd.readouterr()
            assert out == ""
            msg = "Option policy-id not allowed with argument category, enabled, sub-category, device, fields, sort-by, order-by"
            assert msg in err

    def test_cmd_get_failure_when_init_log(self, mocker, capfd, docker_services):
        mocker.patch.object(
            Logger, "__init__", side_effect=Exception("Internal server error. Failed in log initialization")
        )

        sys.argv = ["cli.py", "get", "--policy-id", "123456789a"]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.LOG_INITIALIZATION_FAILED_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert err == "[E10012]Internal server error. Failed in log initialization\n"

    @pytest.mark.parametrize(
        "args",
        [
            (["get", "--policy-id", "a21bc21587", "b51b1215ce"]),  # Case where multiple IDs are specified
            (["get", "--policy-id"]),  # Case where no IDs are specified
            (["get", "a21bc21587"]),  # Case where an ID is entered without specifying the ID option
            (["get", "--policy-ids", "a21bc21587"]),  # Case where a non-existent option is specified
            (["--policy-id", "a21bc21587"]),  # Case where no subcommand is specified
            (["select", "--policy-id", "a21bc21587"]),  # Case where a non-existent subcommand is entered
            (["selectall", "--policy-id", "a21bc21587"]),  # Case where a non-existent subcommand is entered
            (["a21bc21587"]),  # Case where neither subcommand nor ID option is specified
            (
                ["get-all", "-c", "systemOperation", "--enabled", "all"]
            ),  # Case where a non-existent subcommand is specified
            (["", "-c", "nodeConfigurationPolicy", "--enabled", "true"]),  # Case where no subcommand is specified
            (
                ["get", "nodeConfigurationPolicy", "--enabled", "true"]
            ),  # Case where the category option is not specified
            (["get", "-c", "nodeConfigurationPolicy", "true"]),  # Case where the enable option is not specified
            (["get", "nodeConfigurationPolicy", "true"]),  # Case where neither category nor enable option is specified
            (
                ["get", "-c", "systemOperation", "--enabled", "all", "-t", "process"]
            ),  # Case where a non-existent parameter is entered
            (["get", "--fields"]),
            (["get", "--device"]),
            (["get", "--sub-category"]),
            (["get", "--sort-by"]),
            (["get", "--order-by"]),
            (["get", "--subCategory", "hardwareConnectionsLimit"]),
            (["get", "--sortBy", "createdAt"]),
            (["get", "--orderBy", "desc"]),
            # Case where a non-existent abbreviation for the command is specified
            (["get", "-f"]),
            (["get", "-d"]),
            (["get", "-s"]),
            (["get", "--so"]),
            (["get", "-o"]),
            (["get", "-e"]),
            (["get", "--limit", "createdAt"]),  # Case where the value of limit is a string
            (["get", "--offset", "createdAt"]),  # Case where the value of offset is a string
        ],
    )
    def test_cmd_get_failure_when_invalid_command_content(self, mock_db_connection, args):
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (["get", "--policy-id", "a21bc21587a"]),  # Case where the ID exceeds the specified character count
            (["get", "--policy-id", "a21bc2158"]),  # Case where the ID is shorter than the specified character count
            (["get", "--policy-id", "z21bc21587"]),  # Case where the ID contains characters other than hexadecimal
            (
                ["get", "-c", "systemOperation", "--enabled", "all"]
            ),  # Case where an unexpected string is specified for the category
            (
                ["get", "-c", "nodeConfigurationPolicy", "--enabled", "error"]
            ),  # Case where an unexpected string is specified for the enabled option
            (
                ["get", "-c", "all,nodeConfigurationPolicy", "--enabled", "all"]
            ),  # Case where both "all" and other constraint types are specified for the category
            (
                [
                    "get",
                    "-c",
                    "nodeConfigurationPolicy,nodeConfigurationPolicy",
                    "--enabled",
                    "all",
                ]
            ),  # Case where the constraint type is duplicated in the category
            (
                [
                    "get",
                    "-c",
                    "all,all",
                    "--enabled",
                    "all",
                ]
            ),  # Case where "all" is duplicated in the category
            (
                [
                    "get",
                    "-c",
                    "all,nodeConfigurationPolicy,systemOperationPolicy",
                    "--enabled",
                    "all",
                ]
            ),  # Case where "all" and all constraint types are specified
            (["get", "--sub-category", "hardware"]),
            (["get", "--device", "otherProcessor"]),
            (["get", "--fields", "policyIDD"]),
            (["get", "--fields", "policyID,policyID"]),
            (["get", "--sort-by", "policy"]),  # Case where sortBy has an unexpected value
            (["get", "--sort-by", "createdAt", "--order-by", "sort"]),  # Case where orderBy has an unexpected value
            (["get", "--order-by", "sort"]),  # Case where sortBy is missing, and orderBy has an unexpected value
            (["get", "--limit", "0"]),  # Case where the limit value is 0
            (["get", "--offset", "-1"]),  # Case where the offset value is -1
        ],
    )
    def test_cmd_get_failure_when_invalid_input_data(self, mock_db_connection, args):
        sys.argv = ["cli.py", *args]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (["get", "-c", "nodeConfigurationPolicy", "--enabled", "all"]),
        ],
    )
    def test_cmd_get_all_failure_when_init_log(self, mocker, capfd, args, docker_services):
        mocker.patch.object(
            Logger, "__init__", side_effect=Exception("Internal server error. Failed in log initialization")
        )

        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.LOG_INITIALIZATION_FAILED_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert err == "[E10012]Internal server error. Failed in log initialization\n"


class TestUpdate:
    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                    "-i",
                ]
            ),
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-t",
                    "hardwareConnectionsLimit",
                    "-i",
                ]
            ),
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-i",
                ]
            ),
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                ]
            ),
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "--force",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                    "-i",
                ]
            ),
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "--force",
                    "--category",
                    "nodeConfigurationPolicy",
                    "--title",
                    "hardwareConnectionsLimit",
                    "--input",
                ]
            ),
        ],
    )
    def test_cmd_update_success(
        self,
        mocker,
        mock_db_connection,
        args,
        get_tmp_nodepolicyjson_file,
    ):
        mock_cursor = mocker.MagicMock()
        mock_cursor.rowcount = 0
        mock_cursor.fetchone = lambda: {
            "policy_id": args[2],
            "category": "nodeConfigurationPolicy",
            "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
        }

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

        if args[-1] == "-i" or args[-1] == "--input":
            sys.argv = ["cli.py", *args, get_tmp_nodepolicyjson_file]
        else:
            sys.argv = ["cli.py", *args]
        PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_success_when_device_uppercase(
        self,
        mocker,
        mock_db_connection,
        args,
        get_tmp_nodepolicy_device_uppercase_json_file,
    ):
        mock_cursor = mocker.MagicMock()
        mock_cursor.rowcount = 0
        mock_cursor.fetchone = lambda: {
            "policy_id": args[2],
            "category": "nodeConfigurationPolicy",
            "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
        }

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

        if args[-1] == "-i" or args[-1] == "--input":
            sys.argv = ["cli.py", *args, get_tmp_nodepolicy_device_uppercase_json_file]
        else:
            sys.argv = ["cli.py", *args]
        PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "systemOperationPolicy",
                    "-t",
                    "useThreshold",
                    "-i",
                ]
            ),
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-t",
                    "useThreshold",
                    "-i",
                ]
            ),
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "systemOperationPolicy",
                    "-i",
                ]
            ),
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "systemOperationPolicy",
                    "-t",
                    "useThreshold",
                ]
            ),
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "--force",
                    "-c",
                    "systemOperationPolicy",
                    "-t",
                    "useThreshold",
                    "-i",
                ]
            ),
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "--force",
                    "--category",
                    "systemOperationPolicy",
                    "--title",
                    "useThreshold",
                    "--input",
                ]
            ),
        ],
    )
    def test_cmd_update_success_when_category_system_constraint(
        self,
        mocker,
        args,
        get_tmp_systempolicyjson_file,
    ):
        class FakeDB:
            def update(policyID, category, title, policy, force):
                return 1

            def close():
                pass

            def open_db_connection():
                pass

            def check_for_duplication_policy(policy: dict, policyID: str = None, assumed_count: int = 1):
                pass

            def get_policy(policyID):
                return {
                    "policyID": "a21bc21587",
                    "category": "systemOperationPolicy",
                    "title": "testTitle",
                    "policy": {"useThreshold": {"gpu": {"value": 50, "unit": "percent", "comparison": "gt"}}},
                    "enabled": True,
                }

        mocker.patch(
            "policymanager.cli.DbAccess",
            mocker.MagicMock(return_value=FakeDB),
        )
        if args[-1] == "-i" or args[-1] == "--input":
            sys.argv = ["cli.py", *args, get_tmp_systempolicyjson_file]
        else:
            sys.argv = ["cli.py", *args]
        PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "systemPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                    "-i",
                ]
            ),  # Case where an unexpected category is entered
            (
                [
                    "update",
                    "--policy-id",
                    "z21bc21587",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "-i",
                ]
            ),  # Case where the title option is specified, but no data is entered
            (
                [
                    "update",
                    "--policy-id",
                    "z21bc21587",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                    "-fo",
                    "-i",
                ]
            ),  # Case where a non-existent abbreviation is specified
        ],
    )
    def test_cmd_update_failure_when_invalid_command_content(self, mock_db_connection, args):
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (["update", "--policy-id", "a21bc21587a"]),  # Case where the ID exceeds the specified character count
            (["update", "--policy-id", "a21bc2158"]),  # Case where the ID is shorter than the specified character count
            (["update", "--policy-id", "z21bc21587"]),  # Case where the ID contains characters other than hexadecimal
        ],
    )
    def test_cmd_update_failure_when_invalid_input_data(self, mock_db_connection, args):
        sys.argv = ["cli.py", *args]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "systemOperationPolicy",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_failure_when_system_constraint_with_node_policy(
        self, mock_db_connection, args, get_tmp_nodepolicyjson_file, mocker
    ):
        mock_cursor = mocker.MagicMock()
        mock_cursor.rowcount = 0
        mock_cursor.fetchone.side_effect = [
            {
                "policyID": "a21bc21587",
                "category": "nodeConfigurationPolicy",
                "title": "testTitle",
                "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": False,
            }
        ]

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

        sys.argv = ["cli.py", *args, get_tmp_nodepolicyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_failure_when_node_constraint_with_system_policy(
        self, mock_db_connection, args, get_tmp_systempolicyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_systempolicyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "systemOperationPolicy",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_failure_when_value_above_maximum(
        self, mock_db_connection, args, get_tmp_system_maxerror_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_maxerror_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "systemOperationPolicy",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_failure_when_value_below_minimum(
        self, mock_db_connection, args, get_tmp_system_minerror_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_minerror_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "systemOperationPolicy",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_failure_when_comparison_above_maximum(
        self, mock_db_connection, args, get_tmp_system_comminerror_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_comminerror_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "systemOperationPolicy",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_failure_when_comparison_below_minimum(
        self, mock_db_connection, args, get_tmp_system_commaxerror_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_commaxerror_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "systemOperationPolicy",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_failure_when_comparison_invalid(
        self, mock_db_connection, args, get_tmp_system_comerror_patern1_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_comerror_patern1_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "systemOperationPolicy",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_failure_when_comparison_empty(
        self, mock_db_connection, args, get_tmp_system_comerror_patern2_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_comerror_patern2_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "systemOperationPolicy",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_failure_when_comparison_unexpected_value(
        self, mock_db_connection, args, get_tmp_system_comerror_patern3_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_comerror_patern3_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "systemOperationPolicy",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_failure_when_comparison_disallowed_value_specified(
        self, mock_db_connection, args, get_tmp_system_comerror_patern4_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_comerror_patern4_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "systemOperationPolicy",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_failure_when_comparison_unexpected_case_with_operator(
        self, mock_db_connection, args, get_tmp_system_comerror_patern5_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_comerror_patern5_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "systemOperationPolicy",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_failure_when_subcategory_array_node_constraint(
        self, mock_db_connection, args, get_tmp_system_subcategory_array_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_system_subcategory_array_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_failure_when_invalid_parameters_node_constraint(
        self, mock_db_connection, args, get_tmp_node_error_policyjson_file
    ):
        sys.argv = ["cli.py", *args, get_tmp_node_error_policyjson_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "123456789a",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_success_with_fakedb(
        self,
        mock_db_connection,
        args,
        get_tmp_nodepolicyjson_file,
        capfd,
        init_db_instance,
        caplog,
        mocker,
    ):
        mocker.patch("logging.config.dictConfig")
        logger = logging.getLogger("logger.py")
        logger.handlers.clear()
        logger.addHandler(caplog.handler)
        logger.setLevel(logging.DEBUG)
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query="Delete from policies")
        init_db_instance.commit()
        insert_query = (
            f"INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )
        params1 = [
            "123456789a",
            "nodeConfigurationPolicy",
            "insert1",
            json.dumps({"hardwareConnectionsLimit": {"cpu": {"maxNum": 15, "minNum": 1}}}),
            True,
            "2023-09-01T00:00:00Z",
            "2023-09-01T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params1)
        init_db_instance.commit()

        sys.argv = ["cli.py", *args, get_tmp_nodepolicyjson_file]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.NORMAL
        out, err = capfd.readouterr()

        # std ouptut is Completed successfully
        assert out == "Completed successfully\n"
        # no error in std
        assert err == ""
        assert "Completed successfully" in caplog.text

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_success_when_category_node_constraint(
        self, mock_db_connection, mocker, args, get_tmp_nodepolicyjson_file, capfd
    ):
        mock_cursor = mocker.MagicMock()
        mock_cursor.rowcount = 0
        mock_cursor.fetchone.side_effect = [
            {
                "policyID": "a21bc21587",
                "category": "nodeConfigurationPolicy",
                "title": "testTitle",
                "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": False,
            }
        ]

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

        sys.argv = ["cli.py", *args, get_tmp_nodepolicyjson_file]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.NORMAL
        out, err = capfd.readouterr()

        # std ouptut is Completed successfully
        assert out == "Completed successfully\n"
        # no error in std
        assert err == ""

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "systemOperationPolicy",
                    "-t",
                    "systemOperationUpdate",
                    "-i",
                ]
            ),
        ],
    )
    def test_cmd_update_success_when_category_system_constraint(
        self, mock_db_connection, args, get_tmp_systempolicyjson_file, capfd
    ):
        sys.argv = ["cli.py", *args, get_tmp_systempolicyjson_file]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.NORMAL
        out, err = capfd.readouterr()

        # std ouptut is Completed successfully
        assert out == "Completed successfully\n"
        # no error in std
        assert err == ""

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--policy-id",
                    "a21bc21587",
                    "-c",
                    "nodeConfigurationPolicy",
                    "-t",
                    "hardwareConnectionsLimit",
                ]
            ),
        ],
    )
    def test_cmd_update_failure_when_state_not_invalid(self, args, mocker, get_policyID, capfd, caplog):
        mocker.patch.object(
            DbAccess,
            "_normalize_db_result",
            side_effect=[get_policyID[0], get_policyID[0]],
        )
        mocker.patch("logging.config.dictConfig")
        mock_cursor = mocker.MagicMock()
        mock_cursor.fetchone.side_effect = [get_policyID, get_policyID]
        mock_cursor.rowcount = 0

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.INVALID_OPERATION_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert err == "[E10007]Specified a21bc21587 is not in disabled state\n"
        assert "[E10007]Specified a21bc21587 is not in disabled state" in caplog.text

    def test_cmd_update_failure_when_init_log(
        self,
        mocker,
        get_tmp_systempolicyjson_file,
        capfd,
    ):
        mocker.patch.object(
            Logger, "__init__", side_effect=Exception("Internal server error. Failed in log initialization")
        )

        sys.argv = [
            "cli.py",
            "update",
            "--policy-id",
            "a21bc21587",
            "-c",
            "systemOperationPolicy",
            "-i",
            get_tmp_systempolicyjson_file,
        ]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.LOG_INITIALIZATION_FAILED_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert err == "[E10012]Internal server error. Failed in log initialization\n"


class TestDelete:
    @pytest.mark.parametrize(
        "args",
        [
            (["delete", "--policy-id", "a21bc21587"]),
            (["delete", "--policy-id", "a21bc21587", "--force"]),
        ],
    )
    def test_cmd_delete_success(self, mock_db_connection, args):
        sys.argv = ["cli.py", *args]
        PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (["delete", "--policy-id", "a21bc21587", "b51b1215ce"]),  # Case where multiple IDs are specified
            (["delete", "--policy-id"]),  # Case where no IDs are specified
            (["delete"]),  # Case where the ID option is not specified
            (["delete", "a21bc21587"]),  # Case where an ID is entered without specifying the ID option
            (["delete", "--policy-ids", "a21bc21587"]),  # Case where a non-existent option is specified
            (["--policy-id", "a21bc21587"]),  # Case where no subcommand is specified
            (["sdelete", "--policy-id", "a21bc21587"]),  # Case where a non-existent subcommand is entered
            (["a21bc21587"]),  # Case where neither the subcommand nor the ID option is specified
            (["delete", "--id", "a21bc21587"]),  # Case where `--id` is specified
            (["delete", "--policy-id", "a21bc21587", "-fo"]),  # Case where a non-existent abbreviation is specified
        ],
    )
    def test_cmd_delete_failure_when_invalid_command_content(self, mock_db_connection, args):
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (["delete", "--policy-id", "a21bc21587a"]),  # Case where the ID exceeds the specified character count
            (["delete", "--policy-id", "a21bc2158"]),  # Case where the ID is shorter than the specified character count
            (["delete", "--policy-id", "z21bc21587"]),  # Case where the ID contains characters other than hexadecimal
        ],
    )
    def test_cmd_delete_failure_when_invalid_input_data(self, mock_db_connection, args):
        sys.argv = ["cli.py", *args]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (["delete", "--policy-id", "123456789a"]),
        ],
    )
    def test_cmd_delete_success_with_fakedb(
        self,
        args,
        capfd,
        init_db_instance,
        mocker,
        mock_db_connection,
        caplog,
    ):
        mocker.patch("logging.config.dictConfig")
        logger = logging.getLogger("logger.py")
        logger.handlers.clear()
        logger.addHandler(caplog.handler)
        logger.setLevel(logging.DEBUG)

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.NORMAL
        out, err = capfd.readouterr()

        # std ouptut is Completed successfully
        assert out == "Completed successfully\n"
        # no error in std
        assert err == ""
        assert "Completed successfully" in caplog.text

    def test_cmd_delete_failure_when_init_log(self, mocker, capfd, docker_services):
        mocker.patch.object(
            Logger, "__init__", side_effect=Exception("Internal server error. Failed in log initialization")
        )

        sys.argv = ["cli.py", "delete", "--policy-id", "123456789a"]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.LOG_INITIALIZATION_FAILED_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert err == "[E10012]Internal server error. Failed in log initialization\n"


class TestExport:
    @pytest.mark.parametrize(
        "args",
        [
            (["export", "--format", "json", "--output"]),
            (["export", "--format", "json", "-o"]),
            (["export", "--format", "yaml", "-o"]),
            (["export", "--format", "csv", "-o"]),
        ],
    )
    def test_cmd_export_success_with_fakedb(
        self,
        args,
        capfd,
        init_db_instance,
        output_json_file,
        output_yaml_file,
        output_csv_file,
        caplog,
        mocker,
    ):
        mocker.patch("logging.config.dictConfig")
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        if args[2] == "json":
            sys.argv = ["cli.py", *args, output_json_file]
        elif args[2] == "yaml":
            sys.argv = ["cli.py", *args, output_yaml_file]
        elif args[2] == "csv":
            sys.argv = ["cli.py", *args, output_csv_file]

        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.NORMAL
        out, err = capfd.readouterr()

        # std ouptut is Completed successfully
        assert out == "Completed successfully\n"
        # no error in std
        assert err == ""
        assert "Completed successfully" in caplog.text

    @pytest.mark.parametrize(
        ("args", "count"),
        [
            (["export", "--format", "json", "--output"], 0),
            (["export", "--format", "json", "--output"], 1),
            (["export", "--format", "json", "--output"], 4),
            (["export", "--format", "yaml", "--output"], 0),
            (["export", "--format", "yaml", "--output"], 1),
            (["export", "--format", "yaml", "--output"], 4),
            (["export", "--format", "csv", "--output"], 0),
            (["export", "--format", "csv", "--output"], 1),
            (["export", "--format", "csv", "--output"], 4),
        ],
    )
    def test_cmd_export_success(
        self,
        mocker,
        init_db_instance,
        args,
        output_json_file,
        output_yaml_file,
        output_csv_file,
        capfd,
        get_db_policies,
        count,
    ):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)
        cursor = init_db_instance.cursor()
        cursor.execute("Delete from policies")
        init_db_instance.commit()
        policies = [
            {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
            {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
            {"useThreshold": {"gpu": {"value": 80, "unit": "percent", "comparision": "gt"}}},
            {"useThreshold": {"dsp": {"value": 80, "unit": "percent", "comparision": "lt"}}},
        ]

        query = """INSERT into policies (policyID, category,title, policy,enabled,createdAt,updatedAt)
                    VALUES 
                    ('123456789a', 'nodeConfigurationPolicy','test',%s,False,'2023/09/21' ,'2023/09/21'),
                    ('123456789c', 'nodeConfigurationPolicy','test',%s,True,'2023/09/21' ,'2023/09/21'),
                    ('123456789b', 'systemOperationPolicy','test',%s,False,'2023/09/28' ,'2023/09/28'),
                    ('123456789d', 'systemOperationPolicy','test',%s,True,'2023/09/28' ,'2023/09/28')
                """
        cursor.execute(query, vars=[json.dumps(p) for p in policies])
        init_db_instance.commit()
        match count:
            case 1:
                cursor.execute(query="Delete from policies where policyID in ('123456789b','123456789c','123456789d')")
                init_db_instance.commit()
            case 0:
                cursor.execute(query="Delete from policies")
                init_db_instance.commit()
        if args[2] == "json":
            sys.argv = ["cli.py", *args, output_json_file]
        elif args[2] == "yaml":
            sys.argv = ["cli.py", *args, output_yaml_file]
        elif args[2] == "csv":
            sys.argv = ["cli.py", *args, output_csv_file]

        config = BASE_LOGGING_CONFIG.copy()
        config["root"]["handlers"] = ["file"]
        PolicyManagerCLI("test", Logger(config)).run()

        result = None

        if args[2] == "json":
            with open(output_json_file, mode="r", encoding="utf8") as file_path:
                result = json.load(file_path)
        elif args[2] == "yaml":
            with open(output_yaml_file, mode="r", encoding="utf8") as file_path:
                result = yaml.safe_load(file_path)
        elif args[2] == "csv":
            with open(output_csv_file, mode="r", encoding="utf8") as file_path:
                ex_cnt = int(next(file_path).split(":")[-1].strip().replace("\n", ""))
                csv_reader = csv.DictReader(file_path)
                policies_data = []
                for row in csv_reader:
                    row["policy"] = ast.literal_eval(row.get("policy"))
                    row["enabled"] = row.get("enabled").lower() in ["true"]
                    policies_data.append(row)
                result = {"exportedCount": ex_cnt, "policies": policies_data}

        assert_data = [
            {
                "exportedCount": len(get_db_policies),
                "policies": get_db_policies,
            },
            {
                "exportedCount": 1,
                "policies": [get_db_policies[2]],
            },
            {
                "exportedCount": 0,
                "policies": [],
            },
        ]

        assert result in assert_data

        out, err = capfd.readouterr()
        # std ouptut is Completed successfully
        assert out == "Completed successfully\n"
        # no error in std
        assert err == ""
        cursor.execute("Delete from policies")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [
            (["export", "--format", "--output", "/export.json"]),  # Case where format is specified but has no value
            (
                ["export", "json", "--output", "/export.json"]
            ),  # Case where the format is entered without specifying the format option
            (
                ["export", "--formats", "json" "--output", "/export.json"]
            ),  # Case where a non-existent option is specified
            (["--format", "json" "--output", "/export.json"]),  # Case where no subcommand is specified
            (
                ["eexport", "--fotmat", "json", "--output", "/export.json"]
            ),  # Case where a non-existent subcommand is entered
            (["json", "--output", "/export.json"]),  # Case where neither subcommand nor ID option is specified
            (["export", "--output", "/export.json", "/export.csv"]),  # Case where multiple formats are specified
            (["export", "--output", ""]),  # Case where output is specified but the value is empty
            (["export", "--output"]),  # Case where output is specified but has no value
            (["export", "/export.json"]),  # Case where output is entered without specifying the output option
            (["export", "--outputs", "/export.json"]),  # Case where a non-existent option is specified
            (["--output", "/export.json"]),  # Case where no subcommand is specified
            (["eexport", "--output", "/export.json"]),  # Case where a non-existent subcommand is entered
            (["json"]),  # Case where neither subcommand nor ID option is specified
            (
                ["export", "-f", "json", "--output", "/export.json"]
            ),  # Case where a non-existent abbreviation is specified
        ],
    )
    def test_cmd_export_failure_when_invalid_command_content(self, mock_db_connection, args):
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as e:
            PolicyManagerCLI("test", Logger).run()

    @pytest.mark.parametrize(
        "args",
        [
            (["export", "--format", "tsv", "--output"]),  # Case where an unexpected string is specified
            (["export", "--format", "yml", "--output"]),  # Case where an unexpected string is specified
        ],
    )
    def test_cmd_export_failure_when_invalid_input_data(
        self,
        mock_db_connection,
        args,
        output_json_file,
    ):
        sys.argv = ["cli.py", *args, output_json_file]
        with pytest.raises(ValidationError) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (["export", "--format", "json", "--output"]),
            (["export", "--format", "yaml", "--output"]),
            (["export", "--format", "csv", "--output"]),
        ],
    )
    def test_cmd_export_failure_when_file_write_failed(
        self,
        mocker,
        mock_db_connection,
        args,
    ):
        if args[2] == "json":
            file_path = "/tmp/11111111/test.json"
        elif args[2] == "yaml":
            file_path = "/tmp/11111111/test.yaml"
        elif args[2] == "csv":
            file_path = "/tmp/11111111/test.csv"
        sys.argv = ["cli.py", *args, file_path]
        with pytest.raises(ExportPolicyException) as e:
            PolicyManagerCLI("test", Logger(BASE_LOGGING_CONFIG)).run()

    @pytest.mark.parametrize(
        "args",
        [
            (["export", "--format", "json", "--output"]),
            (["export", "--format", "yaml", "--output"]),
        ],
    )
    def test_cmd_export_failure_when_write_failed(self, mocker, mock_db_connection, args, capfd, caplog):
        mocker.patch("logging.config.dictConfig")
        if args[2] == "json":
            file_path = "/tmp/11111111/test.json"
        elif args[2] == "yaml":
            file_path = "/tmp/11111111/test.yaml"
        sys.argv = ["cli.py", *args, file_path]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.EXPORT_POLICY_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert "[E10009]Failed to export file" in err
        assert "[E10009]Failed to export file" in caplog.text

    def test_cmd_export_failure_when_init_log(self, mocker, capfd, docker_services):
        mocker.patch.object(
            Logger, "__init__", side_effect=Exception("Internal server error. Failed in log initialization")
        )

        sys.argv = ["cli.py", "export", "--format", "json", "--output", output_json_file]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.LOG_INITIALIZATION_FAILED_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert err == "[E10012]Internal server error. Failed in log initialization\n"


class TestCommon:
    @pytest.mark.parametrize(
        "args",
        [
            (["get", "-c", "nodeConfigurationPolicyss", "--enabled", "all"]),
        ],
    )
    def test_common_failure_when_invalid_input_value(self, args, capfd):
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        regex = re.compile(r"^\[E10001\]")
        assert regex.search(err)

    @pytest.mark.parametrize(
        "args",
        [
            (["get", "-c", "nodeConfigurationPolicy", "--enabled", "all"]),
        ],
    )
    def test_common_failure_when_config_load_failed(self, args, mocker, capfd):
        mocker.patch("logging.config.dictConfig")
        mock_logger = mocker.MagicMock()
        mocker.patch("yaml.safe_load", side_effect=[LogSettingFileValidationError("file is not exsist")])
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.CONFIG_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        regex = re.compile(r"^\[E10002\]Failed to load policymanager_log_config.yaml")
        assert regex.search(err)
        # assert "[E10002]Failed to load policymanager_log_config.yaml" in caplog.text

    @pytest.mark.parametrize(
        "error",
        [
            (psycopg2.errors.ConnectionException),
            (psycopg2.errors.SqlclientUnableToEstablishSqlconnection),
            (psycopg2.errors.ConnectionDoesNotExist),
            (psycopg2.errors.SqlserverRejectedEstablishmentOfSqlconnection),
            (psycopg2.errors.ConnectionFailure),
            (psycopg2.errors.TransactionResolutionUnknown),
            (psycopg2.errors.ProtocolViolation),
            (psycopg2.errors.InvalidSqlStatementName),
            (psycopg2.errors.TriggeredDataChangeViolation),
            (psycopg2.errors.InvalidAuthorizationSpecification),
            (psycopg2.errors.InvalidPassword),
            (psycopg2.errors.InvalidCursorName),
            (psycopg2.errors.TransactionRollback),
            (psycopg2.errors.TransactionIntegrityConstraintViolation),
            (psycopg2.errors.StatementCompletionUnknown),
            (psycopg2.errors.DeadlockDetected),
            (psycopg2.errors.InsufficientResources),
            (psycopg2.errors.DiskFull),
            (psycopg2.errors.OutOfMemory),
            (psycopg2.errors.TooManyConnections),
            (psycopg2.errors.ConfigurationLimitExceeded),
            (psycopg2.errors.ProgramLimitExceeded),
            (psycopg2.errors.StatementTooComplex),
            (psycopg2.errors.TooManyColumns),
            (psycopg2.errors.TooManyArguments),
            (psycopg2.errors.ObjectNotInPrerequisiteState),
            (psycopg2.errors.ObjectInUse),
            (psycopg2.errors.CantChangeRuntimeParam),
            (psycopg2.errors.LockNotAvailable),
            (psycopg2.errors.UnsafeNewEnumValueUsage),
            (psycopg2.errors.OperatorIntervention),
            (psycopg2.errors.QueryCanceled),
            (psycopg2.errors.AdminShutdown),
            (psycopg2.errors.CrashShutdown),
            (psycopg2.errors.CannotConnectNow),
            (psycopg2.errors.DatabaseDropped),
            (psycopg2.errors.IdleSessionTimeout),
            (psycopg2.errors.SystemError),
            (psycopg2.errors.IoError),
            (psycopg2.errors.UndefinedFile),
            (psycopg2.errors.DuplicateFile),
            (psycopg2.errors.FdwError),
            (psycopg2.errors.FdwOutOfMemory),
            (psycopg2.errors.FdwDynamicParameterValueNeeded),
            (psycopg2.errors.FdwInvalidDataType),
            (psycopg2.errors.FdwColumnNameNotFound),
            (psycopg2.errors.FdwInvalidDataTypeDescriptors),
            (psycopg2.errors.FdwInvalidColumnName),
            (psycopg2.errors.FdwInvalidColumnNumber),
            (psycopg2.errors.FdwInvalidUseOfNullPointer),
            (psycopg2.errors.FdwInvalidStringFormat),
            (psycopg2.errors.FdwInvalidHandle),
            (psycopg2.errors.FdwInvalidOptionIndex),
            (psycopg2.errors.FdwInvalidOptionName),
            (psycopg2.errors.FdwOptionNameNotFound),
            (psycopg2.errors.FdwReplyHandle),
            (psycopg2.errors.FdwUnableToCreateExecution),
            (psycopg2.errors.FdwUnableToCreateReply),
            (psycopg2.errors.FdwUnableToEstablishConnection),
            (psycopg2.errors.FdwNoSchemas),
            (psycopg2.errors.FdwSchemaNotFound),
            (psycopg2.errors.FdwTableNotFound),
            (psycopg2.errors.FdwFunctionSequenceError),
            (psycopg2.errors.FdwTooManyHandles),
            (psycopg2.errors.FdwInconsistentDescriptorInformation),
            (psycopg2.errors.FdwInvalidAttributeValue),
            (psycopg2.errors.FdwInvalidStringLengthOrBufferLength),
            (psycopg2.errors.FdwInvalidDescriptorFieldIdentifier),
        ],
    )
    def test_common_failure_when_db_connection_failed_sabclass(self, error, mocker, capfd, caplog):
        mocker.patch("logging.config.dictConfig")
        mocker.patch("psycopg2.connect").side_effect = error
        mocker.patch("time.sleep", return_value=None)
        sys.argv = ["cli.py", "get"]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.DB_CONNECTION_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert err == "[E10003]Could not connect to PolicyDB: \n"
        assert "[E10003]Could not connect to PolicyDB" in caplog.text

    @pytest.mark.parametrize(
        "args",
        [
            (["get", "-c", "nodeConfigurationPolicy", "--enabled", "all"]),
        ],
    )
    def test_common_failure_when_invalid_query(self, args, mocker, capfd, caplog):
        mocker.patch("logging.config.dictConfig")
        mock_cursor = mocker.MagicMock()
        err = psycopg2.ProgrammingError
        err.pgcode = "42601"
        mock_cursor.execute.side_effect = err

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.QUERY_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert (
            err
            == "[E10004]Query failed: 42601\nCheck PostgreSQL's error code table\n[https://pgsql-jp.github.io/current/html/errcodes-appendix.html]\n"
        )
        assert "[E10004]Query failed" in caplog.text

    @pytest.mark.parametrize(
        ("error", "err_code"),
        [
            (psycopg2.errors.CaseNotFound, "20000"),
            (psycopg2.errors.CardinalityViolation, "21000"),
            (psycopg2.errors.InvalidCatalogName, "3D000"),
            (psycopg2.errors.InvalidSchemaName, "3F000"),
            (psycopg2.errors.SyntaxErrorOrAccessRuleViolation, "42000"),
            (psycopg2.errors.InsufficientPrivilege, "42501"),
            (psycopg2.errors.SyntaxError, "42601"),
            (psycopg2.errors.InvalidName, "42602"),
            (psycopg2.errors.InvalidColumnDefinition, "42611"),
            (psycopg2.errors.NameTooLong, "42622"),
            (psycopg2.errors.DuplicateColumn, "42701"),
            (psycopg2.errors.AmbiguousColumn, "42702"),
            (psycopg2.errors.UndefinedColumn, "42703"),
            (psycopg2.errors.UndefinedObject, "42704"),
            (psycopg2.errors.DuplicateObject, "42710"),
            (psycopg2.errors.DuplicateAlias, "42712"),
            (psycopg2.errors.DuplicateFunction, "42723"),
            (psycopg2.errors.AmbiguousFunction, "42725"),
            (psycopg2.errors.GroupingError, "42803"),
            (psycopg2.errors.DatatypeMismatch, "42804"),
            (psycopg2.errors.WrongObjectType, "42809"),
            (psycopg2.errors.InvalidForeignKey, "42830"),
            (psycopg2.errors.CannotCoerce, "42846"),
            (psycopg2.errors.UndefinedFunction, "42883"),
            (psycopg2.errors.GeneratedAlways, "428C9"),
            (psycopg2.errors.ReservedName, "42939"),
            (psycopg2.errors.UndefinedTable, "42P01"),
            (psycopg2.errors.UndefinedParameter, "42P02"),
            (psycopg2.errors.DuplicateCursor, "42P03"),
            (psycopg2.errors.DuplicateDatabase, "42P04"),
            (psycopg2.errors.DuplicatePreparedStatement, "42P05"),
            (psycopg2.errors.DuplicateSchema, "42P06"),
            (psycopg2.errors.DuplicateTable, "42P07"),
            (psycopg2.errors.AmbiguousParameter, "42P08"),
            (psycopg2.errors.AmbiguousAlias, "42P09"),
            (psycopg2.errors.InvalidColumnReference, "42P10"),
            (psycopg2.errors.InvalidCursorDefinition, "42P11"),
            (psycopg2.errors.InvalidDatabaseDefinition, "42P12"),
            (psycopg2.errors.InvalidFunctionDefinition, "42P13"),
            (psycopg2.errors.InvalidPreparedStatementDefinition, "42P14"),
            (psycopg2.errors.InvalidSchemaDefinition, "42P15"),
            (psycopg2.errors.InvalidTableDefinition, "42P16"),
            (psycopg2.errors.InvalidObjectDefinition, "42P17"),
            (psycopg2.errors.IndeterminateDatatype, "42P18"),
            (psycopg2.errors.InvalidRecursion, "42P19"),
            (psycopg2.errors.WindowingError, "42P20"),
            (psycopg2.errors.CollationMismatch, "42P21"),
            (psycopg2.errors.IndeterminateCollation, "42P22"),
            (psycopg2.errors.WithCheckOptionViolation, "44000"),
        ],
    )
    def test_main_failure_when_invalid_query_subclass(self, error, err_code, mocker, capfd, caplog, docker_services):
        mocker.patch("logging.config.dictConfig")
        mock_cursor = mocker.MagicMock()
        err = error
        err.pgcode = err_code
        mock_cursor.execute.side_effect = err

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)
        sys.argv = ["cli.py", "get"]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.QUERY_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert (
            err
            == f"[E10004]Query failed: {err_code}\nCheck PostgreSQL's error code table\n[https://pgsql-jp.github.io/current/html/errcodes-appendix.html]\n"
        )
        assert "[E10004]Query failed" in caplog.text

    @pytest.mark.parametrize(
        "args",
        [
            (["insert", "-c", "nodeConfigurationPolicy", "-t", "test", "-i"]),
        ],
    )
    def test_common_failure_when_policy_duplicate_with_db(
        self, args, get_tmp_nodepolicyjson_file, mocker, capfd, caplog
    ):
        mocker.patch("logging.config.dictConfig")
        mock_cursor = mocker.MagicMock()
        mock_cursor.rowcount = 1

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)
        sys.argv = ["cli.py", *args, get_tmp_nodepolicyjson_file]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.DUPLICATE_POLICY_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert re.match(r"^\[E10008\]", err)
        assert "[E10008]" in caplog.text

    @pytest.mark.parametrize(
        "args",
        [
            (["get", "-c", "nodeConfigurationPolicy", "--enabled", "all"]),
        ],
    )
    def test_common_failure_when_nonexistent_id(self, args, mocker, capfd, caplog):
        mocker.patch("logging.config.dictConfig")
        mock_cursor = mocker.MagicMock()
        mock_cursor.execute.side_effect = IdNotFoundException("a21bc21587")

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == ExitCode.ID_NOT_FOUND_ERROR
        out, err = capfd.readouterr()
        # No std output
        assert out == ""
        # Output appropriate error codes and messages to standard error
        assert err == "[E10005]Specified a21bc21587 is not found\n"
        assert "[E10005]Specified a21bc21587 is not found" in caplog.text

    def test_common_failure_when_plugin_load_failed(
        self, mocker, caplog, capfd, get_tmp_nodepolicyjson_file
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("logging.config.dictConfig")
        args = [
            "update",
            "--policy-id",
            "123456789a",
            "-c",
            "nodeConfigurationPolicy",
            "-t",
            "hardwareConnectionsLimit",
            "-i",
            get_tmp_nodepolicyjson_file,
        ]
        sys.argv = ["cli.py", *args]
        mocker.patch.object(Plugin, "_get_plugin_names", side_effect=[Exception])

        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == ExitCode.PLUGIN_LOAD_ERROR
        out, err = capfd.readouterr()
        assert out == ""
        assert "Failed to load plugin" in err
        assert "[E10010]Failed to load plugin" in caplog.text

    def test_common_failure_when_required_plugin_not_found(
        self, mocker, capfd, get_tmp_nodepolicyjson_file
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        args = [
            "insert",
            "-c",
            "nodeConfigurationPolicy",
            "-t",
            "hardwareConnectionsLimit",
            "-i",
            get_tmp_nodepolicyjson_file,
            "--enabled",
        ]
        sys.argv = ["cli.py", *args]
        mocker.patch.object(
            Plugin,
            "_init_objs",
            side_effect=[ValidationError("Failed to load plugins in specified category")],
        )

        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        out, err = capfd.readouterr()
        assert out == ""
        assert "Failed to load plugins in specified category\n" in err

    @pytest.mark.parametrize("exc", [{RequestException()}, {Timeout()}, {ConnectionError()}, {Exception()}])
    def test_common_failure_when_secret_store_retrieval_failed(self, mocker, exc, capfd):
        mocker.patch("policymanager.common.config_reader.PolicyConfigReader")

        mocker.patch("policymanager.common.config_reader.PolicyLogConfigReader")
        mocker.patch("requests.get")

        sys.argv = ["cli.py", "get"]
        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == ExitCode.SECRET_REQUEST_ERROR
        out, err = capfd.readouterr()
        assert out == ""
        assert "[E10011]Failed to retrieve secret store" in err

    @pytest.mark.parametrize("args", [["get", "-c", "all"]])
    def test_common_success_when_unexpected_error_occurred(self, args, capfd, mocker):
        mocker.patch("psycopg2.connect", return_value=Exception)
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == ExitCode.VALIDATION_ERROR
        out, err = capfd.readouterr()
        assert out == ""
        assert "Unexpected error: " in err


class Testhelp:
    @pytest.mark.parametrize(
        "args",
        [
            ([]),
            (
                [
                    "--help",
                ]
            ),
            (
                [
                    "-h",
                ]
            ),
        ],
    )
    def test_common_success_when_help(
        self,
        args,
        capfd,
    ):
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 0
        out, err = capfd.readouterr()

        # usage shows
        assert "usage" in out
        assert "positional arguments:" in out
        assert "insert" in out
        assert "change-enabled" in out
        assert "get" in out
        assert "update" in out
        assert "export" in out
        assert "options:" in out
        assert "-h" in out
        assert "--help" in out

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "insert",
                    "--help",
                ]
            ),
            (
                [
                    "insert",
                    "-h",
                ]
            ),
        ],
    )
    def test_cmd_register_success_when_help(
        self,
        args,
        capfd,
    ):
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 0
        out, err = capfd.readouterr()

        # usage shows
        assert "usage" in out
        assert "insert" in out
        assert "options:" in out
        assert "-h" in out
        assert "--help" in out
        assert "-c" in out
        assert "--category" in out
        assert "CATEGORY" in out
        assert "-t" in out
        assert "--title" in out
        assert "TITLE" in out
        assert "-i" in out
        assert "--input" in out
        assert "POLICY_JSON_PATH" in out
        assert "--enabled" in out

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "change-enabled",
                    "--help",
                ]
            ),
            (
                [
                    "change-enabled",
                    "-h",
                ]
            ),
        ],
    )
    def test_cmd_change_enabled_success_when_help(
        self,
        args,
        capfd,
    ):
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 0
        out, err = capfd.readouterr()

        # usage shows
        assert "usage" in out
        assert "change-enabled" in out
        assert "options:" in out
        assert "-h" in out
        assert "--help" in out
        assert "--enable-id-list" in out
        assert "ID" in out
        assert "--disable-id-list" in out
        assert "ID" in out

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "get",
                    "--help",
                ]
            ),
            (
                [
                    "get",
                    "-h",
                ]
            ),
        ],
    )
    def test_cmd_get_success_when_help(
        self,
        args,
        capfd,
    ):
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 0
        out, err = capfd.readouterr()

        # usage shows
        assert "usage" in out
        assert "get" in out
        assert "options:" in out
        assert "-h" in out
        assert "--help" in out
        assert "--policy-id" in out
        assert "POLICY_ID" in out
        assert "-c" in out
        assert "--category" in out
        assert "all" in out
        assert "CATEGORY" in out
        assert "--enabled" in out
        assert "all" in out
        assert "ENABLED" in out
        assert "--sub-category" in out
        assert "SUB_CATEGORY" in out
        assert "--device" in out
        assert "DEVICE" in out
        assert "--sort-by" in out
        assert "SORT_BY" in out
        assert "--order-by" in out
        assert "ORDER_BY" in out

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "update",
                    "--help",
                ]
            ),
            (
                [
                    "update",
                    "-h",
                ]
            ),
        ],
    )
    def test_cmd_update_success_when_help(self, args, capfd, mocker):
        mocker.patch("logging.config.dictConfig")
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 0
        out, err = capfd.readouterr()

        # usage shows
        assert "usage" in out
        assert "update" in out
        assert "options:" in out
        assert "-h" in out
        assert "--help" in out
        assert "--policy-id" in out
        assert "POLICY_ID" in out
        assert "-c" in out
        assert "--category" in out
        assert "CATEGORY" in out
        assert "-t" in out
        assert "--title" in out
        assert "TITLE" in out
        assert "-i" in out
        assert "--input" in out
        assert "POLICY_JSON_PATH" in out
        assert "--force" in out

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "delete",
                    "--help",
                ]
            ),
            (
                [
                    "delete",
                    "-h",
                ]
            ),
        ],
    )
    def test_cmd_delete_success_when_help(self, args, capfd, mocker):
        mocker.patch("logging.config.dictConfig")
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 0
        out, err = capfd.readouterr()

        # usage shows
        assert "usage" in out
        assert "delete" in out
        assert "options:" in out
        assert "-h" in out
        assert "--help" in out
        assert "--policy-id" in out
        assert "POLICY_ID" in out
        assert "--force" in out

    @pytest.mark.parametrize(
        "args",
        [
            (
                [
                    "export",
                    "--help",
                ]
            ),
            (
                [
                    "export",
                    "-h",
                ]
            ),
        ],
    )
    def test_cmd_export_success_when_help(
        self,
        args,
        capfd,
    ):
        sys.argv = ["cli.py", *args]
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 0
        out, err = capfd.readouterr()

        # usage shows
        assert "usage" in out
        assert "export" in out
        assert "options:" in out
        assert "-h" in out
        assert "--help" in out
        assert "--format" in out
        assert "FORMAT" in out
        assert "-o" in out
        assert "--output" in out
        assert "OUTPUT_FILE_PATH" in out
