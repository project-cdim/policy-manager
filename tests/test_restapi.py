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

import json
import logging
import os
import random
import subprocess
import tempfile
import time
import uuid
from http import HTTPStatus

import psycopg2
import pytest
import requests
import yaml
from fastapi.testclient import TestClient
from requests.exceptions import ConnectionError, RequestException, Timeout

from policymanager import restapi
from policymanager.common.logger import Logger, initialize_log
from policymanager.common.config_reader import PolicyConfigReader, PolicyLogConfigReader
from policymanager.common.custom_exceptions import (
    DuplicatePolicyException,
    IdNotFoundException,
    InvalidOperationException,
    LogInitializationError,
    SettingFileValidationError,
    LogSettingFileValidationError,
    UnmatchIdException,
)
from policymanager.common.db import DbAccess, GetAllOption
from policymanager.common.plugin import Plugin
from policymanager.plugins.base import BasePolicyPlugin
from policymanager.restapi import app, db_connection, main
from tests.conftest import BASE_LOGGING_CONFIG, CHARSET_ENCODING, HEADERS_TYPE_JSON, HEADERS_TYPE_YAML, HEADERS_NOSNIFF

client = TestClient(app)

BASEURL = "/cdim/api/v1/"
DB_CONNECT = None


def is_postgresql_ready():
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


@pytest.fixture
def tmp_all_policy_json_file():
    "param policy data fixture"
    json_data = {
        "exportedCount": 20,
        "policies": [
            {
                "policyID": "0000000001",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
            },
            {
                "policyID": "0000000002",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"memory": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
            },
            {
                "policyID": "0000000003",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"storage": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
            },
            {
                "policyID": "0000000004",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
            },
            {
                "policyID": "0000000005",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"fpga": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
            },
            {
                "policyID": "0000000006",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"accelerator": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
            },
            {
                "policyID": "0000000007",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
            },
            {
                "policyID": "0000000008",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"virtualMedia": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
            },
            {
                "policyID": "0000000009",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"graphicController": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
            },
            {
                "policyID": "0000000010",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"networkInterface": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
            },
            {
                "policyID": "0000000011",
                "category": "systemOperationPolicy",
                "title": "NodeConfPolicy",
                "policy": {
                    "useThreshold": {
                        "cpu": {
                            "value": 50,
                            "unit": "percent",
                            "comparison": "gt",
                        }
                    }
                },
                "enabled": True,
            },
            {
                "policyID": "0000000012",
                "category": "systemOperationPolicy",
                "title": "NodeConfPolicy",
                "policy": {
                    "useThreshold": {
                        "memory": {
                            "value": 50,
                            "unit": "percent",
                            "comparison": "gt",
                        }
                    }
                },
                "enabled": True,
            },
            {
                "policyID": "0000000013",
                "category": "systemOperationPolicy",
                "title": "NodeConfPolicy",
                "policy": {
                    "useThreshold": {
                        "storage": {
                            "value": 50,
                            "unit": "percent",
                            "comparison": "gt",
                        }
                    }
                },
                "enabled": True,
            },
            {
                "policyID": "0000000014",
                "category": "systemOperationPolicy",
                "title": "NodeConfPolicy",
                "policy": {
                    "useThreshold": {
                        "gpu": {
                            "value": 50,
                            "unit": "percent",
                            "comparison": "gt",
                        }
                    }
                },
                "enabled": True,
            },
            {
                "policyID": "0000000015",
                "category": "systemOperationPolicy",
                "title": "NodeConfPolicy",
                "policy": {
                    "useThreshold": {
                        "fpga": {
                            "value": 50,
                            "unit": "percent",
                            "comparison": "gt",
                        }
                    }
                },
                "enabled": True,
            },
            {
                "policyID": "0000000016",
                "category": "systemOperationPolicy",
                "title": "NodeConfPolicy",
                "policy": {
                    "useThreshold": {
                        "accelerator": {
                            "value": 50,
                            "unit": "percent",
                            "comparison": "gt",
                        }
                    }
                },
                "enabled": True,
            },
            {
                "policyID": "0000000017",
                "category": "systemOperationPolicy",
                "title": "NodeConfPolicy",
                "policy": {
                    "useThreshold": {
                        "dsp": {
                            "value": 50,
                            "unit": "percent",
                            "comparison": "gt",
                        }
                    }
                },
                "enabled": True,
            },
            {
                "policyID": "0000000018",
                "category": "systemOperationPolicy",
                "title": "NodeConfPolicy",
                "policy": {
                    "useThreshold": {
                        "virtualMedia": {
                            "value": 50,
                            "unit": "percent",
                            "comparison": "gt",
                        }
                    }
                },
                "enabled": True,
            },
            {
                "policyID": "0000000019",
                "category": "systemOperationPolicy",
                "title": "NodeConfPolicy",
                "policy": {
                    "useThreshold": {
                        "graphicController": {
                            "value": 50,
                            "unit": "percent",
                            "comparison": "gt",
                        }
                    }
                },
                "enabled": True,
            },
            {
                "policyID": "0000000020",
                "category": "systemOperationPolicy",
                "title": "NodeConfPolicy",
                "policy": {
                    "useThreshold": {
                        "networkInterface": {
                            "value": 50,
                            "unit": "percent",
                            "comparison": "gt",
                        }
                    }
                },
                "enabled": True,
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
def tmp_import_json_file():
    """tmp  policy json file fuxture"""
    json_data = {
        "exportedCount": 2,
        "policies": [
            {
                "policyID": "d8eceb14da",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"accelerator": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "category": "systemOperationPolicy",
                "title": "NodeConfPolicy",
                "policy": {
                    "useThreshold": {
                        "accelerator": {
                            "value": 50,
                            "unit": "percent",
                            "comparison": "gt",
                        }
                    }
                },
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
def tmp_import_yaml_file():
    """tmp  policy yaml file fuxture"""
    yaml_data = {
        "exportedCount": 2,
        "policies": [
            {
                "policyID": "d8eceb14da",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"accelerator": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "category": "systemOperationPolicy",
                "title": "NodeConfPolicy",
                "policy": {
                    "useThreshold": {
                        "accelerator": {
                            "value": 50,
                            "unit": "percent",
                            "comparison": "gt",
                        }
                    }
                },
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
def get_tmp_import_json_content_yaml_file():
    """tmp  policy json file fuxture"""
    json_data = {
        "exportedCount": 5,
        "policies": [
            {
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14da",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14db",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 2, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "ffeceb14dc",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
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
def tmp_duplicate_import_json_file():
    """tmp  policy json file fuxture"""
    json_data = {
        "exportedCount": 2,
        "policies": [
            {
                "policyID": "ffeceb14da",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
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
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def tmp_mul_duplicate_import_json_file():
    """tmp  policy json file fuxture"""
    json_data = {
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
def tmp_mul_duplicate_import_yaml_file():
    """tmp  policy yaml file fuxture"""
    json_data = {
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
                explicit_start=True,
                encoding="utf-8",
            )
        try:
            yield yaml_file
        finally:
            os.remove(yaml_file)


@pytest.fixture
def tmp_import_json_file_err():
    """tmp  policy json file fuxture"""
    json_data = {
        "exportedCount": 2,
        "policies": [
            {
                "policyID": "d8eceb14da",
                "category": "systemOperationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"accelerator": {"maxNum": 5, "minNum": 1}}},
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
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def tmp_import_yaml_file_err():
    """tmp  policy yaml file fuxture"""
    json_data = {
        "exportedCount": 2,
        "policies": [
            {
                "policyID": "d8eceb14da",
                "category": "systemOperationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"accelerator": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            }
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
                explicit_start=True,
                encoding="utf-8",
            )
        try:
            yield yaml_file
        finally:
            os.remove(yaml_file)


@pytest.fixture
def tmp_import_json_file_many_err():
    """tmp  policy json file fuxture"""
    json_data = {
        "exportedCount": 4,
        "policies": [
            {
                "policyID": "d8eceb14da",
                "category": "systemOperationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"accelerator": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "d8eceb14da",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 10}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "d8eceb14da",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 10, "minNum": 5}}},
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
def tmp_import_yaml_file_many_err():
    """tmp  policy yaml file fuxture"""
    json_data = {
        "exportedCount": 2,
        "policies": [
            {
                "policyID": "d8eceb14da",
                "category": "systemOperationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"accelerator": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "d8eceb14da",
                "category": "nodeConfigurationPolicy",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 10}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            },
            {
                "policyID": "d8eceb14da",
                "title": "NodeConfPolicy",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 10, "minNum": 5}}},
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
                explicit_start=True,
                encoding="utf-8",
            )
        try:
            yield yaml_file
        finally:
            os.remove(yaml_file)


@pytest.fixture
def tmp_import_json_file_pol0_err():
    """tmp  policy json file fuxture"""
    json_data = {"exportedCount": 0, "policies": []}

    with tempfile.TemporaryDirectory() as dir_path:
        json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
        with open(json_file, mode="w", encoding="utf-8") as fh:
            json.dump(json_data, fh, indent=4)
        try:
            yield json_file
        finally:
            os.remove(json_file)


@pytest.fixture
def tmp_import_yaml_file_pol0_err():
    """tmp  policy json file fuxture"""
    json_data = {"exportedCount": 0, "policies": []}

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
        try:
            yield yaml_file
        finally:
            os.remove(yaml_file)


@pytest.fixture
def init_db_instance(docker_services):
    docker_services.wait_until_responsive(timeout=30.0, pause=0.1, check=lambda: is_postgresql_ready())
    yield DB_CONNECT
    DB_CONNECT.close()


class TestRegister:
    @pytest.mark.parametrize(
        ("params", "sleep"),
        [
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"memory": {"maxNum": 1, "minNum": 1}}},
                },
                0.1,
            ),  # Node configuration constraint
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "networkInterface": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                },
                0.2,
            ),  # System operation constraint with device = networkInterface
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"storage": {"maxNum": 1, "minNum": 1}}},
                    "enabled": False,
                },
                0.1,
            ),  # Node configuration constraint with enabled = false
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "accelerator": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                    "enabled": False,
                },
                0.2,
            ),  # System operation constraint with enabled = false
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"accelerator": {"maxNum": 1, "minNum": 1}}},
                    "enabled": True,
                },
                0.1,
            ),  # Node configuration constraint with enabled = true
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "graphicController": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                    "enabled": True,
                },
                0.2,
            ),  # System operation constraint with enabled = true
        ],
    )
    def test_api_register_success(self, params, sleep, mocker, init_db_instance):  # pylint: disable=C2401,W0613,W0621
        """Success test"""
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        time.sleep(sleep)
        response = client.post(BASEURL + "policies", json=params)

        content = json.loads(response.content.decode())

        assert ("policyID") in content.keys()
        inserted_id = content.get("policyID")

        cursor.execute(
            query=f"SELECT policyID, category, title, policy, enabled, createdAt, updatedAt from policies WHERE policyID = '{inserted_id}'"
        )
        inserted_policy = cursor.fetchone()

        # Verify whether the newly added constraints include both enabled and disabled states
        if "enabled" in params.keys() and params.get("enabled"):
            assert inserted_policy[4] == True
        else:
            assert inserted_policy[4] == False

        assert response.status_code == 201

        cursor.execute(query=f"Delete from policies where policyID = '{inserted_id}'")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "params",
        [
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 1, "minNum": 1}}},
                }
            ),  # Node configuration constraint with minNum = maxNum
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 2, "minNum": 1}}},
                }
            ),  # Node configuration constraint with minNum = maxNum + 1
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparison": "gt"}}},
                }
            ),  # System operation constraint with comparison = gt
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparison": "lt"}}},
                }
            ),  # System operation constraint with comparison = lt
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 0, "unit": "percent", "comparison": "ge"}}},
                }
            ),  # System operation constraint with comparison = ge and value = 0
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 100, "unit": "percent", "comparison": "le"}}},
                }
            ),  # System operation constraint with comparison = le and value = 100
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "memory": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                }
            ),  # System operation constraint with device = memory
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "storage": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                }
            ),  # System operation constraint with device = storage
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"gpu": {"value": 100, "unit": "percent", "comparison": "le"}}},
                }
            ),  # System operation constraint with device = gpu
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "fpga": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                }
            ),  # System operation constraint with device = fpga
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "accelerator": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                }
            ),  # System operation constraint with device = accelerator
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"dsp": {"value": 100, "unit": "percent", "comparison": "le"}}},
                }
            ),  # System operation constraint with device = dsp
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "virtualMedia": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                }
            ),  # System operation constraint with device = virtualMedia
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "graphicController": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                }
            ),  # System operation constraint with device = graphicController
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "networkInterface": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                }
            ),  # System operation constraint with device = networkInterface
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 1, "minNum": 1}}},
                    "enabled": False,
                }
            ),  # Node configuration constraint with enabled = false
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 1, "minNum": 1}}},
                    "enabled": True,
                }
            ),  # Node configuration constraint with enabled = true
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "networkInterface": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                    "enabled": True,
                }
            ),  # System operation constraint with enabled = true
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "networkInterface": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                    "enabled": False,
                }
            ),  # System operation constraint with enabled = false
        ],
    )
    def test_api_register_201(self, params, mocker, init_db_instance):  # pylint: disable=C2401,W0613,W0621
        """Success test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        response = client.post(BASEURL + "policies", json=params)
        content = json.loads(response.content.decode())
        assert response.status_code == HTTPStatus.CREATED.value

        assert ("policyID") in content.keys()
        inserted_id = content.get("policyID")

        cursor.execute(
            query=f"SELECT policyID, category, title, policy, enabled, createdAt, updatedAt from policies WHERE policyID = '{inserted_id}'"
        )
        inserted_policy = cursor.fetchone()

        assert (
            inserted_policy[1] == params["category"]
        )  # Assertion between the Category registered in the DB and the Category received in Params
        assert (
            inserted_policy[2] == params["title"]
        )  # Assertion between the Title registered in the DB and the Title received in Params
        assert (
            inserted_policy[3] == params["policy"]
        )  # Assertion between the policy registered in the DB and the policy received in Params
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

        cursor.execute(query=f"Delete from policies where policyID = '{inserted_id}'")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "params",
        [
            (
                {
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                }
            ),  # Case where category is missing
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                }
            ),  # Case where title is missing
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                }
            ),  # Case where policy is missing
            (
                {
                    "category": [1],
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                }
            ),  # Case where category is not a string
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": [1],
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                }
            ),  # Case where title is not a string
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": [1],
                }
            ),  # Case where policy is not a dictionary
            {
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 1, "minNum": 10}}},
            },  # Case where minNum is greater than maxNum
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "a" * 101,
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where title is more than 100 characters
            (
                {
                    "categoryy": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where category key has an extra "y"
            (
                {
                    "ccategory": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where category key has an extra "c" at the beginning
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "titlee": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where title key has an extra "e"
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "ttitle": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where title key has an extra "t" at the beginning
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policyy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where policy key has an extra "y"
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "ppolicy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where policy key has an extra "p"
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "ppolicy": {"hardwareConnectionsLimit": {"otherProcessor": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where policy has an incorrect device type
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"ssss": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where policy key name is incorrect
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 100, "unit": "percent", "comparison": "gt"}}},
                }
            ),  # Case where value and comparison are out of valid range (value = 100, comparison = gt)
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 0, "unit": "percent", "comparison": "lt"}}},
                }
            ),  # Case where value and comparison are out of valid range (value = 0, comparison = lt)
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 101, "unit": "percent", "comparison": "lt"}}},
                }
            ),  # Case where value exceeds the upper limit
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": -1, "unit": "percent", "comparison": "lt"}}},
                }
            ),  # Case where value is below the lower limit
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"unit": "percent", "comparison": "lt"}}},
                }
            ),  # Case where value is missing
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 80, "comparison": "lt"}}},
                }
            ),  # Case where unit is missing
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 80, "unit": "percent"}}},
                }
            ),  # Case where comparison is missing
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 80, "unit": 80, "comparison": "lt"}}},
                }
            ),  # Case where unit is not "percent"
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparison": 80}}},
                }
            ),  # Case where comparison is not [lt, gt, ge, le]
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "cpu": {
                                "value": "percent",
                                "unit": "percent",
                                "comparison": "lt",
                            }
                        }
                    },
                }
            ),  # Case where value is not an integer
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "othrerProcessor": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                }
            ),  # Case where device = otherProcessor
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {
                        "useThreshold": {
                            "cpu": {
                                "value": 50,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                },
            ),  # Case where category is node configuration constraint, but policy is system operation constraint
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where category is system operation constraint, but policy is node configuration constraint
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "cpu": {
                                "value": 50,
                                "unit": "percent",
                                "comparison": ">==",
                            }
                        }
                    },
                },
            ),  # Case where comparison = ">==" (unexpected string)
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "cpu": {
                                "value": 50,
                                "unit": "percent",
                                "comparison": "=",
                            }
                        }
                    },
                },
            ),  # Case where comparison = "=" (unexpected string)
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "cpu": {
                                "value": 50,
                                "unit": "percent",
                                "comparison": "=>",
                            }
                        }
                    },
                },
            ),  # Case where comparison = "=>" (unexpected string)
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "cpu": {
                                "value": 50,
                                "unit": "percent",
                                "comparison": "<<",
                            }
                        }
                    },
                },
            ),  # Case where comparison = "<<" (unexpected string)
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "cpu": {
                                "value": 50,
                                "unit": "percent",
                                "comparison": "",
                            }
                        }
                    },
                },
            ),  # Case where comparison = "" (unexpected string)
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 1, "minNum": 1}}},
                    "enabled": "false",
                },
            ),  # Node configuration constraint where enabled is a string
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "networkInterface": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                    "enabled": "",
                },
            ),  # System operation constraint where enabled is an empty string
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "networkInterface": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                    "enabled": "true",
                },
            ),  # System operation constraint where enabled is true
        ],
    )
    def test_api_register_400_with_message_when_invalid_parameters(
        self, mock_db_connection, params, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        response = client.post(BASEURL + "policies", json=params)
        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("code", "E10001") in content.items()
        assert len(content.get("message")) >= 1
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_register_500_with_message_when_db_connection_failed(
        self, mock_db_connection_operationalerror, init_db_instance
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        response = client.post(
            BASEURL + "policies",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10003") in content.items()
        assert ("message", "Could not connect to PolicyDB: ") in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_register_500_with_message_when_invalid_query(
        self, mock_db_connection_programmingerror, caplog, init_db_instance
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        response = client.post(
            BASEURL + "policies",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10004") in content.items()
        assert (
            "message",
            "Query failed:42601 Check PostgreSQL's error code table [https://pgsql-jp.github.io/current/html/errcodes-appendix.html]",
        ) in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_register_500_with_message_when_invalid_config_value(
        self, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("policymanager.common.config_reader.PolicyLogConfigReader.__init__", return_value=None)
        mocker.patch(
            "policymanager.common.config_reader.PolicyLogConfigReader.get_log_config",
            new_callable=mocker.PropertyMock,
            return_value=BASE_LOGGING_CONFIG,
        )
        mocker.patch(
            "policymanager.common.config_reader.PolicyConfigReader.__init__",
            side_effect=SettingFileValidationError("Dummy message"),
        )
        response = client.post(
            BASEURL + "policies",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )
        content = json.loads(response.content.decode())
        print(content)
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_config.yaml Dummy message",
        ) in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_register_500_with_message_when_config_load_failed(
        self, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("policymanager.common.config_reader.PolicyLogConfigReader.__init__", return_value=None)
        mocker.patch(
            "policymanager.common.config_reader.PolicyLogConfigReader.get_log_config",
            new_callable=mocker.PropertyMock,
            return_value=BASE_LOGGING_CONFIG,
        )
        # Mock resources.read_text to raise FileNotFoundError for PolicyConfigReader
        mocker.patch(
            "importlib.resources.read_text",
            side_effect=[None, FileNotFoundError("File not found")],
        )
        response = client.post(
            BASEURL + "policies",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert content.get("message").startswith("Failed to load policymanager_config.yaml")
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_register_500_with_message_when_invalid_log_config_value(
        self, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("yaml.safe_load", side_effect=[SettingFileValidationError("Dummy message")])
        response = client.post(
            BASEURL + "policies",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_log_config.yaml ('Dummy message',)",
        ) in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_register_500_with_message_when_log_config_load_failed(
        self, mocker, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("yaml.safe_load").side_effect = FileNotFoundError("File not found")
        response = client.post(
            BASEURL + "policies",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_log_config.yaml ('File not found',)",
        ) in content.items()
        # logging is not initialized yet, error logs cannot be checked
        # assert "[E10002]Failed to load policymanager_config.yaml" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_register_500_with_message_when_policy_duplicate(
        self, mock_db_connection_dublicatedPoliceError, caplog, init_db_instance
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        response = client.post(
            BASEURL + "policies",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("code", "E10008") in content.items()
        assert (
            "message",
            "Specified policy is duplicate of",
        ) in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_register_500_with_message_when_plugin_load_failed(self, mocker):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch.object(Plugin, "_get_plugin_names", side_effect=[Exception])

        response = client.post(
            BASEURL + "policies",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10010") in content.items()
        assert (
            "message",
            "Failed to load plugin",
        ) in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_register_500_with_message_when_init_log(self, mocker):

        mocker.patch.object(Logger, "__init__", side_effect=LogInitializationError)
        response = client.post(
            BASEURL + "policies",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10012") in content.items()
        assert (
            "message",
            "Internal server error. Failed in log initialization",
        ) in content.items()


class TestChangeEnabled:
    """Test Class"""

    @pytest.mark.parametrize(
        "params",
        [
            (
                {"enableIDList": ["a21bc21587"], "disableIDList": ["a21bc21586"]}
            ),  # Case where both enable and disable lists have one ID each
            (
                {
                    "enableIDList": ["a21bc21583", "ca2b1215ef"],
                    "disableIDList": ["a21bc21581"],
                }
            ),  # Case where the enable list contains multiple IDs
            (
                {
                    "enableIDList": ["a21bc2158a"],
                    "disableIDList": ["a21bc2158e", "ca2b121523"],
                }
            ),  # Case where the disable list contains multiple IDs
            ({"enableIDList": [], "disableIDList": ["a21bc21381"]}),  # Case where the enable list is empty
            ({"enableIDList": ["a21bc22587"], "disableIDList": []}),  # Case where the disable list is empty
            ({"enableIDList": ["a21bc21487"]}),  # Case where only the enable list is provided
            ({"disableIDList": ["a21bc25587"]}),  # Case where only the disable list is provided
        ],
    )
    def test_api_change_enabled_201(self, init_db_instance, mocker, params: dict):  # pylint: disable=C2401,W0613,W0621
        """Success test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        for k, v in params.items():
            for id_ in v:
                p = [id_]
                query = """INSERT into policies (policyID, category,title, policy,enabled,createdAt,updatedAt)
                                    VALUES (%s, 'nodeConfigurationPolicy', 'test', '{"hardwareConnectionsLimit":{}}', %s,'2024/06/3', '2024/06/3')"""
                if k == "enableIDList":
                    p.append(False)
                else:
                    p.append(True)
                cursor.execute(query, p)
                init_db_instance.commit()

        response = client.put(
            BASEURL + "policies/change-enabled",
            json=params,
        )

        for k, v in params.items():
            for id_ in v:
                cursor.execute(f"Select enabled from policies where policyid='{id_}'")
                db_policy = cursor.fetchone()
                assert (k == "enableIDList") == db_policy[0]

        assert response.status_code == 201

        cursor.execute(query="delete from policies;")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "params",
        [
            (
                {"enableIDList": ["a21bc21587a"], "disableIDList": ["ca2b1215ef"]}
            ),  # Case where an ID in the enable list exceeds the specified length
            (
                {"enableIDList": ["a21bc2158"], "disableIDList": ["a21bc21587"]}
            ),  # Case where an ID in the enable list is shorter than the specified length
            (
                {"enableIDList": ["qa21bc21587"], "disableIDList": ["ca2b1215ef"]}
            ),  # Case where an ID in the enable list contains non-hexadecimal characters
            (
                {
                    "enableIDList": ["a21bc21587", "b51b1215cea"],
                    "disableIDList": ["321da215ef1"],
                }
            ),  # Case where the enable list contains multiple IDs, including an invalid one
            (
                {"xxxxx": ["a21bc21587"], "disableIDList": ["ca2b1215ef"]}
            ),  # Case with an invalid key name in the enable list
            (
                {"enableIDList": ["a21bc21587"], "disableIDList": ["321da215ef1"]}
            ),  # Case where an ID in the disable list exceeds the specified length
            (
                {"enableIDList": ["a21bc21587"], "disableIDList": ["321da5f"]}
            ),  # Case where an ID in the disable list is shorter than the specified length
            (
                {"enableIDList": ["a21bc21587"], "disableIDList": ["321da215fz"]}
            ),  # Case where an ID in the disable list contains non-hexadecimal characters
            (
                {
                    "enableIDList": ["a21bc21587"],
                    "disableIDList": ["321da215ef1", "b51b1215cea"],
                }
            ),  # Case where the disable list contains multiple IDs, including an invalid one
            (
                {"enableIDList": ["a21bc21587"], "zzzzz": ["a21bc21587"]}
            ),  # Case with an invalid key name in the disable list
            ({"enableIDList": [], "disableIDList": []}),  # Case where both enable and disable ID lists are empty
        ],
    )
    def test_api_change_enabled_400_with_message_when_invalid_parameters(
        self, mock_db_connection, params, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        response = client.put(
            BASEURL + "policies/change-enabled",
            json=params,
        )

        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("code", "E10001") in content.items()
        assert len(content.get("message")) >= 1
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_change_enabled_500_with_message_when_db_connection_failed(
        self, mock_db_connection_operationalerror
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        response = client.put(
            BASEURL + "policies/change-enabled",
            json={"enableIDList": ["a21bc21587"], "disableIDList": ["a21bc21587"]},
        )

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10003") in content.items()
        assert ("message", "Could not connect to PolicyDB: ") in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_change_enabled_500_with_message_when_invalid_query(
        self, mock_db_connection_programmingerror
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        response = client.put(
            BASEURL + "policies/change-enabled",
            json={"enableIDList": ["a21bc21587"], "disableIDList": ["a21bc21587"]},
        )

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10004") in content.items()
        assert (
            "message",
            "Query failed:42601 Check PostgreSQL's error code table [https://pgsql-jp.github.io/current/html/errcodes-appendix.html]",
        ) in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_change_enabled_400_with_message_when_nonexistent_constraint_specified(
        self, mock_db_connection_idnotfoundexception, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("logging.config.dictConfig")
        response = client.put(
            BASEURL + "policies/change-enabled",
            json={"enableIDList": ["a21bc21587"], "disableIDList": ["a21bc21587"]},
        )

        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("code", "E10006") in content.items()
        assert ("message", "IDs ['a21bc21587'] is not found") in content.items()
        assert "[E10006]IDs ['a21bc21587'] is not found" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_change_enabled_500_with_message_when_invalid_config_value(
        self, mock_db_connection_settingFilevalidationError, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("logging.config.dictConfig")
        response = client.put(
            BASEURL + "policies/change-enabled",
            json={"enableIDList": ["a21bc21587"], "disableIDList": ["a21bc21587"]},
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_config.yaml Dummy message",
        ) in content.items()
        assert "[E10002]Failed to load policymanager_config.yaml" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_change_enabled_500_with_message_when_invalid_config_value_without_logger(
        self, mocker, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        mocker.patch("policymanager.restapi.initialize_log", side_effect=SettingFileValidationError("Dummy message"))

        response = client.put(
            BASEURL + "policies/change-enabled",
            json={"enableIDList": ["a21bc21587"], "disableIDList": ["a21bc21587"]},
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_config.yaml Dummy message",
        ) in content.items()
        assert "[E10002]Failed to load policymanager_config.yaml" not in caplog.text

    def test_api_change_enabled_500_with_message_when_config_load_failed(
        self, mocker, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        # mocker.patch("policymanager.common.config_reader.PolicyConfigReader")
        # mocker.patch("policymanager.common.config_reader.PolicyLogConfigReader._check_directory_exists").side_effect = FileNotFoundError("File not found")
        mocker.patch("yaml.safe_load").side_effect = FileNotFoundError("File not found")
        response = client.put(
            BASEURL + "policies/change-enabled",
            json={"enableIDList": ["a21bc21587"], "disableIDList": ["a21bc21587"]},
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_log_config.yaml ('File not found',)",
        ) in content.items()
        # logging is not initialized yet, error logs cannot be checked
        # assert "[E10002]Failed to load policymanager_config.yaml" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_change_enabled_500_with_message_when_init_log(self, mocker):
        mocker.patch.object(Logger, "__init__", side_effect=LogInitializationError)
        response = client.put(
            BASEURL + "policies/change-enabled",
            json={"enableIDList": ["a21bc21587"], "disableIDList": ["a21bc21587"]},
        )

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10012") in content.items()
        assert (
            "message",
            "Internal server error. Failed in log initialization",
        ) in content.items()


class TestGetAll:
    @pytest.mark.parametrize(
        "params",
        [
            ({"category": ["all"], "enabled": "all"}),  # Case where category is all
            ({"category": ["all"], "enabled": "true"}),  # Case where enabled is true
            ({"category": ["all"], "enabled": "false"}),  # Case where enabled is false
            ({"category": ["all"]}),  # Case where only category is specified
            ({"enabled": "all"}),  # Case where only enabled is specified
            ({"enabled": "true"}),  # Case where only enabled is specified
            ({"enabled": "false"}),  # Case where only enabled is specified
            ({"subCategory": "hardwareConnectionsLimit"}),  # Case where only subCategory is specified
            ({"subCategory": "useThreshold"}),  # Case where only subCategory is specified
            ({"device": "cpu"}),  # Case where device is cpu
            ({"device": "memory"}),  # Case where device is memory
            ({"device": "storage"}),  # Case where device is storage
            ({"device": "gpu"}),  # Case where device is gpu
            ({"device": "fpga"}),  # Case where device is fpga
            ({"device": "accelerator"}),  # Case where device is accelerator
            ({"device": "dsp"}),  # Case where device is dsp
            ({"device": "virtualMedia"}),  # Case where device is virtualMedia
            ({"device": "graphicController"}),  # Case where device is graphicController
            ({"device": "networkInterface"}),  # Case where device is networkInterface
            ({"fields": ["policyID"]}),  # Case where fields is policyID
            ({"sortBy": "createdAt"}),  # Case where only sortBy is specified
            ({"sortBy": "updatedAt"}),  # Case where only sortBy is specified
            ({"sortBy": "createdAt", "orderBy": "asc"}),  # Combination of sortBy and orderBy (ascending)
            ({"sortBy": "createdAt", "orderBy": "desc"}),  # Combination of sortBy and orderBy (descending)
            ({"sortBy": "updatedAt", "orderBy": "asc"}),  # Combination of sortBy and orderBy (ascending)
            ({"sortBy": "updatedAt", "orderBy": "desc"}),  # Combination of sortBy and orderBy (descending)
            (
                {
                    "category": ["all"],
                    "enabled": "all",
                    "subCategory": "hardwareConnectionsLimit",
                    "device": "cpu",
                    "fields": ["policyID", "createdAt", "updatedAt"],
                    "sortBy": "createdAt",
                    "orderBy": "asc",
                }
            ),  # Combination of parameters (all parameters are present)
            (
                {
                    "enabled": "true",
                    "subCategory": "hardwareConnectionsLimit",
                    "device": "cpu",
                    "fields": ["policyID"],
                    "sortBy": "createdAt",
                    "orderBy": "asc",
                }
            ),  # Combination of parameters (category is missing)
            (
                {
                    "category": ["all"],
                    "subCategory": "hardwareConnectionsLimit",
                    "device": "cpu",
                    "fields": ["policyID", "createdAt", "updatedAt"],
                    "sortBy": "createdAt",
                    "orderBy": "asc",
                }
            ),  # Combination of parameters (enabled is missing)
            (
                {
                    "category": ["all"],
                    "enabled": "all",
                    "device": "cpu",
                    "fields": ["policyID", "createdAt", "updatedAt"],
                    "sortBy": "createdAt",
                    "orderBy": "asc",
                }
            ),  # Combination of parameters (subCategory is missing)
            (
                {
                    "category": ["all"],
                    "enabled": "true",
                    "subCategory": "useThreshold",
                    "fields": ["policyID", "createdAt", "updatedAt"],
                    "sortBy": "createdAt",
                    "orderBy": "asc",
                }
            ),  # Combination of parameters (device is missing)
            (
                {
                    "category": ["all"],
                    "enabled": "false",
                    "subCategory": "useThreshold",
                    "device": "cpu",
                    "sortBy": "createdAt",
                    "orderBy": "asc",
                }
            ),  # Combination of parameters (fields is missing)
            (
                {
                    "category": ["all"],
                    "enabled": "false",
                    "subCategory": "useThreshold",
                    "device": "cpu",
                    "fields": ["policyID", "createdAt", "updatedAt"],
                    "orderBy": "asc",
                }
            ),  # Combination of parameters (sortBy is missing)
            (
                {
                    "category": ["all"],
                    "enabled": "false",
                    "subCategory": "useThreshold",
                    "device": "cpu",
                    "fields": ["policyID", "createdAt", "updatedAt"],
                    "sortBy": "createdAt",
                }
            ),  # Combination of parameters (orderBy is missing)
            ({"limit": 1}),  # Case where limit is 1
            ({"limit": 2}),  # Case where limit is 2
            ({"limit": 20}),  # Case where limit is 20
            ({"offset": 0}),  # Case where offset is 0
            ({"offset": 1}),  # Case where offset is 1
            ({"offset": 20}),  # Case where offset is 20
            (
                {
                    "category": ["all"],
                    "enabled": "false",
                    "subCategory": "useThreshold",
                    "device": "cpu",
                    "fields": ["policyID", "createdAt", "updatedAt"],
                    "sortBy": "createdAt",
                    "orderBy": "desc",
                    "limit": 1,
                }
            ),  # Combination of parameters with limit
            (
                {
                    "category": ["all"],
                    "enabled": "false",
                    "subCategory": "useThreshold",
                    "device": "cpu",
                    "fields": ["policyID", "createdAt", "updatedAt"],
                    "sortBy": "createdAt",
                    "orderBy": "desc",
                    "offset": 0,
                }
            ),  # Combination of parameters with offset
            (
                {
                    "category": ["all"],
                    "enabled": "false",
                    "subCategory": "useThreshold",
                    "device": "cpu",
                    "fields": ["policyID", "createdAt", "updatedAt"],
                    "sortBy": "createdAt",
                    "orderBy": "desc",
                    "limit": 1,
                    "offset": 0,
                }
            ),  # Combination of parameters with limit and offset
            (
                {
                    "category": ["all"],
                    "enabled": "false",
                    "subCategory": "useThreshold",
                    "device": "cpu",
                    "fields": ["policyID", "createdAt", "updatedAt"],
                    "sortBy": "createdAt",
                    "orderBy": "desc",
                    "limit": 20,
                    "offset": 20,
                }
            ),  # Combination of parameters with maximum limit and offset
            ({}),  # Case where no parameters are specified
        ],
    )
    def test_api_get_200(self, mocker, params, init_db_instance):  # pylint: disable=C2401,W0613,W0621
        """Success test"""
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query="Delete from policies")
        init_db_instance.commit()
        response = client.get(BASEURL + "policies", params=params)
        content = json.loads(response.content.decode())
        assert response.status_code == 200
        assert "count" in content.keys()
        assert "policies" in content.keys()
        assert "totalCount" in content.keys()
        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "params",
        [
            (
                {"category": ["nodeConfigurationPolicy"], "enabled": "all"}
            ),  # Case where category is nodeConfigurationPolicy
            (
                {"category": ["nodeConfigurationPolicy"], "enabled": "true"}
            ),  # Case where category is nodeConfigurationPolicy
            (
                {"category": ["nodeConfigurationPolicy"], "enabled": "false"}
            ),  # Case where category is nodeConfigurationPolicy
            ({"category": ["systemOperationPolicy"], "enabled": "all"}),  # Case where category is systemOperationPolicy
            (
                {"category": ["systemOperationPolicy"], "enabled": "true"}
            ),  # Case where category is systemOperationPolicy
            (
                {"category": ["systemOperationPolicy"], "enabled": "false"}
            ),  # Case where category is systemOperationPolicy
            (
                {"category": ["systemOperationPolicy"]}
            ),  # Case where category is systemOperationPolicy and enabled is not specified
            (
                {
                    "category": [
                        "nodeConfigurationPolicy",
                        "systemOperationPolicy",
                    ]
                }
            ),  # Case where multiple categories are specified
        ],
    )
    def test_api_get_200_when_params_specified_not_all(
        self, init_db_instance, mocker, params
    ):  # pylint: disable=C2401,W0613,W0621
        """Success test"""
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)
        response = client.get(BASEURL + "policies", params=params)
        content = json.loads(response.content.decode())
        assert response.status_code == 200
        assert "count" in content.keys()
        assert "policies" in content.keys()
        assert "totalCount" in content.keys()

    @pytest.mark.parametrize(
        "params",
        [
            ({"subCategory": "hardwareConnectionsLimit"}),  # Case where subCategory is hardwareConnectionsLimit
            ({"subCategory": "useThreshold"}),  # Case where subCategory is useThreshold
        ],
    )
    def test_api_get_200_when_params_specified_subcategory(
        self, init_db_instance, mocker, params
    ):  # pylint: disable=C2401,W0613,W0621
        """Success test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        cursor.execute(query="Delete from policies")
        query = ""
        if params["subCategory"] == "hardwareConnectionsLimit":
            query = """INSERT into policies (policyID, category,title, policy,enabled,createdAt,updatedAt)
                                VALUES ('123456789a', 'nodeConfigurationPolicy','test','{"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}}',False,'2023/09/21' ,'2023/09/21')
                    """
        else:
            query = """INSERT into policies (policyID, category,title, policy,enabled,createdAt,updatedAt)
                                VALUES ('123456789b', 'systemOperationPolicy','test2','{"useThreshold": {"fpga": {"value": 80, "unit": "percent", "comparision": "gt"}}}',False,'2023/09/21' ,'2023/09/21')
                    """
        cursor.execute(query)
        init_db_instance.commit()
        response = client.get(BASEURL + "policies", params=params)
        content = json.loads(response.content.decode())
        assert response.status_code == 200
        assert "count" in content.keys()
        assert "policies" in content.keys()
        assert "totalCount" in content.keys()
        policies = content.get("policies")[0]
        policy = next(iter(policies.get("policy")))
        assert params["subCategory"] in policy

    @pytest.mark.parametrize(
        "params",
        [
            ({"device": "cpu"}),  # Case where device is cpu
            ({"device": "memory"}),  # Case where device is memory
            ({"device": "storage"}),  # Case where device is storage
            ({"device": "gpu"}),  # Case where device is gpu
            ({"device": "fpga"}),  # Case where device is fpga
            ({"device": "accelerator"}),  # Case where device is accelerator
            ({"device": "dsp"}),  # Case where device is dsp
            ({"device": "virtualMedia"}),  # Case where device is virtualMedia
            ({"device": "graphicController"}),  # Case where device is graphicController
            ({"device": "networkInterface"}),  # Case where device is networkInterface
            (
                {"subCategory": "hardwareConnectionsLimit", "device": "cpu"}
            ),  # Pattern where subCategory and device are both specified
            ({"device": "CPU"}),  # Case where device is uppercase
            ({"device": "Memory"}),  # Case where device is Memory (uppercase first letter)
            ({"device": "Storage"}),  # Case where device is Storage (uppercase first letter)
            ({"device": "Gpu"}),  # Case where device is Gpu (uppercase first letter)
            ({"device": "FpGA"}),  # Case where device is FpGA (mixed case)
            ({"device": "Accelerator"}),  # Case where device is Accelerator (uppercase first letter)
            ({"device": "DSP"}),  # Case where device is DSP (uppercase)
            ({"device": "VirtualMedia"}),  # Case where device is VirtualMedia (uppercase first letter)
            ({"device": "GraphicController"}),  # Case where device is GraphicController (uppercase first letter)
            ({"device": "NetworkInterface"}),  # Case where device is NetworkInterface (uppercase first letter)
        ],
    )
    def test_api_get_200_when_params_specified_device(
        self, init_db_instance, mocker, params
    ):  # pylint: disable=C2401,W0613,W0621
        """Success test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        cursor.execute(query="Delete from policies")
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

        policy = json.dumps(
            {
                "hardwareConnectionsLimit": {
                    normalizer_device_dict[params["device"].upper()]: {
                        "maxNum": 5,
                        "minNum": 1,
                    }
                }
            }
        )

        query = """INSERT into policies (policyID, category,title, policy,enabled,createdAt,updatedAt)
                    VALUES ('123456789a', 'nodeConfigurationPolicy','test',%s,False,'2023/09/21' ,'2023/09/21')
                """
        cursor.execute(query, vars=[policy])
        init_db_instance.commit()
        response = client.get(BASEURL + "policies", params=params)
        content = json.loads(response.content.decode())
        assert response.status_code == 200
        assert "count" in content.keys()
        assert "policies" in content.keys()
        assert "totalCount" in content.keys()
        assert 1 == content["totalCount"]
        policies = content.get("policies")[0]
        policy = next(iter(policies.get("policy").values()))
        assert list(policy.keys())[0] in normalizer_device_dict.values()

    @pytest.mark.parametrize(
        "params",
        [
            ({"fields": ["policyID"]}),  # Case where fields is policyID
            ({"fields": ["title"]}),  # Case where fields is title
            ({"fields": ["category"]}),  # Case where fields is category
            ({"fields": ["policy"]}),  # Case where fields is policy
            ({"fields": ["enabled"]}),  # Case where fields is enabled
            ({"fields": ["policyID"]}),  # Case where fields is policyID
            ({"fields": ["createdAt"]}),  # Case where fields is createdAt
            ({"fields": ["updatedAt"]}),  # Case where fields is updatedAt
            ({"fields": ["policyID", "policy"]}),  # Case where multiple fields are specified
            (
                {
                    "subCategory": "hardwareConnectionsLimit",
                    "device": "cpu",
                    "fields": ["policyID", "policy"],
                }
            ),  # Pattern where subCategory, device, and fields are all specified
            (
                {
                    "enabled": True,
                    "subCategory": "hardwareConnectionsLimit",
                    "device": "cpu",
                    "fields": ["policyID", "policy"],
                }
            ),  # Pattern where enabled, subCategory, device, and fields are all specified
            (
                {
                    "category": ["nodeConfigurationPolicy"],
                    "enabled": True,
                    "subCategory": "hardwareConnectionsLimit",
                    "device": "cpu",
                    "fields": ["policyID", "policy"],
                }
            ),  # Pattern where category, enabled, subCategory, device, and fields are all specified
        ],
    )
    def test_api_get_200_when_params_specified_fields(
        self, init_db_instance, mocker, params
    ):  # pylint: disable=C2401,W0613,W0621
        """Success test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        cursor.execute(query="Delete from policies")
        query = """INSERT into policies (policyID, category,title, policy,enabled,createdAt,updatedAt) VALUES 
                            ('123456789a', 'nodeConfigurationPolicy','test','{"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}}',True,'2023/10/21' ,'2023/10/21'),
                            ('123456789b', 'systemOperationPolicy','test2','{"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparision": "gt"}}}',False,'2023/09/21' ,'2023/09/21')
                """
        cursor.execute(query)
        init_db_instance.commit()
        policies_data = [
            {
                "policyID": "123456789a",
                "category": "nodeConfigurationPolicy",
                "title": "test",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-10-21T00:00:00Z",
                "updatedAt": "2023-10-21T00:00:00Z",
            },
            {
                "policyID": "123456789b",
                "category": "systemOperationPolicy",
                "title": "test2",
                "policy": {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparision": "gt"}}},
                "enabled": False,
                "createdAt": "2023-09-21T00:00:00Z",
                "updatedAt": "2023-09-21T00:00:00Z",
            },
        ]

        response = client.get(BASEURL + "policies", params=params)
        content = json.loads(response.content.decode())
        assert response.status_code == 200
        assert "count" in content.keys()
        assert "policies" in content.keys()
        assert "totalCount" in content.keys()
        policies = content.get("policies")[0]

        if (
            (params.get("subCategory") == "useThreshold")
            and (params.get("category") == "systemOperationPolicy")
            or params.get("category") == "systemOperationPolicy"
            or params.get("subCategory") == "useThreshold"
        ):
            assartion_data = policies_data[1]  # systemOperationPolicy data
        else:
            assartion_data = policies_data[0]  # nodeConfigPolicy data
        for field in params["fields"]:
            assert field in policies.keys()
            assert policies[field] == assartion_data[field]

        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "params",
        [
            ({"sortBy": "createdAt"}),  # Case where only sortBy is specified
            ({"sortBy": "updatedAt"}),  # Case where only sortBy is specified
            ({"sortBy": "createdAt", "orderBy": "asc"}),  # Combination of sortBy and orderBy (ascending)
            ({"sortBy": "createdAt", "orderBy": "desc"}),  # Combination of sortBy and orderBy (descending)
            ({"sortBy": "updatedAt", "orderBy": "asc"}),  # Combination of sortBy and orderBy (ascending)
            ({"sortBy": "updatedAt", "orderBy": "desc"}),  # Combination of sortBy and orderBy (descending)
            ({"orderBy": "asc"}),  # Case where orderBy is asc
            ({"orderBy": "desc"}),  # Case where orderBy is desc
        ],
    )
    def test_api_get_200_when_params_specified_sortby_and_orderby(
        self, init_db_instance, mocker, params
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

        response = client.get(BASEURL + "policies", params=params)
        content = json.loads(response.content.decode())
        assert response.status_code == 200
        assert "count" in content.keys()
        assert "policies" in content.keys()
        assert "totalCount" in content.keys()
        assert 2 == content["totalCount"]

        if params.get("orderBy") == "asc":
            policies = content.get("policies")[0]
            assert ("policyID", "123456789a") in policies.items()
            assert ("category", "nodeConfigurationPolicy") in policies.items()
            assert ("title", "insert1") in policies.items()
            assert 5 == policies.get("policy").get("hardwareConnectionsLimit").get("gpu").get("maxNum")
            assert 1 == policies.get("policy").get("hardwareConnectionsLimit").get("gpu").get("minNum")
            assert ("enabled", True) in policies.items()
            assert ("createdAt", "2023-09-01T00:00:00Z") in policies.items()
            assert ("updatedAt", "2023-09-01T00:00:00Z") in policies.items()
            policies = content.get("policies")[1]
            assert ("policyID", "123456789b") in policies.items()
            assert ("category", "nodeConfigurationPolicy") in policies.items()
            assert ("title", "insert2") in policies.items()
            assert 5 == policies.get("policy").get("hardwareConnectionsLimit").get("cpu").get("maxNum")
            assert 1 == policies.get("policy").get("hardwareConnectionsLimit").get("cpu").get("minNum")
            assert ("enabled", False) in policies.items()
            assert ("createdAt", "2023-10-01T00:00:00Z") in policies.items()
            assert ("updatedAt", "2023-10-01T00:00:00Z") in policies.items()

        else:
            policies = content.get("policies")[0]
            assert ("policyID", "123456789b") in policies.items()
            assert ("category", "nodeConfigurationPolicy") in policies.items()
            assert ("title", "insert2") in policies.items()
            assert 5 == policies.get("policy").get("hardwareConnectionsLimit").get("cpu").get("maxNum")
            assert 1 == policies.get("policy").get("hardwareConnectionsLimit").get("cpu").get("minNum")
            assert ("enabled", False) in policies.items()
            assert ("createdAt", "2023-10-01T00:00:00Z") in policies.items()
            assert ("updatedAt", "2023-10-01T00:00:00Z") in policies.items()
            policies = content.get("policies")[1]
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

    @pytest.mark.parametrize(
        "params",
        [
            ({"limit": 1}),
            ({"limit": 2}),
            ({"limit": 3}),
            ({"limit": 4}),
            ({"limit": 5}),
            ({"limit": 6}),
            ({"limit": 7}),
            ({"limit": 8}),
            ({"limit": 9}),
            ({"limit": 10}),
            ({"limit": 11}),
            ({"limit": 12}),
            ({"limit": 13}),
            ({"limit": 14}),
            ({"limit": 15}),
            ({"limit": 16}),
            ({"limit": 17}),
            ({"limit": 18}),
            ({"limit": 19}),
            ({"limit": 20}),
            ({"limit": 100}),
        ],
    )
    def test_api_get_200_when_params_specified_limit(
        self, mocker, params, init_db_instance, tmp_all_policy_json_file
    ):  # pylint: disable=C2401,W0613,W0621
        """Success test"""
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)
        cursor = init_db_instance.cursor()
        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

        with open(tmp_all_policy_json_file, "r", encoding="utf-8") as file:
            json_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": "json"},
                files={
                    "input": (
                        "input.json",
                        json_data,
                    )
                },
            )

        response = client.get(BASEURL + "policies", params=params)
        content = json.loads(response.content.decode())
        assert response.status_code == 200
        assert "count" in content.keys()
        assert "policies" in content.keys()
        assert "totalCount" in content.keys()
        assert 20 == content["totalCount"]
        if params["limit"] >= 20:
            assert 20 == content.get("count")
        else:
            assert params["limit"] == content.get("count")
        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "params",
        [
            ({"offset": 0}),
            ({"offset": 1}),
            ({"offset": 2}),
            ({"offset": 3}),
            ({"offset": 4}),
            ({"offset": 5}),
            ({"offset": 6}),
            ({"offset": 7}),
            ({"offset": 8}),
            ({"offset": 9}),
            ({"offset": 10}),
            ({"offset": 11}),
            ({"offset": 12}),
            ({"offset": 13}),
            ({"offset": 14}),
            ({"offset": 15}),
            ({"offset": 16}),
            ({"offset": 17}),
            ({"offset": 18}),
            ({"offset": 19}),
            ({"offset": 20}),
            ({"offset": 100}),
        ],
    )
    def test_api_get_200_when_params_specified_offset(
        self, mocker, params, init_db_instance, tmp_all_policy_json_file
    ):  # pylint: disable=C2401,W0613,W0621
        """Success test"""
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)
        cursor = init_db_instance.cursor()
        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

        with open(tmp_all_policy_json_file, "r", encoding="utf-8") as file:
            json_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": "json"},
                files={
                    "input": (
                        "input.json",
                        json_data,
                    )
                },
            )

        response = client.get(BASEURL + "policies", params=params)
        content = json.loads(response.content.decode())
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF
        assert response.status_code == 200
        assert "count" in content.keys()
        assert "policies" in content.keys()
        assert "totalCount" in content.keys()
        assert 20 == content["totalCount"]
        if params["offset"] >= 20:
            assert 0 == content.get("count")
        else:
            assert params["offset"] == (20 - content.get("count"))
        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "params",
        [
            (
                {"category": ["systemOperation"], "enabled": "all"}
            ),  # Case where an unexpected string is specified for category
            ({"category": ["all"], "enabled": "error"}),  # Case where an unexpected string is specified for enabled
            ({"category": 1}),  # Case where the type specified for category is incorrect
            ({"enabled": 1}),  # Case where the type specified for enabled is incorrect
            ({"category": ""}),  # Case where category is empty
            ({"enabled": ""}),  # Case where enabled is empty
            (
                {"category": ["all", "systemOperationPolicy"], "enabled": "all"}
            ),  # Case where both all and another constraint type are specified in category
            (
                {
                    "category": [
                        "systemOperationPolicy",
                        "systemOperationPolicy",
                    ],
                    "enabled": "all",
                }
            ),  # Case where category is specified multiple times
            (
                {
                    "category": [
                        "all",
                        "nodeConfigurationPolicy",
                        "systemOperationPolicy",
                    ],
                    "enabled": "all",
                }
            ),  # Case where all constraint types are specified
            (
                {
                    "category": ["all", "all"],
                    "enabled": "all",
                }
            ),  # Case where all is specified multiple times
            (
                {
                    "subCategory": "hardware",
                }
            ),  # Case where subCategory is invalid
            (
                {
                    "device": "otherProcessor",
                }
            ),  # Case where device is invalid
            (
                {
                    "fields": ["policyIDD"],
                }
            ),  # Case where fields is invalid
            (
                {
                    "fields": ["policyID", "policyID"],
                }
            ),  # Case where fields are duplicated
            (
                {
                    "fields": [""],
                }
            ),  # Case where fields is an empty string
            ({"sortBy": "policy"}),  # Case where sortBy has an unexpected value
            ({"sortBy": ""}),  # Case where sortBy is an empty string
            ({"sortBy": "createdAt", "orderBy": "sort"}),  # Case where orderBy has an unexpected value
            ({"sortBy": "createdAt", "orderBy": ""}),  # Case where orderBy is an empty string
            ({"orderBy": "sort"}),  # Case where sortBy is missing, and orderBy has an unexpected value
            ({"orderBy": ""}),  # Case where sortBy is missing, and orderBy is an empty string
            ({"limit": 0}),  # Case where limit is 0
            ({"limit": "createdAt"}),  # Case where limit is a string
            ({"offset": -1}),  # Case where offset is less than 0
            ({"offset": "createdAt"}),  # Case where offset is a string
        ],
    )
    def test_api_get_400_with_message_when_invalid_parameters(
        self, init_db_instance, mocker, params
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        response = client.get(BASEURL + "policies", params=params)

        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("code", "E10001") in content.items()
        assert len(content.get("message")) >= 1
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_get_500_with_message_when_db_connection_failed(
        self, mock_db_connection_operationalerror
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        response = client.get(BASEURL + "policies", params={"category": ["all"], "enabled": "all"})

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10003") in content.items()
        assert ("message", "Could not connect to PolicyDB: ") in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_get_500_with_message_when_invalid_query(
        self, mock_db_connection_programmingerror, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        response = client.get(BASEURL + "policies", params={"category": ["all"], "enabled": "all"})

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10004") in content.items()
        assert (
            "message",
            "Query failed:42601 Check PostgreSQL's error code table [https://pgsql-jp.github.io/current/html/errcodes-appendix.html]",
        ) in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_get_500_with_message_when_invalid_config_value(
        self, mock_db_connection_settingFilevalidationError, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("logging.config.dictConfig")
        response = client.get(BASEURL + "policies", params={"category": ["all"], "enabled": "all"})
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_config.yaml Dummy message",
        ) in content.items()
        assert "[E10002]Failed to load policymanager_config.yaml" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_get_500_with_message_when_config_load_failed(
        self, mocker, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("yaml.safe_load").side_effect = FileNotFoundError("File not found")
        response = client.get(BASEURL + "policies", params={"category": ["all"], "enabled": "all"})
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_log_config.yaml ('File not found',)",
        ) in content.items()
        # logging is not initialized yet, error logs cannot be checked
        # assert "[E10002]Failed to load policymanager_config.yaml" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_get_all_500_with_message_when_init_log(self, mocker):
        mocker.patch.object(Logger, "__init__", side_effect=LogInitializationError)

        response = client.get(BASEURL + "policies", params={"category": ["all"], "enabled": "all"})
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10012") in content.items()
        assert (
            "message",
            "Internal server error. Failed in log initialization",
        ) in content.items()

    def test_api_get_all_500_with_message_when_invalid_config_value(
        self, mock_db_connection_settingFilevalidationError, caplog, mocker, init_db_instance
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("logging.config.dictConfig")
        mocker.patch(
            "psycopg2.connect",
            side_effect=[SettingFileValidationError("Dummy message")],
        )

        response = client.get(BASEURL + "policies", params={"category": ["all"], "enabled": "all"})
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_config.yaml Dummy message",
        ) in content.items()
        assert "[E10002]Failed to load policymanager_config.yaml" in caplog.text

    def test_api_get_all_500_with_message_when_invalid_config_value_without_logger(
        self, mocker, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        mocker.patch("policymanager.restapi.initialize_log", side_effect=SettingFileValidationError("Dummy message"))

        response = client.get(BASEURL + "policies", params={"category": ["all"], "enabled": "all"})
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_config.yaml Dummy message",
        ) in content.items()
        assert "[E10002]Failed to load policymanager_config.yaml" not in caplog.text

    def test_api_get_all_500_with_message_when_config_load_failed(
        self, mocker, caplog, init_db_instance
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        settings_side_effect = {
            "version": 1,
            "formatters": {
                "standard": {"format": "%(asctime)s %(levelname)s %(message)s", "datefmt": "%Y/%m/%d %H:%M:%S.%f"}
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
            "root": {"level": "INFO", "handlers": ["file"]},
        }
        mocker.patch("policymanager.common.config_reader.PolicyConfigReader", autospec=True)
        mocker.patch("yaml.safe_load").side_effect = [FileNotFoundError("File not found")]

        response = client.get(BASEURL + "policies", params={"category": ["all"], "enabled": "all"})
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_log_config.yaml ('File not found',)",
        ) in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF


class TestGet:
    @pytest.mark.parametrize(
        "insert_param",
        [
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"virtualMedia": {"maxNum": 1, "minNum": 1}}},
                    "enabled": True,
                }
            ),
        ],
    )
    def test_api_get_success(self, mocker, init_db_instance, insert_param):  # pylint: disable=C2401,W0613,W0621
        """Success test"""
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        insert_response = client.post(BASEURL + "policies", json=insert_param)
        content = json.loads(insert_response.content.decode())
        inserted_id = content.get("policyID")

        response = client.get(BASEURL + "policies/" + inserted_id)
        content = json.loads(response.content.decode())
        assert response.status_code == 200
        assert ("policyID", inserted_id) in content.items()
        assert ("category", "nodeConfigurationPolicy") in content.items()
        assert ("title", "hardwareConnectionsLimit") in content.items()
        assert 1 == content.get("policy").get("hardwareConnectionsLimit").get("virtualMedia").get("maxNum")
        assert 1 == content.get("policy").get("hardwareConnectionsLimit").get("virtualMedia").get("minNum")
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF
        response = client.delete(BASEURL + "policies/" + inserted_id, params={"force": True})

    def test_api_get_200_when_id_specified(self, mocker, init_db_instance):  # pylint: disable=C2401,W0613,W0621
        """Success test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        cursor.execute(query="Delete from policies")
        init_db_instance.commit()
        policy = json.dumps(
            {
                "hardwareConnectionsLimit": {
                    "cpu": {
                        "maxNum": 5,
                        "minNum": 1,
                    }
                }
            }
        )

        query = """INSERT into policies (policyID, category,title, policy,enabled,createdAt,updatedAt)
                    VALUES ('a21bc21587', 'nodeConfigurationPolicy','test',%s,True,'2023/09/21' ,'2023/09/21')
                """
        cursor.execute(query, vars=[policy])
        init_db_instance.commit()

        response = client.get(BASEURL + "policies/a21bc21587")

        content = json.loads(response.content.decode())
        assert response.status_code == 200
        assert ("policyID", "a21bc21587") in content.items()
        assert ("category", "nodeConfigurationPolicy") in content.items()
        assert ("title", "test") in content.items()
        assert 5 == content.get("policy").get("hardwareConnectionsLimit").get("cpu").get("maxNum")
        assert 1 == content.get("policy").get("hardwareConnectionsLimit").get("cpu").get("minNum")
        assert ("enabled", True) in content.items()
        assert ("createdAt", "2023-09-21T00:00:00Z") in content.items()
        assert ("updatedAt", "2023-09-21T00:00:00Z") in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "id",
        [
            ("a21bc21587a"),  # Case where the ID exceeds the specified length
            ("a21bc2158"),  # Case where the ID is shorter than the specified length
            ("z21bc21587"),  # Case where the ID contains non-hexadecimal characters
        ],
    )
    def test_api_get_400_with_message_when_invalid_parameters(
        self, mock_db_connection, id, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        response = client.get(BASEURL + "policies/" + id)

        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("code", "E10001") in content.items()
        assert len(content.get("message")) >= 1
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_get_500_with_message_when_db_connection_failed(
        self, mock_db_connection_operationalerror
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        response = client.get(BASEURL + "policies/a21bc21587")

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10003") in content.items()
        assert ("message", "Could not connect to PolicyDB: ") in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_get_500_with_message_when_invalid_query(
        self, mock_db_connection_programmingerror, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        response = client.get(BASEURL + "policies/a21bc21587")

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10004") in content.items()
        assert (
            "message",
            "Query failed:42601 Check PostgreSQL's error code table [https://pgsql-jp.github.io/current/html/errcodes-appendix.html]",
        ) in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_get_404_with_message_when_nonexistent_id(
        self, mock_db_connection_idnotfoundexception, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("logging.config.dictConfig")
        response = client.get(BASEURL + "policies/a21bc21587")
        content = json.loads(response.content.decode())
        assert response.status_code == 404
        assert ("code", "E10005") in content.items()
        assert ("message", "Specified a21bc21587 is not found") in content.items()
        assert "[E10005]Specified a21bc21587 is not found" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_get_500_with_message_when_invalid_config_value(
        self, mock_db_connection_settingFilevalidationError, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("logging.config.dictConfig")
        response = client.get(BASEURL + "policies/a21bc21587")
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_config.yaml Dummy message",
        ) in content.items()
        assert "[E10002]Failed to load policymanager_config.yaml" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_get_500_with_message_when_invalid_config_value_without_logger(
        self, mock_db_connection_settingFilevalidationError, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("policymanager.restapi.initialize_log", side_effect=SettingFileValidationError("Dummy message"))
        response = client.get(BASEURL + "policies/a21bc21587")
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_config.yaml Dummy message",
        ) in content.items()
        assert "[E10002]Failed to load policymanager_config.yaml" not in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_get_500_with_message_when_config_load_failed(
        self, mocker, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("yaml.safe_load").side_effect = FileNotFoundError("File not found")
        response = client.get(BASEURL + "policies/a21bc21587")
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_log_config.yaml ('File not found',)",
        ) in content.items()
        # logging is not initialized yet, error logs cannot be checked
        # assert "[E10002]Failed to load policymanager_config.yaml" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_get_500_with_message_when_init_log(self, mocker):
        mocker.patch.object(Logger, "__init__", side_effect=LogInitializationError)

        response = client.get(BASEURL + "policies/a21bc21587")
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10012") in content.items()
        assert (
            "message",
            "Internal server error. Failed in log initialization",
        ) in content.items()


class TestUpdate:
    @pytest.mark.parametrize(
        "insert_param,update_param,param,sleep",
        [
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"virtualMedia": {"maxNum": 1, "minNum": 1}}},
                    "enabled": True,
                },
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"graphicController": {"maxNum": 10, "minNum": 3}}},
                },  # case when all params exists
                {"force": True},
                0.1,
            ),
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"virtualMedia": {"maxNum": 1, "minNum": 1}}},
                    "enabled": False,
                },
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "accelerator": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                },
                {"force": False},
                0.2,
            ),
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"virtualMedia": {"maxNum": 1, "minNum": 1}}},
                },
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"accelerator": {"maxNum": 1, "minNum": 1}}},
                },
                {},
                0.1,
            ),
        ],
    )
    def test_api_update_success(
        self, init_db_instance, mocker, insert_param, update_param, param, sleep
    ):  # pylint: disable=C2401,W0613,W0621
        """Success test"""
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        time.sleep(sleep)
        insert_response = client.post(BASEURL + "policies", json=insert_param)
        content = json.loads(insert_response.content.decode())
        inserted_id = content.get("policyID")

        response = client.put(BASEURL + "policies/" + inserted_id, json=update_param, params=param)
        assert response.status_code == 204

        response = client.delete(BASEURL + "policies/" + inserted_id, params=param)

    @pytest.mark.parametrize(
        "insert_param,update_param,param,sleep",
        [
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"virtualMedia": {"maxNum": 1, "minNum": 1}}},
                    "enabled": True,
                },
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"graphicController": {"maxNum": 10, "minNum": 3}}},
                },  # case when all params exists
                {"force": False},
                0.1,
            ),
        ],
    )
    def test_api_update_400_with_message_when_constraint_enabled_force_false(
        self, init_db_instance, mocker, insert_param, update_param, param, sleep, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        """Success test"""
        mocker.patch("logging.config.dictConfig")
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        time.sleep(sleep)
        insert_response = client.post(BASEURL + "policies", json=insert_param)
        content = json.loads(insert_response.content.decode())
        inserted_id = content.get("policyID")

        response = client.put(BASEURL + "policies/" + inserted_id, json=update_param, params=param)
        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("code", "E10007") in content.items()
        assert (
            "message",
            "Specified " + inserted_id + " is not in disabled state",
        ) in content.items()
        assert "[E10007]Specified " + inserted_id + " is not in disabled state" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

        response = client.delete(
            BASEURL + "policies/" + inserted_id,
            params={"force": True},
        )

    @pytest.mark.parametrize(
        "id,param",
        [
            (
                "a21bc21587",
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },  # Case where all parameters exist
            ),
            (
                "a21bc21587",
                {
                    "category": "nodeConfigurationPolicy",
                },  # Case where only the category parameter exists
            ),
            (
                "a21bc21587",
                {"title": "hardwareConnectionsLimit"},  # Case where only the title parameter exists
            ),
            (
                "a21bc21587",
                {
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },  # Case where only the policy parameter exists
            ),
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparison": "gt"}}},
                },
            ),  # System operation constraint with comparison = gt
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparison": "lt"}}},
                },
            ),  # System operation constraint with comparison = lt
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 0, "unit": "percent", "comparison": "ge"}}},
                },
            ),  # System operation constraint with comparison = ge
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 100, "unit": "percent", "comparison": "le"}}},
                },
            ),  # System operation constraint with comparison = le
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "policy": {"useThreshold": {"cpu": {"value": 100, "unit": "percent", "comparison": "le"}}},
                },
            ),  # System operation constraint with only category and policy
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "memory": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                },
            ),  # System operation constraint where device = memory
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "storage": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                },
            ),  # System operation constraint where device = storage
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"gpu": {"value": 100, "unit": "percent", "comparison": "le"}}},
                },
            ),  # System operation constraint where device = gpu
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "fpga": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                },
            ),  # System operation constraint where device = fpga
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "accelerator": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                },
            ),  # System operation constraint where device = accelerator
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"dsp": {"value": 100, "unit": "percent", "comparison": "le"}}},
                },
            ),  # System operation constraint where device = dsp
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "virtualMedia": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                },
            ),  # System operation constraint where device = virtualMedia
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "graphicController": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                },
            ),  # System operation constraint where device = graphicController
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "networkInterface": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                },
            ),  # System operation constraint where device = networkInterface
        ],
    )
    def test_api_update_204_when_category_node_constraint(
        self, init_db_instance, id, param, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Success test"""
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        cursor.execute(query="Delete from policies")

        policy = json.dumps(
            {
                "hardwareConnectionsLimit": {
                    "cpu": {
                        "maxNum": 5,
                        "minNum": 1,
                    }
                }
            }
        )

        query = """INSERT into policies (policyID, category,title, policy,enabled,createdAt,updatedAt)
                    VALUES ('a21bc21587', 'nodeConfigurationPolicy','test',%s,False,'2023/09/21' ,'2023/09/21')
                """
        cursor.execute(query, vars=[policy])
        init_db_instance.commit()
        response = client.put(BASEURL + "policies/" + id, json=param)
        cursor.execute("Select * from policies where policyid = %s", vars=["a21bc21587"])
        updated_policy = cursor.fetchone()

        assert response.status_code == 204

        assert updated_policy[0] == id
        if param.get("category"):
            assert updated_policy[1] == param["category"]
        if param.get("title"):
            assert updated_policy[2] == param["title"]
        if param.get("policy"):
            assert updated_policy[3] == param["policy"]

        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "id,param",
        [
            (
                "a21bc21587",
                {"category": "systemOperationPolicy"},
            ),  # System operation constraint with only category
            (
                "a21bc21587",
                {
                    "policy": {"useThreshold": {"cpu": {"value": 100, "unit": "percent", "comparison": "le"}}},
                },
            ),  # System operation constraint with only policy
        ],
    )
    def test_api_update_204_when_category_system_constraint(
        self, id, param, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Success test"""

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
            "policymanager.restapi.db_connection",
            mocker.MagicMock(return_value=FakeDB),
        )

        response = client.put(BASEURL + "policies/" + id, json=param)
        assert response.status_code == 204

    @pytest.mark.parametrize(
        "id, param",
        [
            (
                "a21bc21587a",
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where the ID has more characters than expected
            (
                "a21bc2158",
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where the ID has fewer characters than expected
            (
                "z21bc21587",
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where non-hexadecimal characters are included in the ID
            (
                "a21bc2158",
                {
                    "category": [1],
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where the category type is not a string
            (
                "a21bc21587",
                {
                    "category": "nodeConfigurationPolicy",
                    "title": [1],
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where the title type is not a string
            (
                "a21bc21587",
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": [1],
                },
            ),  # Case where the policy type is not a dictionary
            (
                "a21bc21587",
                {},
            ),  # Case where no parameters except ID are provided
            (
                "a21bc21587",
                {
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 1, "minNum": 5}}},
                },
            ),  # Case where minNum is greater than maxNum
            (
                "a21bc21587",
                {"title": "a" * 101},
            ),  # Case where the title has more than 100 characters
            (
                "a21bc21587",
                {
                    "categoryy": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where the category key has an extra "y"
            (
                "a21bc21587",
                {
                    "ccategory": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where the category key has an extra "c" at the beginning
            (
                "a21bc21587",
                {
                    "category": "nodeConfigurationPolicy",
                    "titlee": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where the title key has an extra "e"
            (
                "a21bc21587",
                {
                    "category": "nodeConfigurationPolicy",
                    "ttitle": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where the title key has an extra "t" at the beginning
            (
                "a21bc21587",
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policyy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where the policy key has an extra "y"
            (
                "a21bc21587",
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "ppolicy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where the policy key has an extra "p"
            (
                "a21bc21587",
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"ssss": {"cpu": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where the policy key name is incorrect
            (
                "a21bc21587",
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"otherProcessor": {"maxNum": 5, "minNum": 1}}},
                },
            ),  # Case where the policy device type is incorrect
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 100, "unit": "percent", "comparison": "gt"}}},
                },
            ),  # Case where value and comparison are out of the valid range (value = 100, comparison = gt)
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 0, "unit": "percent", "comparison": "lt"}}},
                },
            ),  # Case where value and comparison are out of the valid range (value = 0, comparison = lt)
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": 101, "unit": "percent", "comparison": "lt"}}},
                },
            ),  # Case where value exceeds the upper limit
            (
                "a21bc21587",
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {"useThreshold": {"cpu": {"value": -1, "unit": "percent", "comparison": "lt"}}},
                },
            ),  # Case where value is below the lower limit
        ],
    )
    def test_api_update_400_with_message_when_invalid_parameters(
        self, mock_db_connection, id, param, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
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

        response = client.put(BASEURL + "policies/" + id, json=param)
        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("code", "E10001") in content.items()
        assert len(content.get("message")) >= 1
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

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
            (psycopg2.OperationalError),
        ],
    )
    def test_api_update_500_with_message_when_db_connection_failed(
        self, mocker, error, docker_services
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("psycopg2.connect").side_effect = error
        mocker.patch("time.sleep", return_value=None)

        response = client.put(
            BASEURL + "policies/a21bc21587",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10003") in content.items()
        assert ("message", "Could not connect to PolicyDB: ") in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    @pytest.mark.parametrize(
        ("error", "err_code"),
        [
            (psycopg2.ProgrammingError, "20000"),
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
    def test_api_update_500_with_message_when_invalid_query(
        self, error, err_code, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        occur_err = error
        occur_err.pgcode = err_code
        mock_cursor = mocker.MagicMock()
        mock_cursor.execute.side_effect = [occur_err]

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)
        response = client.put(
            BASEURL + "policies/a21bc21587",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10004") in content.items()
        assert (
            "message",
            f"Query failed:{err_code} Check PostgreSQL's error code table [https://pgsql-jp.github.io/current/html/errcodes-appendix.html]",
        ) in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_update_404_with_message_when_nonexistent_id(
        self, mock_db_connection_idnotfoundexception, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("logging.config.dictConfig")
        mock_cursor = mocker.MagicMock()
        mock_cursor.rowcount = 0
        mock_cursor.fetchone.side_effect = [None]

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)
        response = client.put(
            BASEURL + "policies/a21bc21587",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 404
        assert ("code", "E10005") in content.items()
        assert ("message", "Specified a21bc21587 is not found") in content.items()
        assert "[E10005]Specified a21bc21587 is not found" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_update_400_with_message_when_constraint_not_disabled(
        self, mock_db_connection_invalidoperationexception, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("logging.config.dictConfig")
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

        response = client.put(
            BASEURL + "policies/a21bc21587",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("code", "E10007") in content.items()
        assert (
            "message",
            "Specified a21bc21587 is not in disabled state",
        ) in content.items()
        assert "[E10007]Specified a21bc21587 is not in disabled state" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_update_500_with_message_when_invalid_config_value(
        self, mock_db_connection_settingFilevalidationError, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("logging.config.dictConfig")
        mocker.patch(
            "psycopg2.connect",
            side_effect=[SettingFileValidationError("Dummy message")],
        )

        response = client.put(
            BASEURL + "policies/a21bc21587",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_config.yaml Dummy message",
        ) in content.items()
        assert "[E10002]Failed to load policymanager_config.yaml" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_update_500_with_message_when_invalid_config_value_without_logger(
        self, mock_db_connection_settingFilevalidationError, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("policymanager.restapi.initialize_log", side_effect=SettingFileValidationError("Dummy message"))

        response = client.put(
            BASEURL + "policies/a21bc21587",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_config.yaml Dummy message",
        ) in content.items()
        assert "[E10002]Failed to load policymanager_config.yaml" not in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_update_500_with_message_when_config_load_failed(
        self, mocker, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("yaml.safe_load").side_effect = [
            FileNotFoundError("File not found"),
        ]
        response = client.put(
            BASEURL + "policies/a21bc21587",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_log_config.yaml ('File not found',)",
        ) in content.items()
        # logging is not initialized yet, error logs cannot be checked
        # assert "[E10002]Failed to load policymanager_config.yaml" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_update_failure_when_policy_duplicate(
        self, mock_db_connection_dublicatedPoliceError, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mock_cursor = mocker.MagicMock()
        mock_cursor.fetchall.return_value = [("123456789a",)]
        mock_cursor.rowcount = 1

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

        response = client.put(
            BASEURL + "policies/a21bc21587",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("code", "E10008") in content.items()
        assert (
            "message",
            "Specified policy is duplicate of",
        ) in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_update_500_with_message_when_init_log(self, mocker):
        mocker.patch.object(Logger, "__init__", side_effect=LogInitializationError)

        response = client.put(
            BASEURL + "policies/a21bc21587",
            json={
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            },
        )

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10012") in content.items()
        assert (
            "message",
            "Internal server error. Failed in log initialization",
        ) in content.items()


class TestDelete:
    @pytest.mark.parametrize(
        "delete_param,insert_param,sleep,",
        [
            (
                {"force": "true"},
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"virtualMedia": {"maxNum": 1, "minNum": 1}}},
                    "enabled": True,
                },
                0.1,
            ),
            (
                {"force": "false"},
                {
                    "category": "systemOperationPolicy",
                    "title": "useThreshold",
                    "policy": {
                        "useThreshold": {
                            "accelerator": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "le",
                            }
                        }
                    },
                },
                0.2,
            ),
            (
                {},
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"accelerator": {"maxNum": 1, "minNum": 1}}},
                },
                0.1,
            ),
        ],
    )
    def test_api_delete_success(
        self, mocker, insert_param, delete_param, sleep, init_db_instance
    ):  # pylint: disable=C2401,W0613,W0621
        """Success test"""
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        time.sleep(sleep)
        insert_response = client.post(BASEURL + "policies", json=insert_param)

        content = json.loads(insert_response.content.decode())
        inserted_id = content.get("policyID")
        response = client.delete(BASEURL + "policies/" + inserted_id, params=delete_param)
        assert response.status_code == 204

    @pytest.mark.parametrize(
        "insert_param,param,sleep",
        [
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "hardwareConnectionsLimit",
                    "policy": {"hardwareConnectionsLimit": {"virtualMedia": {"maxNum": 1, "minNum": 1}}},
                    "enabled": True,
                },
                {"force": False},
                0.1,
            ),
        ],
    )
    def test_api_delete_400_with_message_when_constraint_enabled_force_false(
        self, init_db_instance, mocker, insert_param, param, sleep, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        """Success test"""
        mocker.patch("logging.config.dictConfig")
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        time.sleep(sleep)
        insert_response = client.post(BASEURL + "policies", json=insert_param)
        content = json.loads(insert_response.content.decode())
        inserted_id = content.get("policyID")

        response = client.delete(BASEURL + "policies/" + inserted_id, params=param)
        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("code", "E10007") in content.items()
        assert (
            "message",
            "Specified " + inserted_id + " is not in disabled state",
        ) in content.items()
        assert "[E10007]Specified " + inserted_id + " is not in disabled state" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

        response = client.delete(
            BASEURL + "policies/" + inserted_id,
            params={"force": True},
        )

    @pytest.mark.parametrize(
        "id, param",
        [
            ("a21bc21587", {"force": "true"}),
            ("a21bc21587", {"force": "false"}),
            ("a21bc21587", {}),
        ],
    )
    def test_api_delete_204(self, id, param, init_db_instance, mocker):  # pylint: disable=C2401,W0613,W0621
        """Success test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        cursor.execute(query="Delete from policies")

        policy = json.dumps(
            {
                "hardwareConnectionsLimit": {
                    "cpu": {
                        "maxNum": 5,
                        "minNum": 1,
                    }
                }
            }
        )

        query = """INSERT into policies (policyID, category,title, policy,enabled,createdAt,updatedAt)
                    VALUES ('a21bc21587', 'nodeConfigurationPolicy','test',%s,False,'2023/09/21' ,'2023/09/21')
                """
        cursor.execute(query, vars=[policy])
        init_db_instance.commit()

        response = client.delete(BASEURL + "policies/" + id, params=param)
        assert response.status_code == 204

    @pytest.mark.parametrize(
        "id",
        [
            ("a21bc21587a"),  # Case where the ID has more characters than specified
            ("a21bc2158"),  # Case where the ID has fewer characters than specified
            ("z21bc21587"),  # Case where the ID contains characters other than (0123456789abcdef)
        ],
    )
    def test_api_delete_400_with_message_when_invalid_parameters(
        self, mock_db_connection, id, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        response = client.delete(BASEURL + "policies/" + id)

        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("code", "E10001") in content.items()
        assert len(content.get("message")) >= 1

    def test_api_delete_500_with_message_when_db_connection_failed(
        self, mock_db_connection_operationalerror
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        response = client.delete(BASEURL + "policies/a21bc21587")
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10003") in content.items()
        assert ("message", "Could not connect to PolicyDB: ") in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_delete_500_with_message_when_invalid_query(self, mock_db_connection_programmingerror):
        """Failure Test"""
        response = client.delete(BASEURL + "policies/a21bc21587")

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10004") in content.items()
        assert (
            "message",
            "Query failed:42601 Check PostgreSQL's error code table [https://pgsql-jp.github.io/current/html/errcodes-appendix.html]",
        ) in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_delete_404_with_message_when_nonexistent_id(
        self, mock_db_connection_idnotfoundexception, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("logging.config.dictConfig")
        response = client.delete(BASEURL + "policies/a21bc21587")
        content = json.loads(response.content.decode())
        assert response.status_code == 404
        assert ("code", "E10005") in content.items()
        assert ("message", "Specified a21bc21587 is not found") in content.items()
        assert "[E10005]Specified a21bc21587 is not found" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_delete_400_with_message_when_constraint_not_disabled(
        self, mock_db_connection_invalidoperationexception, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("logging.config.dictConfig")
        response = client.delete(BASEURL + "policies/a21bc21587")
        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("code", "E10007") in content.items()
        assert (
            "message",
            "Specified a21bc21587 is not in disabled state",
        ) in content.items()
        assert "[E10007]Specified a21bc21587 is not in disabled state" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_delete_500_with_message_when_invalid_config_value(
        self, mock_db_connection_settingFilevalidationError, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("logging.config.dictConfig")
        response = client.delete(BASEURL + "policies/a21bc21587")
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_config.yaml Dummy message",
        ) in content.items()
        assert "[E10002]Failed to load policymanager_config.yaml" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_delete_500_with_message_when_invalid_config_value_without_logger(
        self, mock_db_connection_settingFilevalidationError, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("policymanager.restapi.initialize_log", side_effect=SettingFileValidationError("Dummy message"))
        response = client.delete(BASEURL + "policies/a21bc21587")
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_config.yaml Dummy message",
        ) in content.items()
        assert "[E10002]Failed to load policymanager_config.yaml" not in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_delete_500_with_message_when_config_load_failed(
        self, mocker, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("yaml.safe_load").side_effect = FileNotFoundError("File not found")
        response = client.delete(BASEURL + "policies/a21bc21587")
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_log_config.yaml ('File not found',)",
        ) in content.items()
        # logging is not initialized yet, error logs cannot be checked
        # assert "[E10002]Failed to load policymanager_config.yaml" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_delete_500_with_message_when_init_log(self, mocker):
        mocker.patch.object(Logger, "__init__", side_effect=LogInitializationError)

        response = client.delete(BASEURL + "policies/a21bc21587")
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10012") in content.items()
        assert (
            "message",
            "Internal server error. Failed in log initialization",
        ) in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF


class TestExport:

    @pytest.mark.parametrize(
        ("params", "count"),
        [
            (
                {"fileName": "export.json", "format": "json"},
                3,
            ),  # Case where fileName and format are specified
            ({"format": "json"}, 1),  # Case with 1 record output
            ({"fileName": "export.json", "format": "json"}, 0),  # Case with 0 records output
        ],
    )
    def test_api_export_success(self, init_db_instance, mocker, params, count):  # pylint: disable=C2401,W0613,W0621
        """Success test"""
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        match count:
            case 1:
                cursor.execute(query="Delete from policies")
                cursor.execute(
                    query="""
                            INSERT into policies (policyID, category,title, policy,enabled,createdAt,updatedAt)
                            VALUES 
                            ('123456789a','nodeConfigurationPolicy','test','{"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}}',False,'2023/09/21' ,'2023/09/21')
                            """
                )
            case 0:
                cursor.execute(query="Delete from policies")
        init_db_instance.commit()
        response = client.get(BASEURL + "policies/export", params=params)
        content = json.loads(response.content.decode())
        assert response.status_code == 200
        assert "exportedCount" in content.keys()
        assert "policies" in content.keys()
        if count == 1:  # 1 record
            assert content.get("exportedCount") == 1
        if count == 0:  # 0 record
            assert content.get("exportedCount") == 0
            assert content.get("policies") == []
        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "params",
        [
            ({"fileName": "export.json", "format": "json"}),  # Case where fileName and format are specified as JSON
            ({"fileName": "export.yaml", "format": "yaml"}),  # Case where fileName and format are specified as YAML
        ],
    )
    def test_api_export_200(self, init_db_instance, mocker, params):  # pylint: disable=C2401,W0613,W0621
        """Success test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        cursor.execute(query="Delete from policies")
        init_db_instance.commit()
        policy = json.dumps(
            {
                "hardwareConnectionsLimit": {
                    "cpu": {
                        "maxNum": 5,
                        "minNum": 1,
                    }
                }
            }
        )

        query = """INSERT into policies (policyID, category,title, policy,enabled,createdAt,updatedAt)
                    VALUES ('a21bc21587', 'nodeConfigurationPolicy','test',%s,False,'2023/09/21' ,'2023/09/21')
                """
        cursor.execute(query, vars=[policy])
        init_db_instance.commit()
        response = client.get(BASEURL + "policies/export", params=params)
        format_ = params.get("format")

        if format_ == "json":
            content = json.loads(response.content.decode())
            assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        elif format_ == "yaml":
            content = yaml.safe_load(response.content.decode())
            assert response.headers.get("Content-Type") == HEADERS_TYPE_YAML
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF
        assert response.status_code == 200
        assert "exportedCount" in content.keys()
        assert "policies" in content.keys()
        assert content["exportedCount"] == 1
        assert content["policies"][0]["title"] == "test"
        assert content["policies"][0]["category"] == "nodeConfigurationPolicy"
        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "params",
        [
            ({"format": "tsv"}),  # Unexpected string format
            ({"format": "yml"}),  # Unexpected string format
            ({"format": ""}),  # Empty string format
            ({"format": None}),  # None format
            ({"fileName": "", "format": "json"}),  # Case where fileName is an empty string
        ],
    )
    def test_api_export_400_with_message_when_invalid_parameters(
        self,
        init_db_instance,
        mocker,
        params,
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        response = client.get(BASEURL + "policies/export", params=params)

        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("code", "E10001") in content.items()
        assert len(content.get("message")) >= 1
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_export_500_with_message_when_db_connection_failed(
        self, mock_db_connection_operationalerror
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        response = client.get(
            BASEURL + "policies/export",
            params={"fileName": "test.json", "format": "json"},
        )

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10003") in content.items()
        assert ("message", "Could not connect to PolicyDB: ") in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_export_500_with_message_when_invalid_query(
        self,
        mock_db_connection_programmingerror,
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        response = client.get(
            BASEURL + "policies/export",
            params={"fileName": "test.json", "format": "json"},
        )

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10004") in content.items()
        assert (
            "message",
            "Query failed:42601 Check PostgreSQL's error code table [https://pgsql-jp.github.io/current/html/errcodes-appendix.html]",
        ) in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_export_500_with_message_when_invalid_config_value(
        self, mock_db_connection_settingFilevalidationError, caplog, mocker
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("logging.config.dictConfig")
        response = client.get(
            BASEURL + "policies/export",
            params={"fileName": "test.json", "format": "json"},
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_config.yaml Dummy message",
        ) in content.items()
        assert "[E10002]Failed to load policymanager_config.yaml" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_export_500_with_message_when_invalid_config_value_without_logger(
        self, mocker, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        mocker.patch("policymanager.restapi.initialize_log", side_effect=SettingFileValidationError("Dummy message"))

        response = client.get(
            BASEURL + "policies/export",
            params={"fileName": "test.json", "format": "json"},
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_config.yaml Dummy message",
        ) in content.items()
        assert "[E10002]Failed to load policymanager_config.yaml" not in caplog.text

    def test_api_export_500_with_message_when_config_load_failed(
        self,
        mocker,
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""
        mocker.patch("yaml.safe_load").side_effect = FileNotFoundError("File not found")
        response = client.get(BASEURL + "policies/export", params={"format": "json"})
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_log_config.yaml ('File not found',)",
        ) in content.items()
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_export_500_with_message_when_file_output_failed(
        self, mock_db_connection, mocker, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("logging.config.dictConfig")
        mocker.patch.object(tempfile, "NamedTemporaryFile", side_effect=Exception("testError"))
        response = client.get(BASEURL + "policies/export", params={"format": "json"})

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10009") in content.items()
        assert ("message", "Failed to export file: testError") in content.items()
        assert "[E10009]Failed to export file" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_export_500_with_message_when_yaml_output_failed(
        self, mock_db_connection, mocker, caplog
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("logging.config.dictConfig")
        mocker.patch.object(tempfile, "NamedTemporaryFile", side_effect=Exception("testError"))
        response = client.get(BASEURL + "policies/export", params={"format": "yaml"})

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10009") in content.items()
        assert ("message", "Failed to export file: testError") in content.items()
        assert "[E10009]Failed to export file" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_export_500_with_message_when_init_log(self, mocker):
        mocker.patch.object(Logger, "__init__", side_effect=LogInitializationError)

        response = client.get(
            BASEURL + "policies/export",
            params={"fileName": "test.json", "format": "json"},
        )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10012") in content.items()
        assert (
            "message",
            "Internal server error. Failed in log initialization",
        ) in content.items()


class TestImport:
    def test_api_import_success(
        self, init_db_instance, mocker, tmp_import_json_file
    ):  # pylint: disable=C2401,W0613,W0621:
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        with open(tmp_import_json_file, "r") as file:
            json_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": "json"},
                files={
                    "input": (
                        "input.json",
                        json_data,
                    )
                },
            )
        content = json.loads(response.content.decode())
        assert ("summary") in content.keys()
        assert "completed" in content.get("summary").get("status")
        assert 2 == content.get("summary").get("totalCount")
        assert 2 == content.get("summary").get("completedCount")
        assert ("details") in content.keys()
        assert ("policyID", "d8eceb14da") in content.get("details")[0].items()
        assert ("message", "completed") in content.get("details")[0].items()
        assert response.status_code == 201
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

        cursor.execute(query="Delete from policies;")
        init_db_instance.commit()

    def test_api_import_success_when_yaml_import(
        self, init_db_instance, mocker, tmp_import_yaml_file
    ):  # pylint: disable=C2401,W0613,W0621:
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        with open(tmp_import_yaml_file, "r", encoding="utf-8") as file:
            yaml_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": "yaml"},
                files={
                    "input": (
                        "input.yaml",
                        yaml_data,
                    )
                },
            )
            content = json.loads(response.content.decode())
            assert ("summary") in content.keys()
            assert "completed" in content.get("summary").get("status")
            assert 2 == content.get("summary").get("totalCount")
            assert 2 == content.get("summary").get("completedCount")
            assert ("details") in content.keys()
            assert ("policyID", "d8eceb14da") in content.get("details")[0].items()
            assert ("message", "completed") in content.get("details")[0].items()
            assert response.status_code == 201

        cursor.execute(query="Delete from policies;")
        init_db_instance.commit()

    def test_api_import_success_when_id_duplicate(self, init_db_instance, mocker):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query="Delete from policies;")
        init_db_instance.commit()
        insert_query = (
            "INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )
        params = [
            "123456789a",
            "systemOperationPolicy",
            "NodeConfPolicy",
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
                        "title": "NodeConfPolicy",
                        "policy": {"hardwareConnectionsLimit": {"memory": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where the policyID in the DB and the input data are duplicated
                ],
            },
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "123456789a",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfPolicy",
                        "policy": {"hardwareConnectionsLimit": {"memory": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where policyID of element 1 in the input data and the DB is duplicated
                ],
            },
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfPolicy",
                        "policy": {"hardwareConnectionsLimit": {"memory": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                    {
                        "policyID": "123456789a",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where policyID of element 2 in the input data and the DB is duplicated
                ],
            },
        ]

        for json_data in test_data:
            with tempfile.TemporaryDirectory() as dir_path:
                json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
                with open(json_file, mode="w", encoding="utf-8") as fh:
                    json.dump(json_data, fh, indent=4)
                with open(json_file, "r", encoding="utf-8") as file:
                    data = file.read().encode("utf-8")
                response = client.post(
                    BASEURL + "policies/import",
                    params={"format": "json"},
                    files={
                        "input": (
                            "input.json",
                            data,
                        )
                    },
                )
            assert response.status_code == 201

            content = json.loads(response.content.decode())
            assert ("summary") in content.keys()
            assert "completed" in content.get("summary").get("status")
            assert len(json_data["policies"]) == content.get("summary").get("totalCount")
            assert len(json_data["policies"]) == content.get("summary").get("completedCount")
            assert ("details") in content.keys()

            cursor.execute(query="SELECT * from policies where policyID != '123456789a'")
            assert cursor.rowcount == len(json_data["policies"])

            cursor.execute(query="Delete from policies where policyID != '123456789a'")
            init_db_instance.commit()

    def test_api_import_success_when_id_nonexistent(self, init_db_instance, mocker):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query="Delete from policies;")
        init_db_instance.commit()
        test_data = [
            {
                "exportedCount": 1,
                "policies": [
                    {
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where a single constraint data entry is missing the policyID
                ],
            },
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                    {
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfPolicy",
                        "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where multiple constraint data entries are missing policyIDs
                ],
            },
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfPolicy",
                        "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where multiple constraint data entries are present, but the first entry is missing a policyID
                ],
            },
            {
                "exportedCount": 2,
                "policies": [
                    {
                        "policyID": "ffeceb14da",
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfPolicy",
                        "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },
                    {
                        "category": "nodeConfigurationPolicy",
                        "title": "NodeConfPolicy",
                        "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
                        "enabled": True,
                        "createdAt": "2023-05-10T00:00:00Z",
                        "updatedAt": "2023-05-10T00:00:00Z",
                    },  # Case where multiple constraint data entries are present, but the second entry is missing a policyID
                ],
            },
        ]

        for json_data in test_data:
            with tempfile.TemporaryDirectory() as dir_path:
                json_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.json")
                with open(json_file, mode="w", encoding="utf-8") as fh:
                    json.dump(json_data, fh, indent=4)
                with open(json_file, "r", encoding="utf-8") as file:
                    data = file.read().encode("utf-8")
                response = client.post(
                    BASEURL + "policies/import",
                    params={"format": "json"},
                    files={
                        "input": (
                            "input.json",
                            data,
                        )
                    },
                )
            assert response.status_code == 201

            content = json.loads(response.content.decode())
            assert ("summary") in content.keys()
            assert "completed" in content.get("summary").get("status")
            assert len(json_data["policies"]) == content.get("summary").get("totalCount")
            assert len(json_data["policies"]) == content.get("summary").get("completedCount")
            assert ("details") in content.keys()

            cursor.execute(query="SELECT * from policies")
            assert cursor.rowcount == len(json_data["policies"])

            cursor.execute(query="Delete from policies")
            init_db_instance.commit()

        # yaml format check
        for json_data in test_data:
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
                with open(yaml_file, "r", encoding="utf-8") as file:
                    data = file.read().encode("utf-8")
                response = client.post(
                    BASEURL + "policies/import",
                    params={"format": "yaml"},
                    files={
                        "input": (
                            "input.yaml",
                            data,
                        )
                    },
                )
            assert response.status_code == 201

            content = json.loads(response.content.decode())
            assert ("summary") in content.keys()
            assert "completed" in content.get("summary").get("status")
            assert len(json_data["policies"]) == content.get("summary").get("totalCount")
            assert len(json_data["policies"]) == content.get("summary").get("completedCount")
            assert ("details") in content.keys()

            cursor.execute(query="SELECT * from policies")
            assert cursor.rowcount == len(json_data["policies"])

            cursor.execute(query="Delete from policies")
            init_db_instance.commit()

    def test_api_import_400_with_message_when_policy_zero(
        self,
        init_db_instance,
        mocker,
        tmp_import_json_file_pol0_err,
        tmp_import_yaml_file_pol0_err,
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        with open(tmp_import_json_file_pol0_err, "r") as file:
            json_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": "json"},
                files={
                    "input": (
                        "input.json",
                        json_data,
                    )
                },
            )

        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("summary") in content.keys()
        assert "failed" in content.get("summary").get("status")
        assert 0 == content.get("summary").get("totalCount")
        assert 0 == content.get("summary").get("failedCount")
        assert ("details") in content.keys()
        assert len(content.get("details")) == 1

        with open(tmp_import_yaml_file_pol0_err, "r") as file:
            yaml_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": "yaml"},
                files={
                    "input": (
                        "input.yaml",
                        yaml_data,
                    )
                },
            )

        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("summary") in content.keys()
        assert "failed" in content.get("summary").get("status")
        assert 0 == content.get("summary").get("totalCount")
        assert 0 == content.get("summary").get("failedCount")
        assert ("details") in content.keys()
        assert len(content.get("details")) == 1
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    def test_api_import_400_with_message_when_invalid_parameters(
        self,
        init_db_instance,
        mocker,
        tmp_import_json_file_err,
        tmp_import_yaml_file_err,
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        with open(tmp_import_json_file_err, "r") as file:
            json_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": "json"},
                files={
                    "input": (
                        "input.json",
                        json_data,
                    )
                },
            )

        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("summary") in content.keys()
        assert "failed" in content.get("summary").get("status")
        assert 1 == content.get("summary").get("totalCount")
        assert 1 == content.get("summary").get("failedCount")
        assert ("details") in content.keys()
        assert ("policyID", "d8eceb14da") in content.get("details")[0].items()
        assert len(content.get("details")[0].get("message")) > 1
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

        with open(tmp_import_yaml_file_err, "r") as file:
            json_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": "yaml"},
                files={
                    "input": (
                        "input.yaml",
                        json_data,
                    )
                },
            )

        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("summary") in content.keys()
        assert "failed" in content.get("summary").get("status")
        assert 1 == content.get("summary").get("totalCount")
        assert 1 == content.get("summary").get("failedCount")
        assert ("details") in content.keys()
        assert ("policyID", "d8eceb14da") in content.get("details")[0].items()
        assert len(content.get("details")[0].get("message")) > 1
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    def test_api_import_400_with_message_when_many_invalid_parameters(
        self,
        init_db_instance,
        mocker,
        tmp_import_json_file_many_err,
        tmp_import_yaml_file_many_err,
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        with open(tmp_import_json_file_many_err, "r") as file:
            json_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": "json"},
                files={
                    "input": (
                        "input.json",
                        json_data,
                    )
                },
            )

        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("summary") in content.keys()
        assert "failed" in content.get("summary").get("status")
        assert 3 == content.get("summary").get("totalCount")
        assert 3 == content.get("summary").get("failedCount")
        assert ("details") in content.keys()
        assert ("policyID", "d8eceb14da") in content.get("details")[0].items()
        assert len(content.get("details")[0].get("message")) > 1
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

        with open(tmp_import_yaml_file_many_err, "r") as file:
            json_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": "yaml"},
                files={
                    "input": (
                        "input.yaml",
                        json_data,
                    )
                },
            )

        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("summary") in content.keys()
        assert "failed" in content.get("summary").get("status")
        assert 3 == content.get("summary").get("totalCount")
        assert 3 == content.get("summary").get("failedCount")
        assert ("details") in content.keys()
        assert ("policyID", "d8eceb14da") in content.get("details")[0].items()
        assert len(content.get("details")[0].get("message")) > 1
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    def test_api_import_400_with_message_when_nonexistent_file_specified(
        self,
        init_db_instance,
        mocker,
        tmp_import_json_file_err,
        tmp_import_yaml_file_err,
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()

        response = client.post(BASEURL + "policies/import", params={"format": "json"})

        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("code", "E10001") in content.items()
        assert ("message") in content.keys()
        assert len(content.get("message")[0]) > 0
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

        response = client.post(BASEURL + "policies/import", params={"format": "yaml"})

        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("code", "E10001") in content.items()
        assert ("message") in content.keys()
        assert len(content.get("message")[0]) > 0
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    def test_api_import_failure_when_invalid_file_format(self, init_db_instance, mocker):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
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
                   title: NodeConfPolicy
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
                response = client.post(
                    BASEURL + "policies/import",
                    params={"format": "json"},
                    files={
                        "input": (
                            "input.json",
                            json_file,
                        )
                    },
                )
            content = json.loads(response.content.decode())
            assert response.status_code == 400
            assert ("summary") in content.keys()
            assert "failed" in content.get("summary").get("status")
            assert 0 == content.get("summary").get("totalCount")
            assert 0 == content.get("summary").get("failedCount")
            assert (
                content.get("details")[0].get("message")
                == "File failed to load because specified format is different from file format"
            )
            assert response.charset_encoding == CHARSET_ENCODING
            assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
            assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

        with tempfile.TemporaryDirectory() as dir_path:
            yaml_file = os.path.join(dir_path, f"{str(uuid.uuid4())}.yaml")
            with open(yaml_file, mode="w", encoding="utf-8") as fh:
                csv_data = """
                category,title,policy/hardwareConnectionsLimit/gpu/maxNum,policy/hardwareConnectionsLimit/gpu/minNum
                nodeConfigurationPolicy,NodeConfPolicy,5,1
                """
                fh.write(csv_data)

                response = client.post(
                    BASEURL + "policies/import",
                    params={"format": "yaml"},
                    files={
                        "input": (
                            "input.yaml",
                            yaml_file,
                        )
                    },
                )
            content = json.loads(response.content.decode())
            assert response.status_code == 400
            assert ("summary") in content.keys()
            assert "failed" in content.get("summary").get("status")
            assert 0 == content.get("summary").get("totalCount")
            assert 0 == content.get("summary").get("failedCount")
            assert (
                content.get("details")[0].get("message")
                == "File failed to load because specified format is different from file format"
            )
            assert response.charset_encoding == CHARSET_ENCODING
            assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
            assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    def test_api_import_failure_when_duplicate_data_exists(
        self, init_db_instance, mocker, tmp_duplicate_import_json_file
    ):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        with open(tmp_duplicate_import_json_file, "r") as file:
            json_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": "json"},
                files={
                    "input": (
                        "input.json",
                        json_data,
                    )
                },
            )
        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("summary") in content.keys()
        assert "failed" in content.get("summary").get("status")
        assert 2 == content.get("summary").get("totalCount")
        assert 1 == content.get("summary").get("failedCount")
        assert ("policyID", "ffeceb14da") in content.get("details")[0].items()
        assert (
            content.get("details")[0].get("message")
            == "Specified policy hardwareConnectionsLimit and cpu are duplicates in file"
        )
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    @pytest.mark.parametrize(
        "format_,input_",
        [
            ("json", "input.json"),
            ("yaml", "input.yaml"),
        ],
    )
    def test_api_import_500_with_message_when_multiple_duplicate_data(
        self,
        init_db_instance,
        mocker,
        format_,
        input_,
        tmp_mul_duplicate_import_json_file,
        tmp_mul_duplicate_import_yaml_file,
    ):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        filePath = tmp_mul_duplicate_import_json_file if format_ == "json" else tmp_mul_duplicate_import_yaml_file
        with open(filePath, "r") as file:
            json_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": format_},
                files={
                    "input": (
                        input_,
                        json_data,
                    )
                },
            )
        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("summary") in content.keys()
        assert "failed" in content.get("summary").get("status")
        assert 4 == content.get("summary").get("totalCount")
        assert 2 == content.get("summary").get("failedCount")
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    @pytest.mark.parametrize(
        "format_,input_",
        [
            ("json", "input.json"),
            ("yaml", "input.yaml"),
        ],
    )
    def test_api_import_500_with_message_when_invalid_config_value(
        self,
        mock_db_connection_settingFilevalidationError,
        format_,
        input_,
        tmp_import_json_file,
        tmp_import_yaml_file,
        caplog,
        mocker,
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("logging.config.dictConfig")
        filePath = tmp_import_json_file if format_ == "json" else tmp_import_yaml_file
        with open(filePath, "r") as file:
            json_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": format_},
                files={
                    "input": (
                        input_,
                        json_data,
                    )
                },
            )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_config.yaml Dummy message",
        ) in content.items()
        assert "[E10002]Failed to load policymanager_config.yaml" in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    @pytest.mark.parametrize(
        "format_,input_",
        [
            ("json", "input.json"),
            ("yaml", "input.yaml"),
        ],
    )
    def test_api_import_500_with_message_when_invalid_config_value_without_logger(
        self,
        mock_db_connection_settingFilevalidationError,
        format_,
        input_,
        tmp_import_json_file,
        tmp_import_yaml_file,
        caplog,
        mocker,
    ):  # pylint: disable=C2401,W0613,W0621
        mocker.patch("policymanager.restapi.initialize_log", side_effect=SettingFileValidationError("Dummy message"))
        filePath = tmp_import_json_file if format_ == "json" else tmp_import_yaml_file
        with open(filePath, "r") as file:
            json_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": format_},
                files={
                    "input": (
                        input_,
                        json_data,
                    )
                },
            )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10002") in content.items()
        assert (
            "message",
            "Failed to load policymanager_config.yaml Dummy message",
        ) in content.items()
        assert "[E10002]Failed to load policymanager_config.yaml" not in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_import_500_with_message_when_json_read_permission_denied(
        self,
        mocker,
        tmp_import_json_file,
        caplog,
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("json.load", side_effect=[Exception("File has no permission")])
        with open(tmp_import_json_file, "r") as file:
            json_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": "json"},
                files={
                    "input": (
                        "input.json",
                        json_data,
                    )
                },
            )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("summary") in content.keys()
        assert "failed" in content.get("summary").get("status")
        assert 0 == content.get("summary").get("totalCount")
        assert 0 == content.get("summary").get("failedCount")
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_import_500_with_message_when_yaml_read_permission_denied(
        self,
        mocker,
        tmp_import_yaml_file,
        caplog,
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch(
            "yaml.load",
            side_effect=[
                {
                    "version": 1,
                    "formatters": {
                        "standard": {
                            "format": "%(asctime)s %(levelname)s %(message)s",
                            "datefmt": "%Y/%m/%d %H:%M:%S.%f",
                        }
                    },
                    "handlers": {
                        "file": {
                            "class": "logging.handlers.RotatingFileHandler",
                            "level": "INFO",
                            "formatter": "standard",
                            "filename": "/var/log/cdim/app_layout_apply.log",
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
                },
                Exception("File has no permission"),
            ],
        )

        with open(tmp_import_yaml_file, "r") as file:
            yaml_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": "yaml"},
                files={
                    "input": (
                        "input.yaml",
                        yaml_data,
                    )
                },
            )
        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("summary") in content.keys()
        assert "failed" in content.get("summary").get("status")
        assert 0 == content.get("summary").get("totalCount")
        assert 0 == content.get("summary").get("failedCount")
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    @pytest.mark.parametrize(
        "format_,input_",
        [
            ("json", "input.json"),
            ("yaml", "input.yaml"),
        ],
    )
    def test_api_import_failure_when_duplicate_case(
        self,
        mock_db_connection_dublicatedPoliceError,
        format_,
        input_,
        tmp_import_json_file,
        tmp_import_yaml_file,
        caplog,
        mocker,
    ):  # pylint: disable=C2401,W0613,W0621
        """Failure Test"""

        mocker.patch("logging.config.dictConfig")
        filePath = tmp_import_json_file if format_ == "json" else tmp_import_yaml_file

        with open(filePath, "r") as file:
            json_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": format_},
                files={
                    "input": (
                        input_,
                        json_data,
                    )
                },
            )
        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("summary") in content.keys()
        assert "failed" in content.get("summary").get("status")
        assert 2 == content.get("summary").get("totalCount")
        assert 1 == content.get("summary").get("failedCount")
        assert ("details") in content.keys()
        assert ("policyID", "123456789a") in content.get("details")[0].items()
        assert (
            "message",
            "Specified policy is duplicate of 123456789b",
        ) in content.get(
            "details"
        )[0].items()
        assert '"message":"[E10008]' in caplog.text
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_import_failure_when_file_format_mismatch(
        self, init_db_instance, mocker, get_tmp_import_json_content_yaml_file
    ):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        with open(get_tmp_import_json_content_yaml_file, "r") as file:
            json_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": "yaml"},
                files={
                    "input": (
                        "input.yaml",
                        json_data,
                    )
                },
            )
        content = json.loads(response.content.decode())
        assert response.status_code == 400
        assert ("summary") in content.keys()
        assert "failed" in content.get("summary").get("status")
        assert 0 == content.get("summary").get("totalCount")
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    def test_api_import_500_with_message_when_init_log(self, mocker, tmp_import_json_file):
        mocker.patch.object(Logger, "__init__", side_effect=LogInitializationError)

        with open(tmp_import_json_file, "r") as file:
            json_data = file.read().encode("utf-8")
            response = client.post(
                BASEURL + "policies/import",
                params={"format": "json"},
                files={
                    "input": (
                        "input.json",
                        json_data,
                    )
                },
            )

        content = json.loads(response.content.decode())
        assert response.status_code == 500
        assert ("code", "E10012") in content.items()
        assert (
            "message",
            "Internal server error. Failed in log initialization",
        ) in content.items()


class TestMain:

    def test_api_common_retrieve_from_secret_store_when_db_config_missing(self, mocker, init_db_instance):
        config = {
            "db": {
                "dbname": "PolicyDB",
                "user": "user01",
                "host": "0.0.0.0",
                "port": 5432,
            },
            "server": {
                "host": "0.0.0.0",
                "port": 8010,
            },
        }
        mocker.patch("policymanager.common.config_reader.PolicyLogConfigReader")
        mocker.patch("policymanager.common.config_reader.PolicyConfigReader.get_db_config").return_value = config
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
        params = [
            "123456789a",
            "nodeConfigurationPolicy",
            "insert1",
            json.dumps({"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}}),
            True,
            "2023-09-01T00:00:00Z",
            "2023-09-01T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()

        response = client.get(BASEURL + "policies")
        content = json.loads(response.content.decode())
        assert response.status_code == 200
        assert "count" in content.keys()
        assert "policies" in content.keys()
        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

    @pytest.mark.parametrize("exc", [{RequestException()}, {Timeout()}, {ConnectionError()}, {Exception()}])
    def test_api_common_failure_when_unexpected_error_from_secret_store(self, mocker, exc):
        config = {
            "db": {
                "dbname": "PolicyDB",
                "user": "user01",
                "host": "0.0.0.0",
                "port": 5432,
            },
            "server": {
                "host": "0.0.0.0",
                "port": 8010,
            },
        }
        mocker.patch("policymanager.common.config_reader.PolicyLogConfigReader")
        mocker.patch("policymanager.common.config_reader.PolicyConfigReader.get_db_config").return_value = config
        mocker.patch("requests.get")
        requests.get.side_effect = exc
        response = client.get(BASEURL + "policies")
        content = json.loads(response.content.decode())
        assert response.status_code == 500

        assert ("code", "E10011") in content.items()
        assert "Failed to retrieve secret store" in content.get("message")
        assert response.charset_encoding == CHARSET_ENCODING
        assert response.headers.get("Content-Type") == HEADERS_TYPE_JSON
        assert response.headers.get("X-Content-Type-Options") == HEADERS_NOSNIFF

    @pytest.mark.parametrize("exc", [{RequestException()}, {Timeout()}, {ConnectionError()}])
    def test_api_common_failure_when_failed_to_retrieve_from_secret_store(self, mocker, capfd, exc):
        config = {
            "db": {
                "dbname": "PolicyDB",
                "user": "user01",
                "host": "0.0.0.0",
                "port": 5432,
            },
            "server": {
                "host": "0.0.0.0",
                "port": 8010,
            },
        }
        mocker.patch("yaml.safe_load").return_value = config
        mocker.patch("requests.get")
        requests.get.side_effect = exc

        main()
        out, err = capfd.readouterr()
        # no stdout
        assert out == ""
        # Ensure that appropriate error codes and messages are output to standard error
        assert "[E10011]Failed to retrieve secret store" in err

    def test_api_common_uvicorn_operates_normally(self, mocker):
        uvicorn_mockup = mocker.patch("uvicorn.run")
        main()
        assert uvicorn_mockup.call_count == 1

    def test_api_common_failure_when_invalid_config_value(self, mocker, capfd):
        mocker.patch(
            "policymanager.restapi.PolicyConfigReader",
            side_effect=SettingFileValidationError("Dummy message"),
        )
        main()
        _, err = capfd.readouterr()
        assert err.split("\n")[0] == "[E10002]Failed to load policymanager_config.yaml"

    def test_api_common_db_recreate(
        self,
    ):  # pylint:disable=C2401,C0103,
        """Verify that when the global variable DATABASE has no value, the value is input and returned through db_connection"""
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
                    "filename": "/var/log/cdim/app_layout_apply.log",
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
        db_gen = db_connection(logger)
        assert isinstance(db_gen, object)
        db_regen = db_connection(logger)
        assert db_gen != db_regen

    def test_api_common_no_traceback_after_server_stop(self, mocker):
        mockup = mocker.patch("policymanager.restapi.uvicorn.run", side_effect=KeyboardInterrupt)

        main()

        assert mockup.call_count == 1
