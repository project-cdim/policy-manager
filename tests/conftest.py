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
import pytest
import logging.config
from policymanager.common.logger import Logger
from policymanager.common.config_reader import PolicyLogConfigReader
from policymanager.common.custom_exceptions import (
    DuplicatePolicyException,
    IdNotFoundException,
    InvalidOperationException,
    LogInitializationError,
    SettingFileValidationError,
    LogSettingFileValidationError,
    UnmatchIdException,
)
import psycopg2
from policymanager.restapi import GetAllOption

CHARSET_ENCODING = "utf-8"
HEADERS_TYPE_JSON = "application/json; charset=utf-8"
HEADERS_TYPE_YAML = "application/yaml; charset=utf-8"
HEADERS_NOSNIFF = "nosniff"


BASE_LOGGING_CONFIG = {
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


@pytest.fixture(autouse=True)
def clean_root_logger():
    log_config = PolicyLogConfigReader().get_log_config
    log_config["disable_existing_loggers"] = False
    logging.config.dictConfig(log_config)


class FakeDBACCESS:  # py;int:disable=E0213
    """Dummy DBAccess class used to verify normal operation"""

    def get_all_policy(
        options: GetAllOption, category: list = ["all"], fields: list = None
    ):  # py;int:disable=E0213,W0613
        """Dummy method for retrieving constraints in bulk"""
        policies = []
        if not fields:
            fields = [
                "policyID",
                "category",
                "title",
                "policy",
                "enabled",
                "createdAt",
                "updatedAt",
            ]
        if options.device is None:
            options.device = "cpu"

        if (
            "nodeConfigurationPolicy" in category
            and not "systemOperationPolicy" in category
            or options.subCategory == "hardwareConnectionsLimit"
        ):
            policy = {
                "policyID": "d8eceb14da",
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {options.device: {"maxNum": 5, "minNum": 1}}},
                "enabled": True if options.enabled != False else False,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            }
            policies.append({k: v for k, v in policy.items() if k in fields})

        elif (
            not "nodeConfigurationPolicy" in category
            and "systemOperationPolicy" in category
            or options.subCategory == "useThreshold"
        ):
            policy = {
                "policyID": "abc10dfaa9",
                "category": "systemOperationPolicy",
                "title": "useThreshold",
                "policy": {
                    "useThreshold": {
                        options.device: {
                            "value": 80,
                            "unit": "percent",
                            "comparison": "lt",
                        }
                    }
                },
                "enabled": True if options.enabled != False else False,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            }

            policies.append({k: v for k, v in policy.items() if k in fields})
        else:
            policy = {
                "policyID": "d8eceb14da",
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {options.device: {"maxNum": 5, "minNum": 1}}},
                "enabled": True if options.enabled != False else False,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            }
            policies.append({k: v for k, v in policy.items() if k in fields})
            policy = {
                "policyID": "abc10dfaa9",
                "category": "systemOperationPolicy",
                "title": "useThreshold",
                "policy": {
                    "useThreshold": {
                        options.device: {
                            "value": 80,
                            "unit": "percent",
                            "comparison": "lt",
                        }
                    }
                },
                "enabled": True if options.enabled != False else False,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            }
            policies.append({k: v for k, v in policy.items() if k in fields})

        return {"count": len(policies), "policies": policies}

    def register(category: str, title: str, policy: dict, enabled: bool):  # py;int:disable=E0213,W0613
        """Dummy method for registering constraints"""
        return "a21bc21587"

    def change_enabled(enableIDList: list, disableIDList: list):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for enabling/disabling constraints"""
        return 1

    def get_policy(policyID: str):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for retrieving constraints by ID"""
        return {
            "policyID": policyID,
            "category": "nodeConfigurationPolicy",
            "title": "hardwareConnectionsLimit",
            "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
            "enabled": True,
            "createdAt": "2023-05-10T00:00:00Z",
            "updatedAt": "2023-05-10T00:00:00Z",
        }

    def update(policyID: str, category: str, title: str, policy: dict, force: bool):  # py;int:disable=E0213,W0613
        """Dummy method for updating constraints"""
        return 1

    def delete(policyID: str, force: bool):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for deleting constraints"""
        return 1

    def export():  # py;int:disable=E0213,W0613,C0103
        """Dummy method for exporting constraints"""
        policies = [
            {
                "policyID": "d8eceb14da",
                "category": "nodeConfigurationPolicy",
                "title": "hardwareConnectionsLimit",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": True,
                "createdAt": "2023-05-10T00:00:00Z",
                "updatedAt": "2023-05-10T00:00:00Z",
            }
        ]

        return {"exportedCount": len(policies), "policies": policies}

    def import_policy(policy_list: list):
        return [{"policyID": "d8eceb14da", "message": "completed"}]

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
    """restapi.db_connection mock"""
    mocker.patch(
        "policymanager.restapi.db_connection",
        mocker.MagicMock(return_value=FakeDBACCESS),
    )


class FakeDBACCESSOperationalError:
    """Dummy DBAccess class used to verify OperationalError"""

    def get_all_policy(
        options: GetAllOption, category: list = ["all"], fields: list = None
    ):  # py;int:disable=E0213,W0613
        """Dummy method for retrieving constraints in bulk"""
        raise psycopg2.OperationalError

    def register(category: str, title: str, policy: dict, enabled: bool):  # py;int:disable=E0213,W0613
        """Dummy method for registering constraints"""
        raise psycopg2.OperationalError

    def get_policy(policyID: str):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for retrieving constraints by ID"""
        raise psycopg2.OperationalError

    def change_enabled(enableIDList: list, disableIDList: list):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for enabling/disabling constraints"""
        raise psycopg2.OperationalError

    def update(policyID: str, category: str, title: str, policy: dict, force: bool):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for updating constraints"""
        raise psycopg2.OperationalError

    def delete(policyID: str, force: bool):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for deleting constraints"""
        raise psycopg2.OperationalError

    def export():  # py;int:disable=E0213,W0613,C0103
        """Dummy method for exporting constraints"""
        raise psycopg2.OperationalError

    def import_policy(format: str, policy_list: list):
        raise psycopg2.OperationalError

    def close():
        pass

    def open_db_connection():
        pass

    def check_for_duplication_policy(policy: dict, policyID: str = None, assumed_count: int = 1):
        raise psycopg2.OperationalError

    def get_policy_count(options: GetAllOption):
        return {"totalCount": 1}


@pytest.fixture
def mock_db_connection_operationalerror(mocker):
    """restapi.db_connection mock"""
    mocker.patch(
        "policymanager.restapi.db_connection",
        mocker.MagicMock(return_value=FakeDBACCESSOperationalError),
    )


class FakeDBACCESSProgrammingError:
    """Dummy DBAccess class used to verify ProgrammingError"""

    def get_all_policy(
        options: GetAllOption, category: list = ["all"], fields: list = None
    ):  # py;int:disable=E0213,W0613
        """Dummy method for retrieving constraints (bulk retrieval)"""
        err = psycopg2.ProgrammingError
        err.pgcode = "42601"
        raise err

    def register(category: str, title: str, policy: dict, enabled: bool):  # py;int:disable=E0213,W0613
        """Dummy method for registering constraints"""

        err = psycopg2.ProgrammingError
        err.pgcode = "42601"
        raise err

    def get_policy(policyID: str):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for retrieving constraints (by ID)"""
        err = psycopg2.ProgrammingError
        err.pgcode = "42601"
        raise err

    def change_enabled(enableIDList: list, disableIDList: list):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for enabling/disabling constraints"""
        err = psycopg2.ProgrammingError
        err.pgcode = "42601"
        raise err

    def update(policyID: str, category: str, title: str, policy: dict, force: bool):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for updating constraints"""
        err = psycopg2.ProgrammingError
        err.pgcode = "42601"
        raise err

    def delete(policyID: str, force: bool):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for deleting constraints"""
        err = psycopg2.ProgrammingError
        err.pgcode = "42601"
        raise err

    def export():  # py;int:disable=E0213,W0613,C0103
        """Dummy method for exporting constraints"""
        err = psycopg2.ProgrammingError
        err.pgcode = "42601"
        raise err

    def import_policy(format: str, policy_list: list):
        """Dummy method for importing policy"""
        err = psycopg2.ProgrammingError
        err.pgcode = "42601"
        raise err

    def close():
        """Dummy method for closing the connection"""
        pass

    def open_db_connection():
        """Dummy method for opening the connection"""
        pass

    def check_for_duplication_policy(policy: dict, policyID: str = None, assumed_count: int = 1):
        """Dummy method for checking for duplicate policies"""
        err = psycopg2.ProgrammingError
        err.pgcode = "42601"
        raise err

    def get_policy_count(options: GetAllOption):
        """Dummy method for retrieving policy count"""
        return {"totalCount": 1}


@pytest.fixture
def mock_db_connection_programmingerror(mocker):
    """restapi.db_connection mock"""
    mocker.patch(
        "policymanager.restapi.db_connection",
        mocker.MagicMock(return_value=FakeDBACCESSProgrammingError),
    )


class FakeDBACCESSIdNotFoundException:
    """Dummy DBAccess class used to verify IdNotFoundException"""

    def get_policy(policyID: str):  # py;int:disable=E0213,W0613
        """Dummy method for retrieving constraints by ID"""
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

    def close():
        pass

    def open_db_connection():
        pass

    def check_for_duplication_policy(policy: dict, policyID: str = None, assumed_count: int = 1):
        pass

    def get_policy_count(options: GetAllOption):
        return {"totalCount": 1}


@pytest.fixture
def mock_db_connection_idnotfoundexception(mocker):
    """restapi.db_connection mock"""
    mocker.patch(
        "policymanager.restapi.db_connection",
        mocker.MagicMock(return_value=FakeDBACCESSIdNotFoundException),
    )


class FakeDBACCESSInvalidOperationException:
    """Dummy DBAccess class used to verify InvalidOperationException"""

    def update(policyID: str, category: str, title: str, policy: dict, force: bool):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for updating constraints"""
        raise InvalidOperationException(policyID)

    def delete(policyID: str, force: bool):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for deleting constraints"""
        raise InvalidOperationException(policyID)

    def get_policy(policyID: str):
        return {
            "category": "nodeConfigurationPolicy",
            "title": "NodeConfPolicy",
            "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
            "enabled": True,
            "createdAt": "2023-05-10T00:00:00Z",
            "updatedAt": "2023-05-10T00:00:00Z",
        }

    def close():
        pass

    def open_db_connection():
        pass

    def check_for_duplication_policy(policy: dict, policyID: str = None, assumed_count: int = 1):
        pass


@pytest.fixture
def mock_db_connection_invalidoperationexception(mocker):
    """restapi.db_connection mock"""
    mocker.patch(
        "policymanager.restapi.db_connection",
        mocker.MagicMock(return_value=FakeDBACCESSInvalidOperationException),
    )


class FakeDBACCESSSettingFileValidationError:  # py;int:disable=E0213
    """Dummy DBAccess class used to verify SettingFileValidationError"""

    def get_all_policy(
        options: GetAllOption, category: list = ["all"], fields: list = None
    ):  # py;int:disable=E0213,W0613
        """Dummy method for retrieving constraints in bulk"""
        raise SettingFileValidationError("Dummy message")

    def register(category: str, title: str, policy: dict, enabled: str):  # py;int:disable=E0213,W0613
        """Dummy method for registering constraints"""
        raise SettingFileValidationError("Dummy message")

    def change_enabled(enableIDList: list, disableIDList: list):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for enabling/disabling constraints"""
        raise SettingFileValidationError("Dummy message")

    def get_policy(policyID: str):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for retrieving constraints by ID"""
        raise SettingFileValidationError("Dummy message")

    def update(policyID: str, category: str, title: str, policy: dict, force: bool):  # py;int:disable=E0213,W0613
        """Dummy method for updating constraints"""
        raise SettingFileValidationError("Dummy message")

    def delete(policyID: str, force: bool):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for deleting constraints"""
        raise SettingFileValidationError("Dummy message")

    def export():  # py;int:disable=E0213,W0613,C0103
        """Dummy method for exporting constraints"""
        raise SettingFileValidationError("Dummy message")

    def import_policy(policy_list: list):
        raise SettingFileValidationError("Dummy message")

    def close():
        pass

    def open_db_connection():
        raise SettingFileValidationError("Dummy message")

    def check_for_duplication_policy(policy: dict, policyID: str = None, assumed_count: int = 1):
        pass

    def get_policy_count(options: GetAllOption):
        return {"totalCount": 1}


@pytest.fixture
def mock_db_connection_settingFilevalidationError(mocker):
    """restapi.db_connection mock"""
    mocker.patch(
        "policymanager.restapi.db_connection",
        mocker.MagicMock(return_value=FakeDBACCESSSettingFileValidationError),
    )


class FakeDBACCESSDuplicatePolicyException:
    """Dummy DBAccess class used to verify DuplicatePolicyException"""

    def get_policy(policyID: str):
        return True

    def register(category: str, title: str, policy: dict, enabled: str):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for adding constraints"""
        raise DuplicatePolicyException("Specified policy is duplicate of")

    def update(policyID: str, category: str, title: str, policy: dict, force: bool):  # py;int:disable=E0213,W0613,C0103
        """Dummy method for updating constraints"""
        raise DuplicatePolicyException("Specified policy is duplicate of")

    def import_policy(policy_list: list):
        raise DuplicatePolicyException(
            [
                {
                    "policyID": "123456789a",
                    "message": "Specified policy is duplicate of 123456789b",
                }
            ]
        )

    def close():
        pass

    def open_db_connection():
        pass

    def check_for_duplication_policy(policy: dict, policyID: str = None, assumed_count: int = 1):
        raise DuplicatePolicyException("Specified policy is duplicate of")

    def get_policy_count(options: GetAllOption):
        return {"totalCount": 1}


@pytest.fixture
def mock_db_connection_dublicatedPoliceError(mocker):
    """restapi.db_connection mock"""
    mocker.patch(
        "policymanager.restapi.db_connection",
        mocker.MagicMock(return_value=FakeDBACCESSDuplicatePolicyException),
    )
