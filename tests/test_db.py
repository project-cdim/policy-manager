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

import datetime
import json
import logging
from logging import INFO

import psycopg2
import psycopg2.extras
import pytest
from jsonschema import ValidationError

from policymanager.common.logger import Logger, initialize_log
from policymanager.common.custom_exceptions import (
    DuplicatePolicyException,
    IdNotFoundException,
    InvalidOperationException,
    UnmatchIdException,
)
from policymanager.common.db import DbAccess, GetAllOption
from policymanager.plugins.base import BasePolicyPlugin

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
def get_db_instance():
    logger = logger = initialize_log()
    return DbAccess(logger)


@pytest.fixture
def get_db_policies():
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


@pytest.fixture
def init_db_instance(docker_services):
    docker_services.wait_until_responsive(timeout=30.0, pause=0.1, check=lambda: is_postgresql_ready())
    yield DB_CONNECT
    DB_CONNECT.close()


class TestDbAccess:
    @pytest.mark.parametrize(
        "args",
        [
            (
                {
                    "policy_list": [
                        {
                            "policyID": "123456789a",
                            "category": "nodeConfigurationPolicy",
                            "title": "test",
                            "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
                            "enabled": False,
                        },
                        {
                            "policyID": "123456789c",
                            "category": "nodeConfigurationPolicy",
                            "title": "test",
                            "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
                            "enabled": True,
                        },
                    ]
                }
            ),  # Case where numerical constraint conditions are registered successfully
            (
                {
                    "policy_list": [
                        {
                            "category": "nodeConfigurationPolicy",
                            "title": "test",
                            "policy": {"hardwareConnectionsLimit": {"fpga": {"maxNum": 5, "minNum": 1}}},
                            "enabled": True,
                        },
                    ]
                }
            ),  # Case where policyID non-exists
            (
                {
                    "policy_list": [
                        {
                            "policyID": "123456789b",
                            "category": "systemOperationPolicy",
                            "title": "test",
                            "policy": {
                                "useThreshold": {
                                    "cpu": {
                                        "value": 80,
                                        "unit": "percent",
                                        "comparision": "gt",
                                    }
                                }
                            },
                            "enabled": False,
                        },
                        {
                            "policyID": "123456789f",
                            "category": "systemOperationPolicy",
                            "title": "test",
                            "policy": {
                                "useThreshold": {
                                    "storage": {
                                        "value": 80,
                                        "unit": "percent",
                                        "comparision": "lt",
                                    }
                                }
                            },
                            "enabled": True,
                        },
                    ]
                }
            ),  # Case where skip duplicate
        ],
    )
    def test_db_import_success(self, mocker, args, get_db_instance, init_db_instance):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query="Delete from policies;")
        init_db_instance.commit()

        get_db_instance.register(
            category="systemOperationPolicy",
            title="Duplicated policy",
            policy={"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparision": "gt"}}},
            enabled=False,
        )
        import_detail = get_db_instance.import_policy(**args)
        assert len(import_detail) == len(args["policy_list"])
        message_list = [
            "completed",
            "Skipped due to duplicate database and input data",
        ]
        for detail in import_detail:
            assert detail["message"] in message_list or detail["message"].startswith("New policyID has been issued:")

    @pytest.mark.parametrize(
        "args",
        [
            (
                {
                    "policy_list": [
                        {
                            "policyID": "123456789a",
                            "category": "nodeConfigurationPolicy",
                            "title": "test",
                            "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
                            "enabled": False,
                        },
                        {
                            "policyID": "123456789e",
                            "category": "nodeConfigurationPolicy",
                            "title": "ID_Duplicated_Policy",
                            "policy": {"hardwareConnectionsLimit": {"fpga": {"maxNum": 5, "minNum": 1}}},
                            "enabled": True,
                        },
                    ]
                }
            ),
        ],
    )
    def test_db_import_success_when_id_duplicate(self, mocker, args, get_db_instance, init_db_instance):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        mocker.patch.object(
            DbAccess,
            "_get_randomname",
            side_effect=["123456789e", "123456780f"],
        )

        cursor = init_db_instance.cursor()
        cursor.execute(query="Delete from policies;")
        init_db_instance.commit()
        get_db_instance.register(
            category="systemOperationPolicy",
            title="Duplicated policy",
            policy={"policy": {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparision": "gt"}}}},
            enabled=False,
        )

        import_detail = get_db_instance.import_policy(**args)

        assert len(import_detail) == len(args["policy_list"])

        assert import_detail[1]["message"].startswith("policyID was reissued because of duplication")

    def test_db_import_failure_when_import_conflict_update(self, mocker, get_db_instance, get_db_policies):
        mock_cursor = mocker.MagicMock()
        mock_cursor.rowcount = 0
        mock_cursor.fetchone.side_effect = [get_db_policies[0]]

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

        with pytest.raises(DuplicatePolicyException):
            get_db_instance.import_policy(
                **{
                    "policy_list": [
                        {
                            "policyID": "a21bc21587",
                            "category": "nodeConfigurationPolicy",
                            "title": "testTitle",
                            "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
                            "enabled": False,
                        }
                    ]
                }
            )
            assert mock_cursor.fetchone.call_count == 1

    def test_db_export_success(self, mocker, get_db_instance, init_db_instance, get_db_policies):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query="Delete from policies;")
        init_db_instance.commit()

        insert_query = (
            "INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )

        params = [
            "123456789a",
            "nodeConfigurationPolicy",
            "test",
            json.dumps({"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}}),
            False,
            "2023-09-21T00:00:00Z",
            "2023-09-21T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789c",
            "nodeConfigurationPolicy",
            "test",
            json.dumps(
                {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
            ),
            True,
            "2023-09-21T00:00:00Z",
            "2023-09-21T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789b",
            "systemOperationPolicy",
            "test",
            json.dumps({"useThreshold": {"gpu": {"value": 80, "unit": "percent", "comparision": "gt"}}}),
            False,
            "2023-09-28T00:00:00Z",
            "2023-09-28T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789d",
            "systemOperationPolicy",
            "test",
            json.dumps({"useThreshold": {"dsp": {"value": 80, "unit": "percent", "comparision": "lt"}}}),
            True,
            "2023-09-28T00:00:00Z",
            "2023-09-28T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()

        export_result = get_db_instance.export()
        assert_result = {
            "exportedCount": len(get_db_policies),
            "policies": get_db_policies,
        }

        assert export_result["exportedCount"] == assert_result["exportedCount"]

        for item in export_result["policies"]:
            assert item in assert_result["policies"]

    @pytest.mark.parametrize(
        "args",
        [{"policyID": "123456789a"}],
    )
    def test_db_get_success_when_id_specified(self, mocker, args, get_db_instance, init_db_instance, get_db_policies):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        insert_query = (
            "INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )

        params = [
            "123456789a",
            "nodeConfigurationPolicy",
            "test",
            json.dumps({"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}}),
            False,
            "2023-09-21T00:00:00Z",
            "2023-09-21T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        policy = get_db_instance.get_policy(**args)
        assert policy in get_db_policies
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    def test_db_get_failure_when_nonexistent_id(self, mocker, get_db_instance, init_db_instance):
        mock_conn = mocker.patch("psycopg2.connect", return_value=init_db_instance)
        with pytest.raises(IdNotFoundException):
            policy = get_db_instance.get_policy(None)
            assert policy == {}
            assert mock_conn.call_count == 1

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
    def test_db_get_failure_when_invalid_query(self, mocker, get_db_instance, error, err_code):
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

        with pytest.raises(psycopg2.ProgrammingError):
            policy = get_db_instance.get_policy(None)
            assert policy == {}
            assert mock_cursor.execute.call_count == 1

    @pytest.mark.parametrize(
        "args",
        [
            ({"category": ["all"], "enabled": "all"}),
            ({"category": ["nodeConfigurationPolicy"], "enabled": "all"}),
            ({"category": ["all"], "enabled": "true"}),
            ({"category": ["nodeConfigurationPolicy"], "enabled": "true"}),
            ({"category": ["systemOperationPolicy"]}),
            (
                {
                    "category": [
                        "nodeConfigurationPolicy",
                        "systemOperationPolicy",
                    ]
                }
            ),
        ],
    )
    def test_db_get_all_success(self, mocker, args, get_db_instance, init_db_instance, get_db_policies):
        mock_conn = mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        insert_query = (
            f"INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )

        params = [
            "123456789a",
            "nodeConfigurationPolicy",
            "test",
            json.dumps({"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}}),
            False,
            "2023-09-21T00:00:00Z",
            "2023-09-21T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789c",
            "nodeConfigurationPolicy",
            "test",
            json.dumps(
                {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
            ),
            True,
            "2023-09-21T00:00:00Z",
            "2023-09-21T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789b",
            "systemOperationPolicy",
            "test",
            json.dumps({"useThreshold": {"gpu": {"value": 80, "unit": "percent", "comparision": "gt"}}}),
            False,
            "2023-09-28T00:00:00Z",
            "2023-09-28T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789d",
            "systemOperationPolicy",
            "test",
            json.dumps({"useThreshold": {"dsp": {"value": 80, "unit": "percent", "comparision": "lt"}}}),
            True,
            "2023-09-28T00:00:00Z",
            "2023-09-28T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()

        policies = get_db_instance.get_all_policy(GetAllOption(**args))
        assert policies["count"] in (1, 2, 4)
        for i in policies["policies"]:
            assert i in get_db_policies
        assert mock_conn.call_count == 1
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [
            ({"subCategory": "hardwareConnectionsLimit"}),  # Case where only subCategory is specified
            ({"device": "dsp"}),  # Case where only device is specified
            ({"subCategory": "useThreshold", "device": "gpu"}),  # Case where both subCategory and device are specified
        ],
    )
    def test_db_get_all_success_when_args_with_subcategory_and_device(
        self, args, mocker, get_db_instance, init_db_instance, get_db_policies
    ):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        insert_query = (
            f"INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )

        params = [
            "123456789a",
            "nodeConfigurationPolicy",
            "test",
            json.dumps({"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}}),
            False,
            "2023-09-21T00:00:00Z",
            "2023-09-21T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789c",
            "nodeConfigurationPolicy",
            "test",
            json.dumps(
                {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
            ),
            True,
            "2023-09-21T00:00:00Z",
            "2023-09-21T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789b",
            "systemOperationPolicy",
            "test",
            json.dumps({"useThreshold": {"gpu": {"value": 80, "unit": "percent", "comparision": "gt"}}}),
            False,
            "2023-09-28T00:00:00Z",
            "2023-09-28T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789d",
            "systemOperationPolicy",
            "test",
            json.dumps({"useThreshold": {"dsp": {"value": 80, "unit": "percent", "comparision": "lt"}}}),
            True,
            "2023-09-28T00:00:00Z",
            "2023-09-28T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()

        policies = get_db_instance.get_all_policy(GetAllOption(**args))
        assert policies["count"] in [1, 2]
        assert policies["policies"][0] in get_db_policies
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [
            ({"sortBy": "createdAt"}),  # Case where only `sortBy` is specified
            ({"sortBy": "updatedAt"}),  # Case where only `sortBy` is specified
            ({"sortBy": "createdAt", "orderBy": "asc"}),  # Combination of `sortBy` and `orderBy` with `asc`
            ({"sortBy": "createdAt", "orderBy": "desc"}),  # Combination of `sortBy` and `orderBy` with `desc`
            ({"sortBy": "updatedAt", "orderBy": "asc"}),  # Combination of `sortBy` and `orderBy` with `asc`
            ({"sortBy": "updatedAt", "orderBy": "desc"}),  # Combination of `sortBy` and `orderBy` with `desc`
        ],
    )
    def test_db_get_all_success_when_args_with_sortby_and_orderby(
        self, init_db_instance, mocker, args, get_db_instance
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

        policies = get_db_instance.get_all_policy(GetAllOption(**args))
        assert "count" in policies.keys()
        assert "policies" in policies.keys()

        if args.get("orderBy") == "asc":
            policy = policies.get("policies")[0]
            assert ("policyID", "123456789a") in policy.items()
            assert ("category", "nodeConfigurationPolicy") in policy.items()
            assert ("title", "insert1") in policy.items()
            assert 5 == policy.get("policy").get("hardwareConnectionsLimit").get("gpu").get("maxNum")
            assert 1 == policy.get("policy").get("hardwareConnectionsLimit").get("gpu").get("minNum")
            assert ("enabled", True) in policy.items()
            assert ("createdAt", "2023-09-01T00:00:00Z") in policy.items()
            assert ("updatedAt", "2023-09-01T00:00:00Z") in policy.items()
            policy = policies.get("policies")[1]
            assert ("policyID", "123456789b") in policy.items()
            assert ("category", "nodeConfigurationPolicy") in policy.items()
            assert ("title", "insert2") in policy.items()
            assert 5 == policy.get("policy").get("hardwareConnectionsLimit").get("cpu").get("maxNum")
            assert 1 == policy.get("policy").get("hardwareConnectionsLimit").get("cpu").get("minNum")
            assert ("enabled", False) in policy.items()
            assert ("createdAt", "2023-10-01T00:00:00Z") in policy.items()
            assert ("updatedAt", "2023-10-01T00:00:00Z") in policy.items()
        else:
            policy = policies.get("policies")[0]
            assert ("policyID", "123456789b") in policy.items()
            assert ("category", "nodeConfigurationPolicy") in policy.items()
            assert ("title", "insert2") in policy.items()
            assert 5 == policy.get("policy").get("hardwareConnectionsLimit").get("cpu").get("maxNum")
            assert 1 == policy.get("policy").get("hardwareConnectionsLimit").get("cpu").get("minNum")
            assert ("enabled", False) in policy.items()
            assert ("createdAt", "2023-10-01T00:00:00Z") in policy.items()
            assert ("updatedAt", "2023-10-01T00:00:00Z") in policy.items()
            policy = policies.get("policies")[1]
            assert ("policyID", "123456789a") in policy.items()
            assert ("category", "nodeConfigurationPolicy") in policy.items()
            assert ("title", "insert1") in policy.items()
            assert 5 == policy.get("policy").get("hardwareConnectionsLimit").get("gpu").get("maxNum")
            assert 1 == policy.get("policy").get("hardwareConnectionsLimit").get("gpu").get("minNum")
            assert ("enabled", True) in policy.items()
            assert ("createdAt", "2023-09-01T00:00:00Z") in policy.items()
            assert ("updatedAt", "2023-09-01T00:00:00Z") in policy.items()

        cursor.execute(query="Delete from policies")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [
            ({"fields": ["policyID", "policy", "createdAt", "updatedAt"]}),
            ({"fields": ["policyID", "policy"]}),
            ({"fields": ["policyID"]}),
            ({"fields": ["policy", "createdAt"]}),
        ],
    )
    def test_db_get_all_success_when_args_with_fields(
        self, args, mocker, get_db_instance, init_db_instance, get_db_policies
    ):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        insert_query = (
            f"INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )

        params = [
            "123456789a",
            "nodeConfigurationPolicy",
            "test",
            json.dumps({"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}}),
            False,
            "2023-09-21T00:00:00Z",
            "2023-09-21T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789c",
            "nodeConfigurationPolicy",
            "test",
            json.dumps(
                {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
            ),
            True,
            "2023-09-21T00:00:00Z",
            "2023-09-21T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789b",
            "systemOperationPolicy",
            "test",
            json.dumps({"useThreshold": {"gpu": {"value": 80, "unit": "percent", "comparision": "gt"}}}),
            False,
            "2023-09-28T00:00:00Z",
            "2023-09-28T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789d",
            "systemOperationPolicy",
            "test",
            json.dumps({"useThreshold": {"dsp": {"value": 80, "unit": "percent", "comparision": "lt"}}}),
            True,
            "2023-09-28T00:00:00Z",
            "2023-09-28T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()

        policies = get_db_instance.get_all_policy(GetAllOption(**args))
        assert policies["count"] == len(get_db_policies)
        assert policies["policies"] in [
            [
                {
                    "policyID": get_db_policies[0].get("policyID"),
                },
                {
                    "policyID": get_db_policies[1].get("policyID"),
                },
                {
                    "policyID": get_db_policies[2].get("policyID"),
                },
                {
                    "policyID": get_db_policies[3].get("policyID"),
                },
            ],
            [
                {
                    "policyID": get_db_policies[0].get("policyID"),
                    "policy": get_db_policies[0].get("policy"),
                },
                {
                    "policyID": get_db_policies[1].get("policyID"),
                    "policy": get_db_policies[1].get("policy"),
                },
                {
                    "policyID": get_db_policies[2].get("policyID"),
                    "policy": get_db_policies[2].get("policy"),
                },
                {
                    "policyID": get_db_policies[3].get("policyID"),
                    "policy": get_db_policies[3].get("policy"),
                },
            ],
            [
                {
                    "policy": get_db_policies[0].get("policy"),
                    "createdAt": get_db_policies[0].get("createdAt"),
                },
                {
                    "policy": get_db_policies[1].get("policy"),
                    "createdAt": get_db_policies[1].get("createdAt"),
                },
                {
                    "policy": get_db_policies[2].get("policy"),
                    "createdAt": get_db_policies[2].get("createdAt"),
                },
                {
                    "policy": get_db_policies[3].get("policy"),
                    "createdAt": get_db_policies[3].get("createdAt"),
                },
            ],
            [
                {
                    "policyID": get_db_policies[0].get("policyID"),
                    "policy": get_db_policies[0].get("policy"),
                    "createdAt": get_db_policies[0].get("createdAt"),
                    "updatedAt": get_db_policies[0].get("updatedAt"),
                },
                {
                    "policyID": get_db_policies[1].get("policyID"),
                    "policy": get_db_policies[1].get("policy"),
                    "createdAt": get_db_policies[1].get("createdAt"),
                    "updatedAt": get_db_policies[1].get("updatedAt"),
                },
                {
                    "policyID": get_db_policies[2].get("policyID"),
                    "policy": get_db_policies[2].get("policy"),
                    "createdAt": get_db_policies[2].get("createdAt"),
                    "updatedAt": get_db_policies[2].get("updatedAt"),
                },
                {
                    "policyID": get_db_policies[3].get("policyID"),
                    "policy": get_db_policies[3].get("policy"),
                    "createdAt": get_db_policies[3].get("createdAt"),
                    "updatedAt": get_db_policies[3].get("updatedAt"),
                },
            ],
        ]
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [
            (
                {
                    "category": ["nodeConfigurationPolicy", "systemOperationPolicy"],
                    "enabled": False,
                    "subCategory": "hardwareConnectionsLimit",
                    "device": "gpu",
                    "fields": ["policyid", "policy", "updatedAt", "createdAt"],
                }
            ),  #  One pattern where `category`, `enabled`, `subCategory`, `device`, and `fields` are specified simultaneously
            (
                {
                    "subCategory": "useThreshold",
                    "device": "gpu",
                    "fields": ["policyID", "policy"],
                }
            ),  # Pattern where `subCategory`, `device`, and `fields` are specified simultaneously
        ],
    )
    def test_db_get_all_success_when_all_args_specified(
        self, args, mocker, get_db_instance, init_db_instance, get_db_policies
    ):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        insert_query = (
            f"INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )

        params = [
            "123456789a",
            "nodeConfigurationPolicy",
            "test",
            json.dumps({"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}}),
            False,
            "2023-09-21T00:00:00Z",
            "2023-09-21T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789b",
            "systemOperationPolicy",
            "test",
            json.dumps({"useThreshold": {"gpu": {"value": 80, "unit": "percent", "comparision": "gt"}}}),
            False,
            "2023-09-28T00:00:00Z",
            "2023-09-28T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789c",
            "nodeConfigurationPolicy",
            "test",
            json.dumps(
                {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
            ),
            False,
            "2023-09-21T00:00:00Z",
            "2023-09-21T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789d",
            "systemOperationPolicy",
            "test",
            json.dumps({"useThreshold": {"dsp": {"value": 80, "unit": "percent", "comparision": "lt"}}}),
            True,
            "2023-09-28T00:00:00Z",
            "2023-09-28T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()

        policies = get_db_instance.get_all_policy(GetAllOption(**args))
        assert policies["count"] in [1]
        assert policies["policies"] in [
            [
                {
                    "policyID": get_db_policies[0].get("policyID"),
                    "policy": get_db_policies[0].get("policy"),
                }
            ],
            [
                {
                    "policyID": get_db_policies[1].get("policyID"),
                    "policy": get_db_policies[1].get("policy"),
                }
            ],
            [
                {
                    "policyID": get_db_policies[2].get("policyID"),
                    "policy": get_db_policies[2].get("policy"),
                    "createdAt": get_db_policies[2].get("createdAt"),
                    "updatedAt": get_db_policies[2].get("updatedAt"),
                }
            ],
        ]

        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    def test_db_get_all_failure_when_invalid_query(self, mocker, get_db_instance, caplog):
        caplog.set_level(logging.ERROR)
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

        with pytest.raises(psycopg2.ProgrammingError):
            policy = get_db_instance.get_all_policy(GetAllOption())
            assert policy == {}
            assert "[E10004]Query failed" in caplog.text

    @pytest.mark.parametrize(
        "args",
        [
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "testTitle",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                    "enabled": "false",
                }
            ),  # Case for node configuration constraint
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "testTitle",
                    "policy": {"useThreshold": {"cpu": {"value": 80, "unit": "percent", "comparison": "gt"}}},
                    "enabled": "true",
                }
            ),  # Case for system operation constraint
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "testTitle",
                    "policy": {
                        "useThreshold": {
                            "virtualMedia": {
                                "value": 100,
                                "unit": "percent",
                                "comparison": "ge",
                            }
                        }
                    },
                    "enabled": True,
                }
            ),
            (
                {
                    "category": "SQLInjectionpattern-1",
                    "title": "'",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                    "enabled": "false",
                }
            ),  # Case for title single quote(SQL injection pattern)
            (
                {
                    "category": "SQLInjectionpattern-2",
                    "title": "OR 1=1",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                    "enabled": "false",
                }
            ),  # Case for title OR rule(SQL injection pattern)
            (
                {
                    "category": "SQLInjectionpattern-3",
                    "title": "--",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                    "enabled": "false",
                }
            ),  # Case for title commentout(SQL injection pattern)
            (
                {
                    "category": "SQLInjectionpattern-4",
                    "title": "UNION SELECT policyID, category, title, policy FROM policies",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                    "enabled": "false",
                }
            ),  # Case for title UNION(SQL injection pattern)
        ],
    )
    def test_db_register_success(self, mocker, args, get_db_instance, init_db_instance):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()
        id = get_db_instance.register(**args)
        content = get_db_instance.get_policy(id)

        assert len(id) == 10
        assert args.get("title") == content.get("title")
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [
            {
                "category": "nodeConfigurationPolicy",
                "title": "testTitle",
                "policy": {"test": {"cpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": "false",
            },
            {
                "category": "nodeConfigurationPolicy",
                "title": "testTitle",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": "false",
            },
        ],
    )
    def test_db_register_failure_when_invalid_query(
        self,
        mocker,
        args,
        get_db_instance,
    ):
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

        with pytest.raises(psycopg2.ProgrammingError):
            get_db_instance.register(**args)

    @pytest.mark.parametrize(
        "args",
        [
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "testTitle",
                    "policy": {"useThreshold": {"gpu": {"value": 80, "unit": "percent", "comparision": "lt"}}},
                    "enabled": "false",
                }
            ),
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "testTitle",
                    "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
                    "enabled": "true",
                }
            ),
        ],
    )
    def test_db_register_failure_when_policy_duplicate(self, mocker, args, get_db_instance, init_db_instance):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        insert_query = (
            f"INSERT INTO policies "
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
        params = [
            "123456789b",
            "nodeConfigurationPolicy",
            "NodeConfPolicy",
            json.dumps(
                {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 3}}},
            ),
            False,
            "2023-05-10T00:00:00Z",
            "2023-05-10T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        with pytest.raises(DuplicatePolicyException):
            get_db_instance.register(**args)
        cursor = init_db_instance.cursor()
        cursor.execute(query=f"Delete from policies;")

    @pytest.mark.parametrize(
        "args",
        [
            {
                "category": "systemOperationPolicy",
                "title": "testTitle",
                "policy": {"useThreshold": {"gpu": {"value": 80, "unit": "percent", "comparision": "lt"}}},
                "enabled": "false",
            }
        ],
    )
    def test_db_register_failure_when_conflict_with_update_on_register(self, mocker, args, get_db_instance):
        mock_cursor = mocker.MagicMock()

        mock_cursor.execute.return_value = 0

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor
        mocker.patch.object(
            DbAccess,
            "check_for_duplication_policy",
            side_effect=[DuplicatePolicyException("dubplicated")],
        )

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

        with pytest.raises(DuplicatePolicyException):
            get_db_instance.register(**args)

    @pytest.mark.parametrize(
        "args",
        [
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "testTitle",
                    "policy": {"useThreshold": {"gpu": {"value": 80, "unit": "percent", "comparision": "lt"}}},
                    "enabled": "false",
                }
            ),
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "testTitle",
                    "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
                    "enabled": "false",
                }
            ),
        ],
    )
    def test_db_register_failure_when_db_error_on_register(self, mocker, args, get_db_instance):
        mock_connect = mocker.Mock()
        mocker.patch("psycopg2.connect", mock_connect)

        mock_cursor = mocker.Mock()
        mock_connect.return_value.cursor.return_value = mock_cursor
        mock_cursor.rowcount = 0

        mock_cursor.execute.side_effect = [[1], [1], psycopg2.errors.UniqueViolation, [1], [1]]

        assert len(get_db_instance.register(**args)) == 10

    @pytest.mark.parametrize(
        "insert_param,update_param",
        [
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "testTitle",
                    "policy": {"hardwareConnectionsLimit": {"accelerator": {"maxNum": 5, "minNum": 1}}},
                    "enabled": False,
                },
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "testTitle",
                    "policy": {"hardwareConnectionsLimit": {"storage": {"maxNum": 5, "minNum": 1}}},
                    "force": False,
                },  # Specified pattern: All fields present
            ),
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "testTitle",
                    "policy": {"hardwareConnectionsLimit": {"accelerator": {"maxNum": 5, "minNum": 1}}},
                    "enabled": False,
                },
                {
                    "category": None,
                    "title": "testTitle",
                    "policy": {"hardwareConnectionsLimit": {"networkInterface": {"maxNum": 2, "minNum": 2}}},
                    "force": False,
                },  # Specified pattern: Only `title` and `policy`
            ),
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "testTitle",
                    "policy": {
                        "useThreshold": {
                            "accelerator": {
                                "value": 100,
                                "unit": "percent",
                                "comparision": "ge",
                            }
                        }
                    },
                    "enabled": False,
                },
                {
                    "category": None,
                    "title": None,
                    "policy": {
                        "useThreshold": {
                            "fpga": {
                                "value": 100,
                                "unit": "percent",
                                "comparision": "ge",
                            }
                        }
                    },
                    "force": False,
                },
            ),  # Specified pattern: Only `policy`
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "testTitle",
                    "policy": {"hardwareConnectionsLimit": {"accelerator": {"maxNum": 5, "minNum": 1}}},
                    "enabled": False,
                },
                {
                    "category": None,
                    "title": "testTitle",
                    "policy": None,
                    "force": False,
                },  # Specified pattern: Only `title`
            ),
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "testTitle",
                    "policy": {"hardwareConnectionsLimit": {"accelerator": {"maxNum": 5, "minNum": 1}}},
                    "enabled": True,
                },
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "testTitle",
                    "policy": {"hardwareConnectionsLimit": {"storage": {"maxNum": 5, "minNum": 1}}},
                    "force": True,
                },  # Pattern where `force = True`
            ),
        ],
    )
    def test_db_update_success(self, mocker, insert_param, update_param, get_db_instance, init_db_instance):
        mock_con = mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        id_ = get_db_instance.register(**insert_param)

        get_db_instance.update(id_, **update_param)

        assert mock_con.call_count in [2, 3]
        get_db_instance.delete(id_, True)

    def test_db_update_failure_when_invalid_query(self, mocker, get_db_instance):
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

        with pytest.raises(psycopg2.ProgrammingError):
            get_db_instance.update(None, None, None, None, False)
            assert mock_cursor.execute.call_count == 2

    @pytest.mark.parametrize(
        "args",
        [
            (
                {
                    "policyID": "123456789b",
                    "category": "systemOperationPolicy",
                    "title": "testTitle",
                    "policy": None,
                    "force": False,
                }
            ),  # Case where category is [systemOperationPolicy], and no policy is provided
            (
                {
                    "policyID": "123456789b",
                    "category": None,
                    "title": "testTitle",
                    "policy": {"useThreshold": {"cpu": {"value": 100, "unit": "percent", "comparison": "gt"}}},
                    "force": False,
                }
            ),  # Case where category is None, but the policy belongs to systemOperationPolicy
            (
                {
                    "policyID": "123456789a",
                    "category": None,
                    "title": "testTitle",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                    "force": False,
                }
            ),  # Case where category is None, but the policy belongs to nodeConfigurationPolicy
        ],
    )
    def test_db_update_failure_when_invalid_args(self, args, mocker, get_db_instance, init_db_instance):
        mock_con = mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        insert_query = (
            f"INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )
        params = [
            "123456789a",
            "systemOperationPolicy",
            "NodeConfPolicy",
            json.dumps({"useThreshold": {"dsp": {"value": 50, "unit": "percent", "comparison": "gt"}}}),
            False,
            "2023-05-10T00:00:00Z",
            "2023-05-10T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789b",
            "nodeConfigurationPolicy",
            "NodeConfPolicy",
            json.dumps(
                {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 3}}},
            ),
            False,
            "2023-05-10T00:00:00Z",
            "2023-05-10T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()

        with pytest.raises(ValidationError):
            get_db_instance.update(**args)
            assert mock_con.call_count in [1, 2]
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    def test_db_update_failure_when_state_true(self, mocker, get_db_instance, init_db_instance):
        mock_con = mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        insert_query = (
            f"INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )
        params = [
            "123456789a",
            "systemOperationPolicy",
            "NodeConfPolicy",
            json.dumps({"useThreshold": {"dsp": {"value": 50, "unit": "percent", "comparison": "gt"}}}),
            True,
            "2023-05-10T00:00:00Z",
            "2023-05-10T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()

        with pytest.raises(InvalidOperationException):
            get_db_instance.update(
                **{
                    "policyID": "123456789a",
                    "category": "nodeConfigurationPolicy",
                    "title": "testTitle",
                    "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 3}}},
                    "force": False,
                }
            )
            assert mock_con.call_count == 2
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    def test_db_update_failure_when_id_not_specified(self, mocker, get_db_instance, init_db_instance):
        mock_con = mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        with pytest.raises(IdNotFoundException):
            get_db_instance.update("987654321a", None, None, None, False)
            assert mock_con.call_count == 2

    def test_db_update_failure_when_conflict_with_existing_policy(self, mocker, get_db_instance, init_db_instance):
        mock_con = mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        insert_query = (
            f"INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )
        params = [
            "d8eceb14da",
            "nodeConfigurationPolicy",
            "NodeConfPolicy",
            json.dumps({"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}}),
            True,
            "2023-05-10T00:00:00Z",
            "2023-05-10T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789a",
            "systemOperationPolicy",
            "NodeConfPolicy",
            json.dumps({"useThreshold": {"dsp": {"value": 50, "unit": "percent", "comparison": "gt"}}}),
            False,
            "2023-05-10T00:00:00Z",
            "2023-05-10T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()

        with pytest.raises(DuplicatePolicyException):
            get_db_instance.update(
                **{
                    "policyID": "123456789a",
                    "category": "nodeConfigurationPolicy",
                    "title": "testTitle",
                    "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
                    "force": False,
                }
            )
            assert mock_con.call_count == 2

        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    def test_db_update_failure_when_conflict_with_update_on_register(self, mocker, get_db_instance, get_db_policies):
        mock_cursor = mocker.MagicMock()
        policy = get_db_policies[0]
        policy["createdAt"] = datetime.datetime.strptime(policy["createdAt"], "%Y-%m-%dT%H:%M:%SZ")
        policy["updatedAt"] = datetime.datetime.strptime(policy["updatedAt"], "%Y-%m-%dT%H:%M:%SZ")
        mock_cursor.fetchone.side_effect = [policy]

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

        with pytest.raises(DuplicatePolicyException):
            get_db_instance.update(
                **{
                    "policyID": "a21bc21587",
                    "category": "nodeConfigurationPolicy",
                    "title": "testTitle",
                    "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                    "force": False,
                }
            )
            assert mock_cursor.fetchone.call_count == 1

    @pytest.mark.parametrize(
        "args",
        [
            ({"enableIDList": ["123456789a"], "disableIDList": ["d8eceb14da"]}),
            ({"enableIDList": ["123456789a"], "disableIDList": []}),
            ({"disableIDList": ["d8eceb14da"], "enableIDList": []}),
        ],
    )
    def test_db_change_enabled_success(self, mocker, args, get_db_instance, init_db_instance):
        mock_connect = mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        insert_query = (
            f"INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )
        params = [
            "d8eceb14da",
            "nodeConfigurationPolicy",
            "NodeConfPolicy",
            json.dumps({"hardwareConnectionsLimit": {"accelerator": {"maxNum": 5, "minNum": 1}}}),
            True,
            "2023-05-10T00:00:00Z",
            "2023-05-10T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()

        params = [
            "123456789a",
            "systemOperationPolicy",
            "NodeConfPolicy",
            json.dumps(
                {
                    "useThreshold": {
                        "accelerator": {
                            "value": 50,
                            "unit": "percent",
                            "comparison": "gt",
                        }
                    }
                }
            ),
            False,
            "2023-05-10T00:00:00Z",
            "2023-05-10T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()

        get_db_instance.change_enabled(**args)

        assert mock_connect.call_count == 1
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [
            ({"enableIDList": ["a21bc21587"], "disableIDList": []}),
            ({"disableIDList": ["b36fc21588"], "enableIDList": []}),
            (
                {
                    "disableIDList": ["123456789b", "123456789d", "cef8ec7ac"],
                    "enableIDList": [],
                }
            ),
        ],
    )
    def test_db_change_enabled_failure_when_nonexistent_id_specified(
        self, mocker, args, get_db_instance, init_db_instance
    ):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        insert_query = (
            f"INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )
        params = [
            "123456789b",
            "nodeConfigurationPolicy",
            "NodeConfPolicy",
            json.dumps({"hardwareConnectionsLimit": {"accelerator": {"maxNum": 5, "minNum": 1}}}),
            True,
            "2023-05-10T00:00:00Z",
            "2023-05-10T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()

        with pytest.raises(UnmatchIdException):
            get_db_instance.change_enabled(**args)
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    def test_db_change_enabled_failure_when_invalid_query(
        self,
        mocker,
        get_db_instance,
    ):
        err_func = psycopg2.ProgrammingError
        err_func.pgcode = "42601"
        mock_cursor = mocker.MagicMock()
        mock_cursor.rowcount = 1
        err = [None, None, err_func]

        mock_cursor.execute.side_effect = err

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

        with pytest.raises(psycopg2.ProgrammingError):
            get_db_instance.change_enabled(["a21bc21587"], None)
            assert mock_cursor.execute.call_count == 1

    def test_db_change_enabled_rollback_occurs_when_query_error_on_disable(
        self,
        mocker,
        get_db_instance,
    ):
        mock_cursor = mocker.MagicMock()
        mock_cursor.rowcount = 1
        err = psycopg2.ProgrammingError
        err.pgcode = "42601"
        # Mock to trigger an error during a disable update
        mock_cursor.execute.side_effect = [1, 1, 1, err]

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

        with pytest.raises(psycopg2.ProgrammingError):
            get_db_instance.change_enabled(["a21bc21587"], ["a21bc21587"])
            assert mock_cursor.execute.call_count == 1

    @pytest.mark.parametrize(
        "insert_param,param",
        [
            (
                {
                    "category": "nodeConfigurationPolicy",
                    "title": "testTitle",
                    "policy": {"hardwareConnectionsLimit": {"accelerator": {"maxNum": 5, "minNum": 1}}},
                    "enabled": False,
                },
                False,
            ),  # Case force = False
            (
                {
                    "category": "systemOperationPolicy",
                    "title": "testTitle",
                    "policy": {
                        "useThreshold": {
                            "accelerator": {
                                "value": 80,
                                "unit": "percent",
                                "comparison": "gt",
                            }
                        }
                    },
                    "enabled": True,
                },
                True,
            ),  # Case force = True
        ],
    )
    def test_db_delete_success(self, mocker, insert_param, param, get_db_instance, init_db_instance):
        mock_con = mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)
        id = get_db_instance.register(**insert_param)

        get_db_instance.delete(id, param)
        assert mock_con.call_count == 4

    def test_db_delete_failure_when_invalid_query(self, mocker, get_db_instance):
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

        with pytest.raises(psycopg2.ProgrammingError):
            policy = get_db_instance.delete(None, False)
            assert policy == {}

    def test_db_delete_failure_when_nonexistent_id(self, mocker, get_db_instance, init_db_instance):
        mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        with pytest.raises(IdNotFoundException):
            policy = get_db_instance.delete("987654321a", False)
            assert policy == {}

    def test_db_delete_failure_when_state_true(self, mocker, get_db_instance, init_db_instance):
        mock_con = mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)
        cursor = init_db_instance.cursor()
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        insert_query = (
            f"INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )
        params = [
            "d8eceb14da",
            "nodeConfigurationPolicy",
            "NodeConfPolicy",
            json.dumps({"hardwareConnectionsLimit": {"accelerator": {"maxNum": 5, "minNum": 1}}}),
            True,
            "2023-05-10T00:00:00Z",
            "2023-05-10T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()

        with pytest.raises(InvalidOperationException):
            get_db_instance.delete("d8eceb14da", False)
            assert mock_con.call_count == 2
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [{"category": ["all"], "enabled": "all"}],
    )
    def test_db_common_success(self, mocker, args, get_db_instance, init_db_instance, get_db_policies):
        mock_conn = mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        insert_query = (
            f"INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )

        params = [
            "123456789a",
            "nodeConfigurationPolicy",
            "test",
            json.dumps({"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}}),
            False,
            "2023-09-21T00:00:00Z",
            "2023-09-21T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789c",
            "nodeConfigurationPolicy",
            "test",
            json.dumps(
                {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
            ),
            True,
            "2023-09-21T00:00:00Z",
            "2023-09-21T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789b",
            "systemOperationPolicy",
            "test",
            json.dumps({"useThreshold": {"gpu": {"value": 80, "unit": "percent", "comparision": "gt"}}}),
            False,
            "2023-09-28T00:00:00Z",
            "2023-09-28T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789d",
            "systemOperationPolicy",
            "test",
            json.dumps({"useThreshold": {"dsp": {"value": 80, "unit": "percent", "comparision": "lt"}}}),
            True,
            "2023-09-28T00:00:00Z",
            "2023-09-28T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()

        result = get_db_instance.get_policy_count(GetAllOption(**args))
        assert "totalCount" in result.keys()
        assert result["totalCount"] == 4
        assert mock_conn.call_count == 1
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

    @pytest.mark.parametrize(
        "args",
        [{"device": "cpu", "subCategory": "hardwareConnectionsLimit"}],
    )
    def test_db_common_retrieve_count_when_specified_parameters(
        self, mocker, args, get_db_instance, init_db_instance, get_db_policies
    ):
        mock_conn = mocker.patch("psycopg2.connect", return_value=init_db_instance)
        mocker.patch.object(DbAccess, "close", return_value=None)

        cursor = init_db_instance.cursor()
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

        insert_query = (
            f"INSERT INTO policies "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s)"
        )

        params = [
            "123456789a",
            "nodeConfigurationPolicy",
            "test",
            json.dumps({"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}}),
            False,
            "2023-09-21T00:00:00Z",
            "2023-09-21T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789c",
            "nodeConfigurationPolicy",
            "test",
            json.dumps(
                {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
            ),
            True,
            "2023-09-21T00:00:00Z",
            "2023-09-21T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789b",
            "systemOperationPolicy",
            "test",
            json.dumps({"useThreshold": {"gpu": {"value": 80, "unit": "percent", "comparision": "gt"}}}),
            False,
            "2023-09-28T00:00:00Z",
            "2023-09-28T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()
        params = [
            "123456789d",
            "systemOperationPolicy",
            "test",
            json.dumps({"useThreshold": {"dsp": {"value": 80, "unit": "percent", "comparision": "lt"}}}),
            True,
            "2023-09-28T00:00:00Z",
            "2023-09-28T00:00:00Z",
        ]
        cursor.execute(query=insert_query, vars=params)
        init_db_instance.commit()

        result = get_db_instance.get_policy_count(GetAllOption(**args))
        assert "totalCount" in result.keys()
        assert result["totalCount"] == 1
        assert mock_conn.call_count == 1
        cursor.execute(query=f"Delete from policies;")
        init_db_instance.commit()

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
    def test_db_common_failure_when_db_connection_failed(self, mocker, get_db_instance, caplog, error):
        # arrange
        mocker.patch("logging.config.dictConfig")
        caplog.set_level(INFO)
        mocker.patch("psycopg2.connect").side_effect = error
        mocker.patch("time.sleep", return_value=None)
        with pytest.raises(psycopg2.OperationalError):
            logger = logging.getLogger("logger.py")
            logger.handlers.clear()
            logger.addHandler(caplog.handler)
            logger.setLevel(logging.DEBUG)
            get_db_instance.open_db_connection()
            assert "Could not connect to PolicyDB.Reconnecting count: 1" in caplog.text
            assert "Could not connect to PolicyDB.Reconnecting count: 2" in caplog.text
            assert "Could not connect to PolicyDB.Reconnecting count: 3" in caplog.text
            assert "Could not connect to PolicyDB.Reconnecting count: 4" in caplog.text
            assert "Could not connect to PolicyDB.Reconnecting count: 5" in caplog.text
            assert "[E10003]Could not connect to PolicyDB" in caplog.text

    @pytest.mark.parametrize(
        "args",
        [
            {
                "category": "nodeConfigurationPolicy",
                "title": "testTitle",
                "policy": {"test": {"cpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": "false",
            },
            {
                "category": "nodeConfigurationPolicy",
                "title": "testTitle",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
                "enabled": "false",
            },
        ],
    )
    def test_db_register_failure_when_serialization_failue_during_registration(
        self,
        mocker,
        args,
        get_db_instance,
    ):
        err_func = err = psycopg2.errors.SerializationFailure
        err_func.pgcode = "40001"
        mock_cursor = mocker.MagicMock()
        mock_cursor.rowcount = 0
        err = [None, err_func, None, None]
        mock_cursor.execute.side_effect = err

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

        policyID = get_db_instance.register(**args)
        assert len(policyID) == 10

    def test_db_change_enabled_failure_when_serialization_failue_during_change_state(
        self,
        mocker,
        get_db_instance,
    ):
        err_func = psycopg2.errors.SerializationFailure
        err_func.pgcode = "40001"
        mock_cursor = mocker.MagicMock()
        mock_cursor.rowcount = 1
        mock_cursor.commit = True
        err = [None, err_func, None, None]
        mock_cursor.execute.side_effect = err

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

        get_db_instance.change_enabled(["a21bc21587"], None)
        assert mock_cursor.execute.call_count == 4

    def test_db_update_failure_when_serialization_failue_during_update(self, mocker, get_db_instance, docker_services):
        err_func = err = psycopg2.errors.SerializationFailure
        err_func.pgcode = "40001"
        mock_cursor = mocker.MagicMock()
        type(mock_cursor).rowcount = mocker.PropertyMock(side_effect=[0, 1])
        mock_cursor.commit = True
        err = [None, None, err_func, None]
        mock_cursor.execute.side_effect = err

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)
        mocker.patch.object(DbAccess, "get_policy", return_value=None)
        mocker.patch.object(DbAccess, "_check_update_result", return_value=None)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

        get_db_instance.update(
            **{
                "policyID": "d8eceb14da",
                "category": "nodeConfigurationPolicy",
                "title": "testTitle",
                "policy": {"hardwareConnectionsLimit": {"cpu": {"maxNum": 10, "minNum": 1}}},
                "force": False,
            }
        )
        assert mock_cursor.execute.call_count == 4

    @pytest.mark.parametrize(
        "args",
        [
            (
                {
                    "policy_list": [
                        {
                            "policyID": "123456789a",
                            "category": "nodeConfigurationPolicy",
                            "title": "test",
                            "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
                            "enabled": False,
                        },
                        {
                            "policyID": "123456789c",
                            "category": "nodeConfigurationPolicy",
                            "title": "test",
                            "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
                            "enabled": True,
                        },
                    ]
                }
            ),  #  Case where numerical constraint conditions are registered successfully
        ],
    )
    def test_db_import_failure_when_serialization_failue_during_import(
        self, mocker, args, get_db_instance, docker_services
    ):
        err_func = err = psycopg2.errors.SerializationFailure
        err_func.pgcode = "40001"
        mock_cursor = mocker.MagicMock()
        mock_cursor.rowcount = 0
        # fmt: off
        err = [
            None, None, None, None, 
            err_func, None, err_func ,None, err_func, None, err_func, None, err_func, None,  err_func, None,
            None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None,
        ]
        # fmt: on
        mock_cursor.execute.side_effect = err

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)
        import_detail = get_db_instance.import_policy(**args)
        assert len(import_detail) == len(args["policy_list"])
        message_list = [
            "completed",
            "completed",
        ]
        for detail in import_detail:
            assert detail["message"] in message_list

    @pytest.mark.parametrize(
        "args",
        [
            (
                {
                    "policy_list": [
                        {
                            "policyID": "123456789a",
                            "category": "nodeConfigurationPolicy",
                            "title": "test",
                            "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
                            "enabled": False,
                        },
                        {
                            "policyID": "123456789c",
                            "category": "nodeConfigurationPolicy",
                            "title": "test",
                            "policy": {"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}},
                            "enabled": True,
                        },
                    ]
                }
            ),  #  Case where numerical constraint conditions are registered successfully
        ],
    )
    def test_db_import_failure_when_serialization_failue_during_commit_import(
        self, mocker, args, get_db_instance, docker_services
    ):
        err_func = err = psycopg2.errors.SerializationFailure
        err_func.pgcode = "40001"
        mock_cursor = mocker.MagicMock()
        mock_cursor.rowcount = 0

        # fmt: off
        err = [
            None,
            None, None, None, None, None, None, None,
            None, None, None, None, None, None,
            None,
            None, None, None, None, None, None, None,
            None, None, None, None, None, None,
        ]
        # fmt: on
        mock_cursor.execute.side_effect = err

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor
        type(mock_connection).commit = mocker.PropertyMock(
            side_effect=[psycopg2.errors.SerializationFailure, mock_connection]
        )

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)
        import_detail = get_db_instance.import_policy(**args)
        assert len(import_detail) == len(args["policy_list"])
        message_list = [
            "completed",
            "completed",
        ]
        for detail in import_detail:
            assert detail["message"] in message_list

    @pytest.mark.parametrize(
        "args",
        [{"policyID": "123456789a"}],
    )
    def test_db_get_failure_when_serialization_failue_during_get(self, mocker, args, get_db_instance, get_db_policies):
        err_func = psycopg2.errors.SerializationFailure
        err_func.pgcode = "40001"
        mock_cursor = mocker.MagicMock()
        err = [None, err_func, None]
        mock_cursor.execute.side_effect = err
        mock_cursor.fetchone.side_effect = get_db_policies[0]

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)
        mocker.patch.object(DbAccess, "_normalize_db_result", return_value=get_db_policies[0])

        policy = get_db_instance.get_policy(**args)
        assert policy == {
            "policyID": "123456789b",
            "category": "systemOperationPolicy",
            "title": "test",
            "policy": {"useThreshold": {"gpu": {"value": 80, "unit": "percent", "comparision": "gt"}}},
            "enabled": False,
            "createdAt": "2023-09-28T00:00:00Z",
            "updatedAt": "2023-09-28T00:00:00Z",
        }

    @pytest.mark.parametrize(
        "args",
        [
            ({"category": ["all"], "enabled": "all"}),
        ],
    )
    def test_db_get_all_failure_when_serialization_failue_during_get_all(
        self, mocker, args, get_db_instance, get_db_policies
    ):
        err_func = psycopg2.errors.SerializationFailure
        err_func.pgcode = "40001"
        mock_cursor = mocker.MagicMock()
        err = [None, err_func, None]
        mock_cursor.execute.side_effect = err
        mock_cursor.fetchall.side_effect = [[1]]

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)
        mocker.patch.object(DbAccess, "_normalize_db_result", return_value=get_db_policies[0])

        policeis = get_db_instance.get_all_policy(GetAllOption(**args))
        assert policeis == {"count": 1, "policies": [get_db_policies[0]]}

    def test_db_export_failure_when_serialization_failue_during_export(self, mocker, get_db_instance, get_db_policies):
        err_func = psycopg2.errors.SerializationFailure
        err_func.pgcode = "40001"
        mock_cursor = mocker.MagicMock()
        err = [None, err_func, None]
        mock_cursor.execute.side_effect = err
        mock_cursor.fetchall.side_effect = [[1]]

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)
        mocker.patch.object(DbAccess, "_normalize_db_result", return_value=get_db_policies[0])

        policeis = get_db_instance.export()
        assert policeis == {"exportedCount": 1, "policies": [get_db_policies[0]]}

    def test_db_delete_failure_when_serialization_failue_during_delete(self, mocker, get_db_instance):
        err_func = psycopg2.errors.SerializationFailure
        err_func.pgcode = "40001"
        mock_cursor = mocker.MagicMock()
        err = [None, err_func, None]
        mock_cursor.execute.side_effect = err

        mock_connection = mocker.MagicMock()
        mock_connection.cursor.return_value = mock_cursor

        mocker.patch("psycopg2.connect", return_value=mock_connection)
        mocker.patch.object(DbAccess, "get_policy", side_effect=[None, IdNotFoundException("dummy message")])

        mock_dictcursor = mocker.MagicMock()
        mock_dictcursor.__enter__.return_value = mock_cursor
        mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

        get_db_instance.delete("123456789a", False)
        assert mock_cursor.execute.call_count == 3
