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

import importlib

import psycopg2
import pytest
from jsonschema import ValidationError

from policymanager.common.custom_exceptions import PluginLoadException
from policymanager.common.db import DbAccess
from policymanager.common.logger import Logger, initialize_log
from policymanager.common.plugin import Plugin
from policymanager.plugins.base import BasePolicyPlugin


@pytest.fixture
def get_nodepolicy():
    return {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}}


@pytest.fixture
def get_systempolicy():
    return {"useThreshold": {"cpu": {"value": 5, "unit": "percent", "comparison": "lt"}}}


@pytest.fixture
def get_db_instanse():
    logger = initialize_log()
    return DbAccess(logger)


def test_plugin_plugin_is_loading_when_matching_name(get_db_instanse):
    valid_plugins = ["policymanager.plugins.node", "policymanager.plugins.system"]
    loader = Plugin(BasePolicyPlugin, get_db_instanse)
    loaded_plugin_names = loader._get_plugin_names()

    for plugin_name in loaded_plugin_names:
        assert plugin_name in valid_plugins


def test_plugin_load_successful(get_db_instanse):
    loader = Plugin(BasePolicyPlugin, get_db_instanse)

    # check load plaguin
    assert len(loader.plugins) == 2


def test_plugin_failure_when_plugin_load_failed(mocker, get_db_instanse):
    mocker.patch.object(importlib, "import_module", side_effect=[Exception])

    with pytest.raises(PluginLoadException) as err:
        loader = Plugin(BasePolicyPlugin, get_db_instanse)

    assert err.value.message == "Failed to load plugin"


def test_plugin_failure_when_plugin_not_found(mocker, get_db_instanse):
    mocker.patch.object(Plugin, "_get_plugin_names", return_value=[])

    with pytest.raises(ValidationError) as err:
        loader = Plugin(BasePolicyPlugin, get_db_instanse)

    assert err.value.message == "Failed to load plugins in specified category"


def test_plugin_success_when_node_constraint_plugin(get_nodepolicy, get_db_instanse):

    loader = Plugin(BasePolicyPlugin, get_db_instanse)
    loader.validate_policy(get_nodepolicy)

    assert len(loader.objs) >= 1


def test_plugin_success_when_system_constraint_plugin(get_systempolicy, get_db_instanse):

    loader = Plugin(BasePolicyPlugin, get_db_instanse)
    loader.validate_policy(get_systempolicy)

    assert len(loader.objs) >= 1


def test_plugin_failure_when_subcategory_conflict(get_nodepolicy, get_db_instanse):
    # mocker.patch.object(BasePolicyPlugin, "validate_policy", return_value=False)
    loader = Plugin(BasePolicyPlugin, get_db_instanse)
    tmp_objs = loader.objs.copy()
    for i, obj in enumerate(tmp_objs):
        if obj.__module__.endswith("node"):
            del loader.objs[i]
    with pytest.raises(ValidationError) as err:
        loader.validate_policy(get_nodepolicy)
    assert err.value.message.startswith("There is a contradiction in values set for category and policy")
    assert len(loader.objs) == 1


def test_plugin_success_when_duplicate_constraint_node(get_nodepolicy, mocker, get_db_instanse):
    mocker.patch.object(DbAccess, "close", return_value=None)
    mock_cursor = mocker.MagicMock()
    mock_cursor.rowcount = 0

    mock_connection = mocker.MagicMock()
    mock_connection.cursor.return_value = mock_cursor

    mocker.patch("psycopg2.connect", return_value=mock_connection)

    mock_dictcursor = mocker.MagicMock()
    mock_dictcursor.__enter__.return_value = mock_cursor
    mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

    loader = Plugin(BasePolicyPlugin, get_db_instanse)
    loader.validate_dupliction(get_nodepolicy)

    assert len(loader.objs) >= 1


def test_plugin_success_when_duplicate_constraint_system(get_systempolicy, mocker, get_db_instanse):
    mocker.patch.object(DbAccess, "close", return_value=None)
    mock_cursor = mocker.MagicMock()
    mock_cursor.rowcount = 0

    mock_connection = mocker.MagicMock()
    mock_connection.cursor.return_value = mock_cursor

    mocker.patch("psycopg2.connect", return_value=mock_connection)

    mock_dictcursor = mocker.MagicMock()
    mock_dictcursor.__enter__.return_value = mock_cursor
    mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

    loader = Plugin(BasePolicyPlugin, get_db_instanse)
    loader.validate_dupliction(get_systempolicy)

    assert len(loader.objs) >= 1


@pytest.mark.parametrize(
    ("policyID", "category", "policy"),
    [
        (
            "123456789a",
            "nodeConfigurationPolicy",
            {
                "hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}
            },  # Case where both category and policy are specified
        ),
        ("123456789a", "nodeConfigurationPolicy", None),  # Case where the policy is not specified
        (
            "123456789a",
            None,
            {"hardwareConnectionsLimit": {"cpu": {"maxNum": 5, "minNum": 1}}},
        ),  # Case where the category is not specified
    ],
)
def test_plugin_success_when_conflicting_constraint_node(policyID, category, policy, mocker, get_db_instanse):
    mocker.patch.object(DbAccess, "close", return_value=None)
    mock_cursor = mocker.MagicMock()
    mock_cursor.fetchone = lambda: {
        "policy_id": "123456789b",
        "category": "nodeConfigurationPolicy",
        "policy": {"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}},
    }

    mock_connection = mocker.MagicMock()
    mock_connection.cursor.return_value = mock_cursor

    mocker.patch("psycopg2.connect", return_value=mock_connection)

    mock_dictcursor = mocker.MagicMock()
    mock_dictcursor.__enter__.return_value = mock_cursor
    mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

    loader = Plugin(BasePolicyPlugin, get_db_instanse)
    loader.validate_contradiction(policyID, policy, category)

    assert len(loader.objs) >= 2


@pytest.mark.parametrize(
    ("policyID", "category", "policy"),
    [
        (
            "123456789a",
            "systemOperationPolicy",
            {
                "useThreshold": {"cpu": {"value": 5, "unit": "percent", "comparison": "lt"}}
            },  # Case where both category and policy are specified
        ),
        ("123456789a", "systemOperationPolicy", None),  # Case where the policy is not specified
        (
            "123456789a",
            None,
            {"useThreshold": {"cpu": {"value": 5, "unit": "percent", "comparison": "lt"}}},
        ),  # Case where the category is not specified
    ],
)
def test_plugin_success_when_conflicting_constraint_system(policyID, category, policy, mocker, get_db_instanse):
    mocker.patch.object(DbAccess, "close", return_value=None)
    mock_cursor = mocker.MagicMock()
    mock_cursor.fetchone = lambda: {
        "policy_id": "123456789b",
        "category": "systemOperationPolicy",
        "policy": {"useThreshold": {"gpu": {"value": 5, "unit": "percent", "comparison": "lt"}}},
    }

    mock_connection = mocker.MagicMock()
    mock_connection.cursor.return_value = mock_cursor

    mocker.patch("psycopg2.connect", return_value=mock_connection)

    mock_dictcursor = mocker.MagicMock()
    mock_dictcursor.__enter__.return_value = mock_cursor
    mocker.patch.object(psycopg2.extras, "DictCursor", return_value=mock_dictcursor)

    loader = Plugin(BasePolicyPlugin, get_db_instanse)
    loader.validate_contradiction(policyID, policy, category)

    assert len(loader.objs) >= 2
