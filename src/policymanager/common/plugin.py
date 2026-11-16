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
"""Plugin Loader module"""

# flake8: noqa
import importlib
import os
import sys
from enum import StrEnum, _simple_enum

from jsonschema import ValidationError

sys.path.append(os.path.abspath("."))
# pylint: disable=wrong-import-position
from policymanager.common.custom_exceptions import PluginLoadException


@_simple_enum(StrEnum)
class PluginMethods:
    """Plugin Methods value"""

    VALIDATE_POLICY_METHOD = "validate_policy"
    VALIDATE_CATEGORY_POLICY_METHOD = "validate_category_policy"
    HAS_NOT_DUPLICATION_METHOD = "has_not_duplication"


class Plugin:
    """
    Dynamically import Python scripts (*.py) in plugins directory.
    """

    PLUGINS_DIR = "plugins"

    def __init__(self, base: type, db_manager):
        self.base_class: type = base
        self.base_class_name: str = base.__name__
        self.plugins: list = []
        self.objs: list = []
        self.instance_names: set = set()
        self.db_manager = db_manager
        self._import_plugins()

    def _get_plugin_names(self):
        """
        Return list of module names in the plugins directory
        """
        exclude_plugin_list: list = ["__init__.py", "base.py"]
        module_names: list = []

        current_directory = os.path.dirname(os.path.abspath(__file__))
        parent_directory = os.path.dirname(current_directory)
        plugin_directory = os.path.join(parent_directory, self.PLUGINS_DIR)

        for file in os.listdir(plugin_directory):
            if file.endswith(".py") and file not in exclude_plugin_list:
                module_names.append("policymanager." + self.PLUGINS_DIR + "." + os.path.splitext(file)[0])

        return module_names

    def _import_plugins(self):
        """Import modules in the plugins directory

        Raises:
            PluginLoadException: Occurs when could not load any plugin
        """
        try:
            for module_name in self._get_plugin_names():
                module = importlib.import_module(module_name)
                # Assign only modules inheriting from the base class of the plugin.
                plugin = getattr(module, self.base_class_name).__subclasses__()
                self.plugins += plugin

            # Generate an object of the plugin
            self.plugins = set(self.plugins)
            self._init_objs()
        except ValidationError as err:
            raise err
        except Exception as err:
            raise PluginLoadException("Failed to load plugin") from err

    def _init_objs(self):
        """Create class instances and return as a list of objects

        Raises:
            ValidationError: Occurs if no plugin has been loaded
        """
        if len(self.plugins) == 0:
            raise ValidationError("Failed to load plugins in specified category")

        # Generate an instance of the loaded plugin.
        for p in self.plugins:
            self.objs.append(p(self.db_manager))

    def _call_method(self, method_name: PluginMethods, **kwargs):
        """Call method of plugins

        Args:
            method_name (PluginMethods): Call base class methods
        """
        method_result_list = []
        for obj in self.objs:
            method = getattr(obj, method_name)
            # Criteria for executing the appropriate plugin
            if method_name == method_name.VALIDATE_POLICY_METHOD:
                method_result_list.append(method(**kwargs))
            else:
                method(**kwargs)
                break

        # If there is no corresponding plugin, the following conditions will be met.
        if len(method_result_list) > 0 and any(method_result_list) is not True:
            msg = (
                "There is a contradiction in values set for category and policy."
                + "If register, please confirm category and policy you have set."
                + "If update, please confirm that category and policy "
                + "you have set do not contradict those that are already registered"
            )
            raise ValidationError(msg)

    def validate_policy(self, policy: dict):
        """Validate policy with plugin

        Args:
            policy (dict): Constraint policy
        Raises:
            ValidationError: ValidationError
        """
        self._call_method(PluginMethods.VALIDATE_POLICY_METHOD, policy=policy)

    def validate_contradiction(self, policyID: str, policy: dict = None, category: str = None):  # pylint: disable=C0103
        """cheiking for condtradiction with plugin

        Args:
            policyID (str): policy ID
            policy (dict): Contraints Policy. Defaults to None.
            category (str): Constraints Category. Defaults to None.
        Raises:
            ValidationError: ValidationError
            IdNotFoundException: PolicyID not found  error
        """
        self._call_method(
            PluginMethods.VALIDATE_CATEGORY_POLICY_METHOD,
            policyID=policyID,
            category=category,
            policy=policy,
        )

    def validate_dupliction(self, policy: dict, policyID: str = None):  # pylint: disable=C0103
        """Validate policy duplication with plugin

        Args:
            policy (dict): Constraint policy
            policyID (str, optional): Define this parameter while using the update function.
            Defaults to None

        Raises:
            DuplicatePolicyException: Occurs when the policy is duplicated with a registered policy
        """
        self._call_method(PluginMethods.HAS_NOT_DUPLICATION_METHOD, policy=policy, policyID=policyID)
