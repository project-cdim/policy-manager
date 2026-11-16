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
"""plugin Base Class"""

# flake8: noqa
import os
import sys
from abc import ABC, abstractmethod

from jsonschema import ValidationError, validate

sys.path.append(os.path.abspath("."))

# pylint: disable=wrong-import-position
from policymanager.common.const import PolicyValue
from policymanager.common.schemas import combination_schema


class BasePolicyPlugin(ABC):
    """Base Plugins class"""

    def __init__(self, db_manager) -> None:
        self.db_manager = db_manager

    @abstractmethod
    def _validate_inner_ctx(self, inner_data_dict: dict) -> None:
        pass  # pragma: no cover

    @abstractmethod
    def _is_valid_sub_category(self, sub_category: str) -> bool:
        pass  # pragma: no cover

    def validate_category_policy(self, category: str, policy: dict, policyID: str):  # pylint: disable=C0103
        """validate category and policy

        Args:
            category (str): policy category
            policy (dict): policy
            policyID (str): policy ID
        Raises:
            ValidationError: ValidationError
            IdNotFoundException: PolicyID not found  error
        """

        db_policy = self.db_manager.get_policy(policyID)

        # conditions retrieved from the database for consistency checking
        category = category or db_policy["category"]
        policy = policy or db_policy["policy"]

        try:
            validate(
                {"category": category, "policy": list(policy.keys())},
                combination_schema.combination_schema,
            )
        except ValidationError as err:
            msg = (
                "There is a contradiction in values set for category and policy."
                + "If register, please confirm category and policy you have set."
                + "If update, please confirm that category and policy "
                + "you have set do not contradict those that are already registered"
            )
            raise ValidationError(msg) from err

    def _validate_device(self, inner_data_dict: dict) -> None:
        """validate policy to device key

        Args:
            inner_data_dict (dict): policy
        """

        if isinstance(inner_data_dict, dict) is not True:
            raise ValidationError("subCategory is not of type 'dict'")

        # fmt: off
        key_list = [
            "cpu", "memory", "storage", "gpu", "fpga", "accelerator", "dsp",
            "virtualMedia", "graphicController", "networkInterface"
        ]
        # fmt: on
        device_upper_dict = {key.upper(): key for key in key_list}

        inner_key = [key.upper() for key in inner_data_dict.keys()]
        diff_list = set(inner_key) - set(map(lambda key: key.upper(), key_list))
        if len(diff_list) > 0:
            msg = (
                "Unexpected device type has been specified."
                + "Select any of ['cpu', 'memory', 'storage', 'gpu', 'fpga', 'accelerator',"
                + " 'dsp', 'virtualMedia', 'graphicController', 'networkInterface']"
            )
            raise ValidationError(msg)
        for key in inner_data_dict.copy().keys():
            inner_data_dict[device_upper_dict[key.upper()]] = inner_data_dict.pop(key)
        return inner_data_dict

    def validate_policy(self, policy: dict) -> bool:
        """validate systemOperationPolicy or nodeConfigurationPolicy

        Args:
            policy (dict): nodeConfigurationPolicy or systemOperationPolicy

        Raises:
            ValidationError: ValidationError
        """
        # If there is no policy during the update, validation is not required.
        # It is assumed that the check for required keys is performed at a higher level.
        if policy is None:
            return True

        inner_data_dict = next(iter(policy.values()))
        # Extracting all SubCategories of Policy defined in Enum and assigning them to variables
        sub_categories_list = list(PolicyValue.__dict__.get("_value2member_map_").keys())
        current_sub_category = list(policy.keys())[0]

        # Check if the defined SubCategory matches the SubCategory in the provided Policy.
        # Enter the if statement if even one matches.
        if current_sub_category not in sub_categories_list:
            msg = (
                "Your definition of policy is incorrect." + "Select one of ['hardwareConnectionsLimit', 'useThreshold']"
            )
            raise ValidationError(msg)

        if self._is_valid_sub_category(current_sub_category):
            policy[current_sub_category] = self._validate_device(inner_data_dict)
            self._validate_inner_ctx(inner_data_dict)
            return True

        return False

    def has_not_duplication(self, policy: dict, policyID: str = None) -> bool:  # pylint: disable=C0103
        """Check for duplication of policy
        Args:
            policy (dict): Constraint's policy
            policyID (str, optional): Define this parameter while using the update function.
            Defaults to None

        Raises:
            DuplicatePolicyException: Occurs when the policy is duplicated with a registered policy
        """
        if policy is None:
            return
        self.db_manager.open_db_connection()

        self.db_manager.check_for_duplication_policy(policy, policyID)

        self.db_manager.close()
