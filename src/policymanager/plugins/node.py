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
"""nodeConfigurationPolicy plugin"""

from dataclasses import dataclass

from jsonschema import ValidationError, validate

from policymanager.common.const import PolicyValue
from policymanager.plugins.base import BasePolicyPlugin

# pylint: skip-file
# Hardware connection limit
nodeconf_schema = {
    "type": "object",
    "required": ["maxNum", "minNum"],
    "properties": {
        "maxNum": {
            "type": "integer",
            "minimum": 1,
        },
        "minNum": {
            "type": "integer",
            "minimum": 1,
        },
    },
}


@dataclass
class hardwareConnectionsLimit:
    """Data class for hardwareConnectionsLimit"""

    maxNum: int
    minNum: int


class NodePolicyPlugin(BasePolicyPlugin):
    """NodeConfigurationPolicy plugin class"""

    def _validate_inner_ctx(self, inner_data_dict) -> None:
        """validate nodeConfigurationPolicy

        Args:
            inner_data_dict (dict): nodeConfigurationPolicy
        """
        for value in inner_data_dict.values():
            validate(value, nodeconf_schema)
            hardware_limit = hardwareConnectionsLimit(**value)
            if hardware_limit.minNum > hardware_limit.maxNum:
                raise ValidationError("MinNum exceeds maxNum.Please specify minNum is smaller than maxNum")

    def _is_valid_sub_category(self, sub_category: str):
        """Cheking for subCategory type of policy

        Args:
            sub_category (str): Policy's subCategory

        Returns:
            bool: True if it is Node's subCategory. Otherwise False
        """
        return sub_category == PolicyValue.NODECONF
