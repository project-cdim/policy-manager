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
"""systemOperationPolicy plugin"""

from dataclasses import dataclass

from jsonschema import ValidationError, validate

from policymanager.common.const import PolicyValue, SysConfComp, SysConfValue
from policymanager.plugins.base import BasePolicyPlugin

# pylint: skip-file
# Threshold to be used
# Inequality symbols for the threshold
# gt: greater than the threshold, lt: less than the threshold
# le: less than or equal to the threshold, le: greater than or equal to the threshold
systemope_schema = {
    "type": "object",
    "required": ["value", "unit", "comparison"],
    "properties": {
        "value": {
            "type": "integer",
            "minimum": 0,
            "maximum": 100,
        },
        "unit": {
            "type": "string",
            "enum": ["percent"],
        },
        "comparison": {
            "type": "string",
            "enum": ["gt", "lt", "le", "ge"],  # noqa: E231
        },
    },
}


@dataclass
class useThreshold:
    """Data class for useThreshold"""

    value: int
    unit: str
    comparison: str


class SystemOperationPlugin(BasePolicyPlugin):
    """SystemOperationPolicy plugin clas"""

    def _validate_inner_ctx(self, inner_data_dict) -> None:
        """validate systemOperationPolicy

        Args:
            inner_data_dict (dict): systemOperationPolicy
        """
        for value in inner_data_dict.values():
            validate(value, systemope_schema)
            use_rate_threshold = useThreshold(**value)
            if use_rate_threshold.value == SysConfValue.MINNUM and use_rate_threshold.comparison == SysConfComp.LESS:
                raise ValidationError("Value and comparison are set to be less than 0")
            if use_rate_threshold.value == SysConfValue.MAXNUM and use_rate_threshold.comparison == SysConfComp.GREATER:
                raise ValidationError("Value and comparison are set to be greater than 100")

    def _is_valid_sub_category(self, sub_category: str):
        """Cheking for subCategory type of policy

        Args:
            sub_category (str): Policy's subCategory

        Returns:
            bool: True if it is Node's subCategory. False otherwise
        """
        return sub_category == PolicyValue.SYSOPE
