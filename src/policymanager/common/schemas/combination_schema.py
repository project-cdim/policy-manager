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
"""category and policy is matching jsonschema"""

from jsonschema import validate
from jsonschema.exceptions import ValidationError

combination_schema = {
    "type": "object",
    "required": ["category", "policy"],
    "properties": {
        "category": {
            "type": "string",
            "enum": ["nodeConfigurationPolicy", "systemOperationPolicy"],
        },
        "policy": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ["hardwareConnectionsLimit", "useThreshold"],
            },
            "minItems": 1,
        },
    },
    "oneOf": [
        {
            "properties": {
                "category": {
                    "const": "nodeConfigurationPolicy",
                },
                "policy": {
                    "type": "array",
                    "items": {
                        "const": "hardwareConnectionsLimit",
                    },
                },
            },
        },
        {
            "properties": {
                "category": {
                    "const": "systemOperationPolicy",
                },
                "policy": {
                    "type": "array",
                    "items": {
                        "const": "useThreshold",
                    },
                },
            },
        },
    ],
}


def validate_category_policy(category: str, policy: dict):
    """validate category and policy

    Args:
        category (str): policy category
        policy (dict): policy
    Raises:
        ValidationError: ValidationError
    """
    if category and policy:  # pragma: no cover
        try:
            validate(
                {"category": category, "policy": list(policy.keys())},
                combination_schema,
            )
        except ValidationError as err:
            msg = (
                "There is a contradiction in values set for category and policy."
                + "If register, please confirm category and policy you have set."
                + "If update, please confirm that category and policy "
                + "you have set do not contradict those that are already registered"
            )
            raise ValidationError(msg) from err
