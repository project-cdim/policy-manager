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
"""category jsonschema"""

from jsonschema import ValidationError, validate

from policymanager.common.const import CategoryCount

# Used when adding or updating policy. Specify the type of category for the record.
category_schema = {
    "type": "string",
    "enum": ["nodeConfigurationPolicy", "systemOperationPolicy"],
}

# Specify the category to refer to the policy.
getcategory_schema = {
    "type": "array",
    "items": {
        "type": "string",
        "enum": ["all", "nodeConfigurationPolicy", "systemOperationPolicy"],
    },
    "minItems": 1,
}


def validate_get_category(category: list):
    """validate category

    Args:
        category (list): policy category

    Raises:
        ValidationError: Category is set to all, no other values can be set
        ValidationError: Duplicate strings is specified
    """
    validate(category, getcategory_schema)
    if len(category) != len(set(category)):
        raise ValidationError("Duplicate category is specified")

    if "all" in category and len(category) > CategoryCount.LIMIT:
        raise ValidationError("Category is set to all, no other values can be set")
