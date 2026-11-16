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
"""fields jsonschema"""

from jsonschema import validate

# The columns of policy included in the response body. If not specified, all columns will be retrieved.
fields_schema = {
    "type": "array",
    "uniqueItems": True,
    "items": {
        "type": "string",
        "enum": [
            "policyID",
            "category",
            "title",
            "policy",
            "enabled",
            "createdAt",
            "updatedAt",
        ],
    },
    "minItems": 1,
}


def validate_get_fields(fields):
    """Validate fields

    Args:
        fields (list): policy column
    """
    if fields is not None:
        validate(fields, fields_schema)
