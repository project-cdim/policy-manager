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
"""Json schema for sorting results"""

from jsonschema import validate

# Rearrange the policy section.
sortBy_schema = {
    "type": "string",
    "enum": [
        "createdAt",
        "updatedAt",
    ],
}

# Sort order: ascending/descending. If not specified, it will be ascending.
orderBy_schema = {
    "type": "string",
    "enum": [
        "asc",
        "desc",
    ],
}


# pylint: disable=C0103
def validate_get_sort(sortBy: str, orderBy: str):
    """validate sortBy and orderBy

    Args:
        sortBy (str): Column by which the sort is based
        orderBy (str): Sorting method
    """
    validate(sortBy, sortBy_schema)
    if orderBy is not None:  # pragma: no cover
        validate(orderBy, orderBy_schema)
