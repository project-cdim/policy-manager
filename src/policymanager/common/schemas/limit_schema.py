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
"""The jsonschema specifying the number of data acquired."""

from jsonschema import validate

# Number of acquisitions. Acquire policy based on the specified number of items.
limit_schema = {
    "type": "integer",
    "minimum": 1,
}


def validate_limit(limit: int):  # pylint: disable=C0103
    """validate limit option

    Args:
        limit (int):Specify the number of data points.
    """
    validate(limit, limit_schema)
