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
"""Jsonschema for file check of Import function"""

# Checking the contents of the import file
import_file_schema = {
    "type": "object",
    "required": ["policies"],
    "properties": {"policies": {"type": "array", "minItems": 1}},
}

# Required keys for policy in the file
import_policy_schema = {
    "type": "object",
    "required": ["title", "category", "policy", "enabled"],
}
