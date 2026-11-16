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
"""JSON schema for the policy condition enable/disable flag"""

# Used to specify the enable or disable state of the policy conditions you want to obtain.
enabled_schema = {
    "type": "string",
    "enum": ["all", "true", "false"],
}

# Used to specify the enable or disable status of additional policy.
bool_schema = {
    "type": "boolean",
}
