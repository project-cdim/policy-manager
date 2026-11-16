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
"""JSON schema for search parameters within a policy"""

from jsonschema import validate

# hardwareConnectionsLimit or useThreshold. Use for searching within policy.
subCategory_schema = {
    "type": "string",
    "enum": ["hardwareConnectionsLimit", "useThreshold"],
}

# Device type. Used for searching within policy.
device_schema = {
    "type": "string",
    "enum": [
        "CPU",
        "MEMORY",
        "STORAGE",
        "GPU",
        "FPGA",
        "ACCELERATOR",
        "DSP",
        "VIRTUALMEDIA",
        "GRAPHICCONTROLLER",
        "NETWORKINTERFACE",
    ],
}


def validate_get_internal_search_parameter(subCategory: str, device: str):  # pylint: disable=C0103
    """validate policy to device key

    Args:
        subCategory (str): hardwareConnectionsLimit or useThreshold
        device (str):device type
    """
    if subCategory is not None:
        validate(subCategory, subCategory_schema)
    if device is not None:
        validate(device.upper(), device_schema)
