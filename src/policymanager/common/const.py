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
"""Enum package for fixed values"""

from enum import IntEnum, StrEnum, _simple_enum


@_simple_enum(IntEnum)
class ExitCode:
    """Definition of return value constants"""

    def __new__(cls, value):
        obj = int.__new__(cls, value)
        obj._value_ = value
        return obj

    # Normal
    NORMAL = 0
    # Validation error
    VALIDATION_ERROR = 1
    # Config error
    CONFIG_ERROR = 2
    # Database Connection error
    DB_CONNECTION_ERROR = 3
    # Query error
    QUERY_ERROR = 4
    # ID not found  error
    ID_NOT_FOUND_ERROR = 5
    # ID unmatch error
    UNMATCH_ID_ERROR = 6
    # Error where the state is not invalidated when removing or updating policy
    INVALID_OPERATION_ERROR = 7
    # Error of duplicate policy
    DUPLICATE_POLICY_ERROR = 8
    # File write error
    EXPORT_POLICY_ERROR = 9
    # Plugin load error
    PLUGIN_LOAD_ERROR = 10
    # Failed to retrieve secret information
    SECRET_REQUEST_ERROR = 11
    # Failure to initialize logs error
    LOG_INITIALIZATION_FAILED_ERROR = 12


@_simple_enum(IntEnum)
class IdParameter:
    """Definition of Return Value Constants"""

    def __new__(cls, value):
        obj = int.__new__(cls, value)
        obj._value_ = value
        return obj

    # Length of the generated string
    LENGTH = 10


@_simple_enum(IntEnum)
class SysConfValue:
    """systemOperationPolicy comparison value"""

    MAXNUM = 100
    MINNUM = 0


@_simple_enum(StrEnum)
class SysConfComp:
    """systemOperationPolicy comparison value"""

    GREATER = "gt"
    LESS = "lt"


@_simple_enum(StrEnum)
class PolicyValue:
    """policy comparison value"""

    NODECONF = "hardwareConnectionsLimit"
    SYSOPE = "useThreshold"


@_simple_enum(IntEnum)
class CategoryCount:
    """validate category count"""

    LIMIT = 1


@_simple_enum(StrEnum)
class FileEncode:
    """File encoding value"""

    UTF8 = "utf-8"


@_simple_enum(StrEnum)
class RequestParameter:
    """Secret Info Request parameter value"""

    URL = "http://127.0.0.1:3500/v1.0/secrets/cdim-policy-manager/cdim-policy-manager"
    STORE_NAME = "cdim-policy-manager"


@_simple_enum(StrEnum)
class DbConfigName:
    """The value is used as the key when its retrieved from the secret store"""

    DBNAME = "dbname"
    PASS = "password"
    USER = "user"
    HOST = "host"
    PORT = "port"
