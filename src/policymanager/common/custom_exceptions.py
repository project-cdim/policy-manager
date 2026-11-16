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
"""Custom Error Package"""


class InvalidOperationException(Exception):
    """This occurs when the specified policy are not in a disabled state during deletion or update."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class SettingFileValidationError(Exception):
    """Occurs when validation check fails while loading the configuration file."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class LogSettingFileValidationError(Exception):
    """Occurs when validation check fails while loading the configuration file."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class IdNotFoundException(Exception):
    """Occurs when specified policy are not present"""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class UnmatchIdException(Exception):
    """Occurs when the obtained policy ID does not match the contents of "enableIDList" and "disableIDList"."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class DuplicatePolicyException(Exception):
    """Occurs when the details of the restriction type of the newly
    added/updated policy and the device type are the same as those already registered in the database."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class ExportPolicyException(Exception):
    """It occurs when an error happens during file writing."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class PluginLoadException(Exception):
    """Occurs when the corresponding plugin does not exist"""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class SecretInfoGetException(Exception):
    """It occurs when the retrieval of secret information fails."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class LogInitializationError(Exception):
    """Log initialization failed error class"""

    def __init__(self, message):
        """constructor"""
        super().__init__(message)
        self.message = message
