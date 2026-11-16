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
"""Configuration file-related package"""

import json
import os

import requests
from jsonschema import validate
from policymanager.common.config import BaseConfig

from policymanager.common.const import DbConfigName, RequestParameter
from policymanager.common.custom_exceptions import (
    SecretInfoGetException,
    SettingFileValidationError,
    LogSettingFileValidationError,
)
from policymanager.common.schemas.config_schema import config_schema, db_config_shecma, log_config_schema


class PolicyLogConfigReader(BaseConfig):
    """Class for loading logging configuration files"""

    def __init__(self) -> None:
        """Constructor
        If the DB-related settings do not exist in the configuration file,
        acquire the DB-related settings information from the secret store.
        """
        try:
            super().__init__("policymanager.config", "policymanager_log_config.yaml")
            validate(self._config, log_config_schema)
            filename = self._config.get("handlers", {}).get("file", {}).get("filename")
            log_dir = os.path.dirname(filename)
            self._check_directory_exists(log_dir)
        except Exception as error:
            raise LogSettingFileValidationError(error.args) from error

    def _check_directory_exists(self, path: str) -> None:
        """Check if the directory exists.

        Args:
            path (str): Directory path

        Raises:
            FileNotFoundError: The file does not exist.
        """
        if not os.path.isdir(path):
            raise FileNotFoundError(f"Directory not found at path: {path}")

    @property
    def get_log_config(self) -> dict:
        """Read the log setting data from the configuration file for policymanager.

        Returns:
            dict: Data from the loaded configuration file
        """
        return self._config


class PolicyConfigReader(BaseConfig):
    """Class for loading configuration files"""

    def __init__(self) -> None:
        """Constructor
        If the DB-related settings do not exist in the configuration file,
        acquire the DB-related settings information from the secret store.
        """
        try:
            super().__init__("policymanager.config", "policymanager_config.yaml")

            validate(self._config, config_schema)
        except Exception as error:
            raise SettingFileValidationError(error.args) from error

        try:
            # Retrieve the DB configuration information from the secret store
            # that does not exist in the configuration file.
            self._get_secret()
        except Exception as error:
            raise SecretInfoGetException(error.args) from error

    def _get_secret(self) -> None:
        """get secret information for secret store"""
        # Get the setting information keys of the db defined with const as a list type.
        key_list = list(DbConfigName.__dict__.get("_value2member_map_").keys())
        tmp_config = {}
        results = requests.get(
            url=f"{RequestParameter.URL}",
            timeout=100,
        )
        if "db" not in self._config:
            self._config["db"] = {}
        for key in key_list:
            if key not in self._config.get("db"):
                tmp_config[key] = self._retrieve_secret_store(results, key)
        validate(tmp_config, db_config_shecma)
        self._config["db"].update(tmp_config)

    def _retrieve_secret_store(self, results, key) -> int | str:
        """stores information acquired

        Args:
            results (response): get secret store info
            key (str): get secret key
        return:
            secret_info (int,str): db config
        """
        secret_info = json.loads(results.content.decode()).get(key)
        if key == DbConfigName.PORT:
            try:
                # Since port is registered as a str type, convert it to an int type.
                secret_info = int(secret_info)
            except Exception:  # pylint:disable=W0718
                # If the conversion to int type fails, do nothing and return the value,
                # resulting in an error in the json_schema validation check.
                pass
        return secret_info

    @property
    def get_db_config(self) -> dict:
        """Load database settings from the configuration file for poilcymanager.

        Returns:
            dict: Data from the loaded configuration file
        """
        return self._config.get("db")

    @property
    def get_server_config(self) -> dict:
        """Load server settings from the configuration file for policymanager.

        Returns:
            dict: Data from the loaded configuration file
        """
        return self._config.get("server")
