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

import pytest
import requests
from requests.exceptions import ConnectionError, RequestException, Timeout

from policymanager.common.config_reader import PolicyConfigReader, PolicyLogConfigReader
from policymanager.common.custom_exceptions import SecretInfoGetException, SettingFileValidationError, LogSettingFileValidationError


class TestPolicyConfigReader:

    @pytest.mark.parametrize(
        "update_config",
        [
            # Case where `dbname` is missing
            {
                "db": {
                    "user": "user01",
                    "password": "P@ssw0rd",
                    "host": "policy-manager-db",
                    "port": 5432,
                }
            },
            # Case where `user` is missing
            {
                "db": {
                    "dbname": "PolicyDB",
                    "password": "P@ssw0rd",
                    "host": "policy-manager-db",
                    "port": 5432,
                }
            },
            # Case where `password` is missing
            {
                "db": {
                    "dbname": "PolicyDB",
                    "user": "user01",
                    "host": "policy-manager-db",
                    "port": 5432,
                }
            },
            # Case where `host` is missing
            {
                "db": {
                    "dbname": "PolicyDB",
                    "user": "user01",
                    "password": "P@ssw0rd",
                    "port": 5432,
                }
            },
            # Case where `port` is missing
            {
                "db": {
                    "dbname": "PolicyDB",
                    "user": "user01",
                    "password": "P@ssw0rd",
                    "host": "policy-manager-db",
                }
            },
            # Case where both `dbname` and `password` are missing
            {
                "db": {
                    "user": "user01",
                    "host": "policy-manager-db",
                    "port": 5432,
                }
            },
            # Case where both `dbname` and `port` are missing
            {
                "db": {
                    "user": "user01",
                    "password": "P@ssw0rd",
                    "host": "policy-manager-db",
                }
            },
            # Case where both `password` and `port` are missing
            {
                "db": {
                    "dbname": "PolicyDB",
                    "user": "user01",
                    "host": "policy-manager-db",
                }
            },
            # Case where both `user` and `port` are missing
            {
                "db": {
                    "dbname": "PolicyDB",
                    "password": "P@ssw0rd",
                    "host": "policy-manager-db",
                }
            },
            # Case where both `dbname` and `user` are missing
            {
                "db": {
                    "password": "P@ssw0rd",
                    "host": "policy-manager-db",
                    "port": 5432,
                }
            },
            # Case where both `user` and `password` are missing
            {
                "db": {
                    "dbname": "PolicyDB",
                    "host": "policy-manager-db",
                    "port": 5432,
                }
            },
            # Case where both `dbname` and `host` are missing
            {
                "db": {
                    "user": "user01",
                    "password": "P@ssw0rd",
                    "port": 5432,
                }
            },
            # Case where both `user` and `host` are missing
            {
                "db": {
                    "dbname": "PolicyDB",
                    "password": "P@ssw0rd",
                    "port": 5432,
                }
            },
            # Case where both `port` and `host` are missing
            {
                "db": {
                    "dbname": "PolicyDB",
                    "user": "user01",
                    "password": "P@ssw0rd",
                }
            },
            # Case where both `password` and `host` are missing
            {
                "db": {
                    "dbname": "PolicyDB",
                    "user": "user01",
                    "port": 5432,
                }
            },
            # Case where `user`, `password`, and `port` are missing
            {
                "db": {
                    "dbname": "PolicyDB",
                    "host": "policy-manager-db",
                }
            },
            # Case where `password`, `host`, and `port` are missing
            {
                "db": {
                    "dbname": "PolicyDB",
                    "user": "user01",
                }
            },
            # Case where `user`, `password`, and `host` are missing
            {
                "db": {
                    "dbname": "PolicyDB",
                    "port": 5432,
                }
            },
            # Case where `user`, `host`, and `port` are missing
            {
                "db": {
                    "dbname": "PolicyDB",
                    "password": "P@ssw0rd",
                }
            },
            # Case where `dbname`, `password`, and `port` are missing
            {
                "db": {
                    "user": "user01",
                    "host": "policy-manager-db",
                }
            },
            # Case where `dbname`, `password`, and `host` are missing
            {
                "db": {
                    "user": "user01",
                    "port": 5432,
                }
            },
            # Case where `dbname`, `host`, and `port` are missing
            {
                "db": {
                    "user": "user01",
                    "password": "P@ssw0rd",
                }
            },
            # Case where `dbname`, `user`, and `port` are missing
            {
                "db": {
                    "password": "P@ssw0rd",
                    "host": "policy-manager-db",
                }
            },
            # Case where `dbname`, `user`, and `host` are missing
            {
                "db": {
                    "host": "policy-manager-db",
                    "port": 5432,
                }
            },
            # Case where only `dbname` exists
            {
                "db": {
                    "dbname": "PolicyDB",
                }
            },
            # Case where only `user` exists
            {
                "db": {
                    "user": "user01",
                }
            },
            # Case where only `password` exists
            {
                "db": {
                    "password": "P@ssw0rd",
                }
            },
            # Case where only `host` exists
            {
                "db": {
                    "host": "policy-manager-db",
                }
            },
            # Case where only `port` exists
            {
                "db": {
                    "port": 5432,
                }
            },
        ],
    )
    def test_common_retrieve_from_secret_store_when_db_config_missing(self, mocker, update_config, docker_services):
        base_config = {
            "db": {
                "dbname": "PolicyDB",
                "user": "user01",
                "password": "P@ssw0rd",
                "host": "policy-manager-db",
                "port": 5432,
            },
            "log": {
                "logging_level": "INFO",
                "log_dir": "./",
                "file": "app_policy.log",
                "rotation_size": 1000000,
                "backup_files": 3,
                "stdout": False,
            },
            "server": {
                "host": "0.0.0.0",
                "port": 8010,
            },
        }
        config = {**base_config, **update_config}
        mocker.patch("yaml.safe_load").return_value = config
        db_config = PolicyConfigReader().get_db_config
        assert "PolicyDB" == db_config.get("dbname")
        assert "user01" == db_config.get("user")
        assert "P@ssw0rd" == db_config.get("password")
        assert "policy-manager-db" == db_config.get("host")
        assert 5432 == db_config.get("port")

    def test_common_retrieve_from_secret_store_when_all_db_config_missing(self, mocker, docker_services):
        # Case where all DB configurations are missing
        config = {
            "log": {
                "logging_level": "INFO",
                "log_dir": "./",
                "file": "app_policy.log",
                "rotation_size": 1000000,
                "backup_files": 3,
                "stdout": False,
            },
            "server": {
                "host": "0.0.0.0",
                "port": 8010,
            },
        }
        mocker.patch("yaml.safe_load").return_value = config
        db_config = PolicyConfigReader().get_db_config
        assert "PolicyDB" == db_config.get("dbname")
        assert "user01" == db_config.get("user")
        assert "P@ssw0rd" == db_config.get("password")
        assert "policy-manager-db" == db_config.get("host")
        assert 5432 == db_config.get("port")

    def test_common_failure_when_secret_store_port_conversion_failed(self, mocker, docker_services):
        # Case where port conversion from secret store fails
        config = {
            "db": {
                "dbname": "PolicyDB",
                "password": "P@ssword",
                "user": "user01",
                "host": "policy-manager-db",
            },
            "log": {
                "logging_level": "INFO",
                "log_dir": "./",
                "file": "app_policy.log",
                "rotation_size": 1000000,
                "backup_files": 3,
                "stdout": False,
            },
            "server": {
                "host": "0.0.0.0",
                "port": 8010,
            },
        }
        mocker.patch("yaml.safe_load").return_value = config
        mock_connection = mocker.MagicMock()
        mock_connection.content = b'{"pmdb:port": "XXXX"}'
        mocker.patch("requests.get", return_value=mock_connection)

        with pytest.raises(SecretInfoGetException):
            PolicyConfigReader().get_db_config

    @pytest.mark.parametrize("exc", [{RequestException()}, {Timeout()}, {ConnectionError()}, {Exception()}])
    def test_common_failure_when_secret_store_retrieval_failed(self, mocker, exc):
        # Case where retrieval from secret store fails
        config = {
            "db": {
                "dbname": "PolicyDB",
                "user": "user01",
                "host": "policy-manager-db",
                "port": 5432,
            },
            "log": {
                "logging_level": "INFO",
                "log_dir": "./",
                "file": "app_policy.log",
                "rotation_size": 1000000,
                "backup_files": 3,
                "stdout": False,
            },
            "server": {
                "host": "0.0.0.0",
                "port": 8010,
            },
        }
        mocker.patch("yaml.safe_load").return_value = config
        mocker.patch("requests.get")
        requests.get.side_effect = exc

        with pytest.raises(SecretInfoGetException):
            PolicyConfigReader().get_db_config

    def test_common_readable_when_resource_config_file(self):
        # Case where resource configuration file is readable
        obj = PolicyConfigReader()
        assert type(obj.get_db_config) is dict
        assert type(obj.get_server_config) is dict

    @pytest.mark.parametrize(
        "update_confg",
        [
            # Case where `host` is specified as an IP
            {
                "server": {
                    "host": "0.0.0.0",
                    "port": 8003,
                },
            },
            # Case where `host` is specified as a hostname
            {
                "server": {
                    "host": "nec.test.com",
                    "port": 8003,
                },
            },
            # Case where `port` is set to a valid value
            {
                "server": {
                    "host": "nec.test.com",
                    "port": 0,
                },
            },
        ],
    )
    def test_common_readable_when_server_related_config(self, mocker, update_confg):
        # Case where server-related configurations are validated
        base_config = {
            "log": {
                "logging_level": "INFO",
                "log_dir": "./",
                "file": "app_policy.log",
                "rotation_size": 1000000,
                "backup_files": 3,
                "stdout": False,
            },
            "db": {
                "dbname": "test",
                "user": "test_user",
                "password": "p@ssw0rd",
                "host": "192.0.2.10",
                "port": 10024,
            },
        }
        config = {**base_config, **update_confg}
        mocker.patch("yaml.safe_load").return_value = config
        server = PolicyConfigReader().get_server_config
        assert server == update_confg.get("server")

    @pytest.mark.parametrize(
        "update_confg",
        [
            # Case where `host` is specified as an IP
            {
                "server": {
                    "host": "0.0.0.0",
                    "port": "8003",
                },
            },
            # Case where a required field is missing
            {},
        ],
    )
    def test_common_failure_when_server_config_with_invalid_value(self, mocker, update_confg):
        # Case where server configuration contains invalid values
        base_config = {
            "log": {
                "logging_level": "INFO",
                "log_dir": "./",
                "file": "app_policy.log",
                "rotation_size": 1000000,
                "backup_files": 3,
                "stdout": False,
            },
            "db": {
                "dbname": "test",
                "user": "test_user",
                "password": "p@ssw0rd",
                "host": "192.0.2.10",
                "port": 10024,
            },
        }
        config = {**base_config, **update_confg}
        mocker.patch("yaml.safe_load").return_value = config
        with pytest.raises(SettingFileValidationError) as e:
            PolicyConfigReader().get_server_config

    @pytest.mark.parametrize(
        "update_confg",
        [
            # Case where `host` is specified as an IP
            {
                "db": {
                    "dbname": "test",
                    "user": "test_user",
                    "password": "p@ssw0rd",
                    "host": "192.0.2.10",
                    "port": 10024,
                }
            },
            # Case where `host` is specified as a hostname
            {
                "db": {
                    "dbname": "test",
                    "user": "test_user",
                    "password": "p@ssw0rd",
                    "host": "localhost",
                    "port": 10024,
                }
            },
            # Case where `port` has an expected value
            {
                "db": {
                    "dbname": "test",
                    "user": "test_user",
                    "password": "p@ssw0rd",
                    "host": "192.0.2.10",
                    "port": 0,
                }
            },
        ],
    )
    def test_common_readable_when_db_related_config(self, mocker, update_confg):
        # Case where database-related configurations are validated
        base_config = {
            "log": {
                "logging_level": "INFO",
                "log_dir": "./",
                "file": "app_policy.log",
                "rotation_size": 1000000,
                "backup_files": 3,
                "stdout": False,
            },
            "server": {
                "host": "0.0.0.0",
                "port": 8003,
            },
        }
        config = {**base_config, **update_confg}
        mocker.patch("yaml.safe_load").return_value = config
        PolicyConfigReader().get_db_config

    @pytest.mark.parametrize(
        "update_confg",
        [
            # Case where `port` fails validation
            {
                "db": {
                    "dbname": "test",
                    "user": "test_user",
                    "password": "p@ssw0rd",
                    "host": "192.0.2.10",
                    "port": "port",
                }
            },
            # Case where only `db` collection exists
            {"db": None},
            # Case where `dbname` is missing
            {
                "db": {
                    "dbname": None,
                    "user": "test_user",
                    "password": "p@ssw0rd",
                    "host": "192.0.2.10",
                    "port": 5432,
                }
            },
        ],
    )
    def test_common_failure_when_db_config_with_invalid_value(self, mocker, update_confg):
        # Case where database configuration contains invalid values
        base_config = {
            "log": {
                "logging_level": "INFO",
                "log_dir": "./",
                "file": "app_policy.log",
                "rotation_size": 1000000,
                "backup_files": 3,
                "stdout": False,
            },
            "server": {
                "host": "0.0.0.0",
                "port": 8010,
            },
        }
        config = {**base_config, **update_confg}
        mocker.patch("yaml.safe_load").return_value = config
        with pytest.raises(SettingFileValidationError) as e:
            PolicyConfigReader().get_db_config

    @pytest.mark.parametrize(
        "update_confg",
        [
            # Case where `logging_level` has an expected value
            {
                "version": 1,
                "formatters": {
                    "standard": {
                        "format": "%(asctime)s %(levelname)s %(message)s",
                        "datefmt": "%Y/%m/%d %H:%M:%S.%f",
                    },
                },
                "handlers": {
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "INFO",
                        "formatter": "standard",
                        "filename": "/var/log/cdim/app_policy.log",
                        "maxBytes": 100000000,
                        "backupCount": 72,
                        "encoding": "utf-8",
                    },
                    "console": {
                        "class": "logging.StreamHandler",
                        "level": "INFO",
                        "formatter": "standard",
                        "stream": "ext://sys.stdout",
                    },
                },
                "root": {
                    "level": "INFO",
                    "handlers": ["file", "console"],

                }
            },
            {
                "version": 1,
                "formatters": {
                    "standard": {
                        "format": "%(asctime)s %(levelname)s %(message)s",
                        "datefmt": "%Y/%m/%d %H:%M:%S.%f",
                    },
                },
                "handlers": {
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "ERROR",
                        "formatter": "standard",
                        "filename": "/var/log/cdim/app_policy.log",
                        "maxBytes": 100000000,
                        "backupCount": 72,
                        "encoding": "utf-8",
                    },
                    "console": {
                        "class": "logging.StreamHandler",
                        "level": "ERROR",
                        "formatter": "standard",
                        "stream": "ext://sys.stdout",
                    },
                },
                "root": {
                    "level": "ERROR",
                    "handlers": ["file", "console"],

                }
            },
            {
                "log": {
                    "logging_level": "WARN",
                    "log_dir": "./",
                    "file": "app_layout_apply.log",
                    "rotation_size": 1000000,
                    "backup_files": 3,
                    "stdout": False,
                }
            },
            {
                "version": 1,
                "formatters": {
                    "standard": {
                        "format": "%(asctime)s %(levelname)s %(message)s",
                        "datefmt": "%Y/%m/%d %H:%M:%S.%f",
                    },
                },
                "handlers": {
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "CRITICAL",
                        "formatter": "standard",
                        "filename": "/var/log/cdim/app_policy.log",
                        "maxBytes": 100000000,
                        "backupCount": 72,
                        "encoding": "utf-8",
                    },
                    "console": {
                        "class": "logging.StreamHandler",
                        "level": "CRITICAL",
                        "formatter": "standard",
                        "stream": "ext://sys.stdout",
                    },
                },
                "root": {
                    "level": "CRITICAL",
                    "handlers": ["file", "console"],

                }
            },
            {
                "version": 1,
                "formatters": {
                    "standard": {
                        "format": "%(asctime)s %(levelname)s %(message)s",
                        "datefmt": "%Y/%m/%d %H:%M:%S.%f",
                    },
                },
                "handlers": {
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "DEBUG",
                        "formatter": "standard",
                        "filename": "/var/log/cdim/app_policy.log",
                        "maxBytes": 100000000,
                        "backupCount": 72,
                        "encoding": "utf-8",
                    },
                    "console": {
                        "class": "logging.StreamHandler",
                        "level": "DEBUG",
                        "formatter": "standard",
                        "stream": "ext://sys.stdout",
                    },
                },
                "root": {
                    "level": "DEBUG",
                    "handlers": ["file", "console"],

                }
            },
            # Case where `level` is missing
            {
                "version": 1,
                "formatters": {
                    "standard": {
                        "format": "%(asctime)s %(levelname)s %(message)s",
                        "datefmt": "%Y/%m/%d %H:%M:%S.%f",
                    },
                },
                "handlers": {
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        #"level": "INFO",
                        "formatter": "standard",
                        "filename": "/var/log/cdim/app_policy.log",
                        "maxBytes": 100000000,
                        "backupCount": 72,
                        "encoding": "utf-8",
                    },
                    "console": {
                        "class": "logging.StreamHandler",
                        "level": "INFO",
                        "formatter": "standard",
                        "stream": "ext://sys.stdout",
                    },
                },
                "root": {
                    "level": "INFO",
                    "handlers": ["file", "console"],

                }
            },
            # Case where log directory specifies an existing path
            {
                "version": 1,
                "formatters": {
                    "standard": {
                        "format": "%(asctime)s %(levelname)s %(message)s",
                        "datefmt": "%Y/%m/%d %H:%M:%S.%f",
                    },
                },
                "handlers": {
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "INFO",
                        "formatter": "standard",
                        "filename": "./app_policy.log",
                        "maxBytes": 100000000,
                        "backupCount": 72,
                        "encoding": "utf-8",
                    },
                    "console": {
                        "class": "logging.StreamHandler",
                        "level": "INFO",
                        "formatter": "standard",
                        "stream": "ext://sys.stdout",
                    },
                },
                "root": {
                    "level": "INFO",
                    "handlers": ["file", "console"],

                }
            },
            # Case where `filename` has an expected value
            {
                "version": 1,
                "formatters": {
                    "standard": {
                        "format": "%(asctime)s %(levelname)s %(message)s",
                        "datefmt": "%Y/%m/%d %H:%M:%S.%f",
                    },
                },
                "handlers": {
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "INFO",
                        "formatter": "standard",
                        "filename": "./a",
                        "maxBytes": 100000000,
                        "backupCount": 72,
                        "encoding": "utf-8",
                    },
                    "console": {
                        "class": "logging.StreamHandler",
                        "level": "INFO",
                        "formatter": "standard",
                        "stream": "ext://sys.stdout",
                    },
                },
                "root": {
                    "level": "INFO",
                    "handlers": ["file", "console"],

                }
            },
            # Case where `rotation_size` has a valid value
            {
                "version": 1,
                "formatters": {
                    "standard": {
                        "format": "%(asctime)s %(levelname)s %(message)s",
                        "datefmt": "%Y/%m/%d %H:%M:%S.%f",
                    },
                },
                "handlers": {
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "INFO",
                        "formatter": "standard",
                        "filename": "/var/log/cdim/app_policy.log",
                        "maxBytes": 0,
                        "backupCount": 72,
                        "encoding": "utf-8",
                    },
                    "console": {
                        "class": "logging.StreamHandler",
                        "level": "INFO",
                        "formatter": "standard",
                        "stream": "ext://sys.stdout",
                    },
                },
                "root": {
                    "level": "INFO",
                    "handlers": ["file", "console"],

                }
            },
            # Case where `backup_files` has a valid value
            {
                "version": 1,
                "formatters": {
                    "standard": {
                        "format": "%(asctime)s %(levelname)s %(message)s",
                        "datefmt": "%Y/%m/%d %H:%M:%S.%f",
                    },
                },
                "handlers": {
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "INFO",
                        "formatter": "standard",
                        "filename": "/var/log/cdim/app_policy.log",
                        "maxBytes": 0,
                        "backupCount": 3,
                        "encoding": "utf-8",
                    },
                    "console": {
                        "class": "logging.StreamHandler",
                        "level": "INFO",
                        "formatter": "standard",
                        "stream": "ext://sys.stdout",
                    },
                },
                "root": {
                    "level": "INFO",
                    "handlers": ["file", "console"],

                }
            },
            # Case for `stdout` variations
            {
                "version": 1,
                "formatters": {
                    "standard": {
                        "format": "%(asctime)s %(levelname)s %(message)s",
                        "datefmt": "%Y/%m/%d %H:%M:%S.%f",
                    },
                },
                "handlers": {
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "INFO",
                        "formatter": "standard",
                        "filename": "/var/log/cdim/app_policy.log",
                        "maxBytes": 0,
                        "backupCount": 72,
                        "encoding": "utf-8",
                    },
                    "console": {
                        "class": "logging.StreamHandler",
                        "level": "INFO",
                        "formatter": "standard",
                        "stream": "ext://sys.stdout",
                    },
                },
                "root": {
                    "level": "INFO",
                    "handlers": ["file"],

                }
            },
            {
                "version": 1,
                "formatters": {
                    "standard": {
                        "format": "%(asctime)s %(levelname)s %(message)s",
                        "datefmt": "%Y/%m/%d %H:%M:%S.%f",
                    },
                },
                "handlers": {
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "INFO",
                        "formatter": "standard",
                        "filename": "/var/log/cdim/app_policy.log",
                        "maxBytes": 0,
                        "backupCount": 72,
                        "encoding": "utf-8",
                },
                "root": {
                    "level": "INFO",
                    "handlers": ["file"],

                }
            },
        },
        ],
    )
    def test_common_readable_when_log_related_config(self, mocker, update_confg):
        # Validates log-related configurations
        base_config = {
            "version": 1,
            "formatters": {
                "standard": {
                    "format": "%(asctime)s %(levelname)s %(message)s",
                    "datefmt": "%Y/%m/%d %H:%M:%S.%f",
                },
            },
            "handlers": {
                "file": {
                    "class": "logging.handlers.RotatingFileHandler",
                    "level": "INFO",
                    "formatter": "standard",
                    "filename": "/var/log/cdim/app_policy.log",
                    "maxBytes": 100000000,
                    "backupCount": 72,
                    "encoding": "utf-8",
                },
                "console": {
                    "class": "logging.StreamHandler",
                    "level": "INFO",
                    "formatter": "standard",
                    "stream": "ext://sys.stdout",
                },
            },
            "root": {
                "level": "INFO",
                "handlers": ["file", "console"],
            },
        }
        config = {**base_config, **update_confg}
        mocker.patch("yaml.safe_load").return_value = config
        PolicyLogConfigReader().get_log_config

    @pytest.mark.parametrize(
        "update_confg",
        [
            # Case where `logging_level` has an unexpected string
            {
                'version': 1,
                'formatters': {
                    'standard': {
                        'format': '%(asctime)s %(levelname)s %(message)s',
                        'datefmt': '%Y/%m/%d %H:%M:%S.%f'
                    }
                },
                'handlers': {
                    'file': {
                        'class': 'logging.handlers.RotatingFileHandler',
                        'level': 'OFNI',
                        'formatter': 'standard',
                        'filename': '/var/log/cdim/app_policy.log',
                        'maxBytes': 100000000,
                        'backupCount': 72,
                        'encoding': 'utf-8'
                    },
                    'console': {
                        'class': 'logging.StreamHandler',
                        'level': 'OFNI',
                        'formatter': 'standard',
                        'stream': 'ext://sys.stdout'
                    }
                },
                'root': {
                    'level': 'OFNI',
                    'handlers': ['file', 'console']
                }
            },
            # Case where `logging_level` has an invalid type
            {
                'version': 1,
                'formatters': {
                    'standard': {
                        'format': '%(asctime)s %(levelname)s %(message)s',
                        'datefmt': '%Y/%m/%d %H:%M:%S.%f'
                    }
                },
                'handlers': {
                    'file': {
                        'class': 'logging.handlers.RotatingFileHandler',
                        'level': 1,
                        'formatter': 'standard',
                        'filename': '/var/log/cdim/app_policy.log',
                        'maxBytes': 100000000,
                        'backupCount': 72,
                        'encoding': 'utf-8'
                    },
                    'console': {
                        'class': 'logging.StreamHandler',
                        'level': 'INFO',
                        'formatter': 'standard',
                        'stream': 'ext://sys.stdout'
                    }
                },
                'root': {
                    'level': 'INFO',
                    'handlers': ['file', 'console']
                }
            },
            # Case where `log_dir` has an invalid type
            {
                'version': 1,
                'formatters': {
                    'standard': {
                        'format': '%(asctime)s %(levelname)s %(message)s',
                        'datefmt': '%Y/%m/%d %H:%M:%S.%f'
                    }
                },
                'handlers': {
                    'file': {
                        'class': 'logging.handlers.RotatingFileHandler',
                        'level': 1,
                        'formatter': 'standard',
                        'filename': 1,
                        'maxBytes': 100000000,
                        'backupCount': 72,
                        'encoding': 'utf-8'
                    },
                    'console': {
                        'class': 'logging.StreamHandler',
                        'level': 'INFO',
                        'formatter': 'standard',
                        'stream': 'ext://sys.stdout'
                    }
                },
                'root': {
                    'level': 'INFO',
                    'handlers': ['file', 'console']
                }
            },
            # Case where `log_dir` specifies a non-existing path
            {
                'version': 1,
                'formatters': {
                    'standard': {
                        'format': '%(asctime)s %(levelname)s %(message)s',
                        'datefmt': '%Y/%m/%d %H:%M:%S.%f'
                    }
                },
                'handlers': {
                    'file': {
                        'class': 'logging.handlers.RotatingFileHandler',
                        'level': 'INFO',
                        'formatter': 'standard',
                        'filename': '/non_existing_path/app_policy.log',
                        'maxBytes': 100000000,
                        'backupCount': 72,
                        'encoding': 'utf-8'
                    },
                    'console': {
                        'class': 'logging.StreamHandler',
                        'level': 'INFO',
                        'formatter': 'standard',
                        'stream': 'ext://sys.stdout'
                    }
                },
                'root': {
                    'level': 'INFO',
                    'handlers': ['file', 'console']
                }
            },
            # Case where `file` has an invalid type
                        {
                'version': 1,
                'formatters': {
                    'standard': {
                        'format': '%(asctime)s %(levelname)s %(message)s',
                        'datefmt': '%Y/%m/%d %H:%M:%S.%f'
                    }
                },
                'handlers': {
                    'file': {
                        'class': 'logging.handlers.RotatingFileHandler',
                        'level': 'INFO',
                        'formatter': 'standard',
                        'filename': True,
                        'maxBytes': 100000000,
                        'backupCount': 72,
                        'encoding': 'utf-8'
                    },
                    'console': {
                        'class': 'logging.StreamHandler',
                        'level': 'INFO',
                        'formatter': 'standard',
                        'stream': 'ext://sys.stdout'
                    }
                },
                'root': {
                    'level': 'INFO',
                    'handlers': ['file', 'console']
                }
            },
            # Case where `rotation_size` has an invalid type
            {
                'version': 1,
                'formatters': {
                    'standard': {
                        'format': '%(asctime)s %(levelname)s %(message)s',
                        'datefmt': '%Y/%m/%d %H:%M:%S.%f'
                    }
                },
                'handlers': {
                    'file': {
                        'class': 'logging.handlers.RotatingFileHandler',
                        'level': 1,
                        'formatter': 'standard',
                        'filename': '/var/log/cdim/app_policy.log',
                        'maxBytes': '3',
                        'backupCount': 72,
                        'encoding': 'utf-8'
                    },
                    'console': {
                        'class': 'logging.StreamHandler',
                        'level': 'INFO',
                        'formatter': 'standard',
                        'stream': 'ext://sys.stdout'
                    }
                },
                'root': {
                    'level': 'INFO',
                    'handlers': ['file', 'console']
                }
            },
            # Case where `backup_files` has an invalid type
            {
                'version': 1,
                'formatters': {
                    'standard': {
                        'format': '%(asctime)s %(levelname)s %(message)s',
                        'datefmt': '%Y/%m/%d %H:%M:%S.%f'
                    }
                },
                'handlers': {
                    'file': {
                        'class': 'logging.handlers.RotatingFileHandler',
                        'level': 1,
                        'formatter': 'standard',
                        'filename': '/var/log/cdim/app_policy.log',
                        'maxBytes': 3,
                        'backupCount': '72',
                        'encoding': 'utf-8'
                    },
                    'console': {
                        'class': 'logging.StreamHandler',
                        'level': 'INFO',
                        'formatter': 'standard',
                        'stream': 'ext://sys.stdout'
                    }
                },
                'root': {
                    'level': 'INFO',
                    'handlers': ['file', 'console']
                }
            },
            # Case where `stdout` has an invalid type
            {
                'version': 1,
                'formatters': {
                    'standard': {
                        'format': '%(asctime)s %(levelname)s %(message)s',
                        'datefmt': '%Y/%m/%d %H:%M:%S.%f'
                    }
                },
                'handlers': {
                    'file': {
                        'class': 'logging.handlers.RotatingFileHandler',
                        'level': 1,
                        'formatter': 'standard',
                        'filename': '/var/log/cdim/app_policy.log',
                        'maxBytes': '3',
                        'backupCount': 72,
                        'encoding': 'utf-8'
                    },
                    'console': {
                        'class': 'logging.StreamHandler',
                        'level': 'INFO',
                        'formatter': 'standard',
                        'stream': 'ext://sys.stdout'
                    }
                },
                'root': {
                    'level': 'INFO',
                    'handlers': ['file', 1]
                }
            },
        ],
    )
    def test_common_failure_when_log_config_with_invalid_value(self, mocker, update_confg):
        # Case where log configuration contains invalid values
        base_config = {
            'version': 1,
            'formatters': {
                'standard': {
                    'format': '%(asctime)s %(levelname)s %(message)s',
                    'datefmt': '%Y/%m/%d %H:%M:%S.%f'
                }
            },
            'handlers': {
                'file': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'level': 'INFO',
                    'formatter': 'standard',
                    'filename': '/var/log/cdim/app_policy.log',
                    'maxBytes': 100000000,
                    'backupCount': 72,
                    'encoding': 'utf-8'
                },
                'console': {
                    'class': 'logging.StreamHandler',
                    'level': 'INFO',
                    'formatter': 'standard',
                    'stream': 'ext://sys.stdout'
                }
            },
            'root': {
                'level': 'INFO',
                'handlers': ['file', 'console']
            }
        }
        config = {**base_config, **update_confg}
        mocker.patch("yaml.safe_load").return_value = config
        with pytest.raises(LogSettingFileValidationError) as e:
            PolicyLogConfigReader().get_log_config

