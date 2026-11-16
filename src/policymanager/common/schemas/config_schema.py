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
"""Jsonschema for configuration files"""

# Configuration file for policy manager
config_schema = {
    "type": "object",
    "required": ["server"],
    "properties": {
        "db": {
            "type": "object",
            "properties": {
                "dbname": {"type": "string"},
                "user": {"type": "string"},
                "password": {"type": "string"},
                "host": {
                    "type": "string",
                },
                "port": {
                    "type": "integer",
                },
            },
        },
        "server": {
            "type": "object",
            "required": ["host", "port"],
            "properties": {
                "host": {
                    "type": "string",
                },
                "port": {
                    "type": "integer",
                },
            },
        },
    },
}


# Database-related settings
db_config_shecma = {
    "type": "object",
    "properties": {
        "dbname": {"type": "string"},
        "user": {"type": "string"},
        "password": {"type": "string"},
        "host": {
            "type": "string",
        },
        "port": {
            "type": "integer",
        },
    },
}

# Logging-related settings
log_config_schema = {
    "type": "object",
    "required": ["version", "formatters", "handlers", "root"],
    "properties": {
        "version": {"type": "integer"},
        "formatters": {
            "type": "object",
            "properties": {
                "standard": {
                    "type": "object",
                    "properties": {"format": {"type": "string"}, "datefmt": {"type": "string"}},
                    "required": ["format", "datefmt"],
                }
            },
            "required": ["standard"],
        },
        "handlers": {
            "type": "object",
            "properties": {
                "file": {
                    "type": "object",
                    "properties": {
                        "class": {"type": "string"},
                        "level": {
                            "type": "string",
                            "enum": ["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"],
                        },
                        "formatter": {"type": "string"},
                        "filename": {"type": "string"},
                        "maxBytes": {"type": "integer"},
                        "backupCount": {"type": "integer"},
                        "encoding": {"type": "string"},
                    },
                    "required": ["class", "formatter", "filename", "maxBytes", "backupCount"],
                },
                "console": {
                    "type": "object",
                    "properties": {
                        "class": {"type": "string"},
                        "level": {
                            "type": "string",
                            "enum": ["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"],
                        },
                        "formatter": {"type": "string"},
                        "stream": {"type": "string"},
                    },
                    "required": ["class", "formatter", "stream"],
                },
            },
            "required": ["file"],
        },
        "root": {
            "type": "object",
            "properties": {
                "level": {
                    "type": "string",
                    "enum": ["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"],
                },
                "handlers": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["level", "handlers"],
        },
    },
}
