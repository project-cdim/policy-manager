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
"""pydantic data model"""
from typing import Optional
from jsonschema import validate

from pydantic import BaseModel, field_validator  # pylint:disable=E0611

from policymanager.common.schemas import (
    category_schema,
    enabled_schema,
    title_schema,
)


class IdList(BaseModel, extra="forbid"):
    """A data model that stores a list of policyn IDs to enable or disable"""

    enableIDList: Optional[list] = None
    disableIDList: Optional[list] = None


class InsertPolicies(BaseModel, extra="forbid"):
    """Data model for storing category, titles, and policy for adding policy"""

    category: str
    title: str
    policy: dict
    enabled: Optional[bool] = False

    @field_validator("category")
    def validate_category(cls, category):  # pylint:disable=E0213
        """Validation check for category

        Args:
            category (str): category

        Returns:
            str: category
        """

        validate(category, category_schema.category_schema)
        return category

    @field_validator("title")
    def validate_title(cls, title):  # pylint:disable=E0213
        """Title validation check

        Args:
            title (str): title

        Returns:
            str: title
        """
        validate(title, title_schema.title_schema)
        return title

    @field_validator("enabled")
    def validate_enabled(cls, enabled):  # pylint:disable=E0213
        """Validation check for enabled

        Args:
            enabled (bool):Active/inactive state
        """
        validate(enabled, enabled_schema.bool_schema)
        return enabled


class UpdaterPolicies(BaseModel, extra="forbid"):
    """A data model for storing category, titles, and policy for policy updates"""

    category: Optional[str] = None
    title: Optional[str] = None
    policy: Optional[dict] = None

    @field_validator("category")
    def validate_category(cls, category):  # pylint:disable=E0213
        """Validation check for category

        Args:
            category (str): category

        Returns:
            str: category
        """
        validate(category, category_schema.category_schema)
        return category

    @field_validator("title")
    def validate_title(cls, title):  # pylint:disable=E0213
        """Title validation check

        Args:
            title (str): title

        Returns:
            str: title
        """
        validate(title, title_schema.title_schema)
        return title


class GetAllPoliciesOptions(BaseModel, extra="forbid"):
    """A data model to store options of bulk policy retrieval"""

    enabled: Optional[str] = "all"
    subCategory: Optional[str] = None
    device: Optional[str] = None
    sortBy: Optional[str] = "createdAt"
    orderBy: Optional[str] = "desc"
    limit: Optional[int] = 20
    offset: Optional[int] = 0
