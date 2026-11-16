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
"""Packages related to database operations"""

import json
import secrets
import string
import time
from collections import OrderedDict
from dataclasses import dataclass, field

import psycopg2
from psycopg2.errors import SerializationFailure  # pylint:disable=E0611
from psycopg2.extras import DictCursor
from policymanager.common.dateutil import DATETIME_STR_FORMAT, get_now


from policymanager.common.config_reader import PolicyConfigReader
from policymanager.common.const import IdParameter
from policymanager.common.custom_exceptions import (
    DuplicatePolicyException,
    IdNotFoundException,
    InvalidOperationException,
    UnmatchIdException,
)
from policymanager.common.plugin import Plugin
from policymanager.common.schemas.combination_schema import validate_category_policy
from policymanager.plugins.base import BasePolicyPlugin
from policymanager.common.logger import Logger

TABLE_NAME = "policies"
ID_NOT_SPECIFIED = "-"
# DB connection retry interval, DB connection retry limit
INTERVAL_RETRY_CONNECT, LIMIT_RETRY_CONNECT = 5, 5
# Query execution retry interval, query execution retry limit
INTERVAL_RETRY_QUERY, LIMIT_RETRT_QUERY = 0.1, 5


@dataclass
class PolicyRecord:
    """Policy data record"""

    # pylint: disable=C0103
    policyID: str = None
    category: str = None
    title: str = None
    policy: dict = None
    enabled: bool = None


@dataclass
class GetAllOption:
    """Get all options class"""

    # pylint: disable=C0103
    category: list = field(default_factory=lambda: ["all"])
    enabled: str = "all"
    subCategory: str = None
    device: str = None
    fields: list = None
    sortBy: str = "createdAt"
    orderBy: str = "desc"
    limit: int = None
    offset: int = 0


class DbAccess:
    """Connection to the policy database."""

    def __init__(self, logger: Logger):
        """Constructor."""
        self.conn = None
        self.cur = None
        self.logger = logger

    def register(self, category: str, title: str, policy: dict, enabled: bool) -> str:
        """Add policy to the database.

        Args:
            category (str): Category of the policy to register.
            title (str): Title of the policy to register.
            policy (dict): The policy to register.
            enabled (bool): Enabled or disabled state of the policy.

        Returns:
            str: The ID of the registered policy.
        """
        self.open_db_connection()

        # If it completes successfully up to the commit, it will exit the while loop.
        while True:
            policy_rec = PolicyRecord(self._get_randomname(), category, title, policy, enabled)
            try:
                self._insert_policy(policy_rec)
                self.logger.debug(f"Added a new policy (ID) : {policy_rec.policyID}")
                self.conn.commit()
                break
            except psycopg2.IntegrityError:
                self.logger.debug(f"Reissued  policy (ID) : {policy_rec.policyID}")
                continue
            except DuplicatePolicyException as err:
                self.conn.rollback()
                self.close()
                raise err
            except SerializationFailure:
                self.conn.rollback()
                continue

        self.close()
        return policy_rec.policyID

    # pylint: disable=C0103
    def change_enabled(self, enableIDList: list, disableIDList: list):
        """Update the enabled/disabled state of the policy in the database.

        Args:
            enableIdList (list): List of policy IDs to enable.
            disableIdList (list): List of policy IDs to disable.

        Raises:
            IdNotFoundException: Raise when specified ID does not exist.
        """
        self.open_db_connection()
        # If it completes successfully up to the commit, it will exit the while loop.
        while True:
            try:
                if enableIDList:
                    self._update_id_list(enableIDList, "True")
                if disableIDList:
                    self._update_id_list(disableIDList, "False")
                self.conn.commit()
                break
            except SerializationFailure:
                self.conn.rollback()
                continue

        self.close()

    def _update_id_list(self, id_list, enabled_str: str):
        """Update enabled state for a list of policy.

        Args:
            id_list (list): List of IDs to update.
            enabled_str (str): Update value for the enabled column.

        Raises:
            UnmatchIDException: Raise when specified ID does not exist.
        """
        self._execute_query(
            "SELECT policyID FROM " + TABLE_NAME + " WHERE policyID IN %s",
            params=[(*id_list,)],
        )
        check_ids = self.cur.fetchall()
        # Check the number of entries retrieved from the DB against the ID list.
        if len(id_list) != self.cur.rowcount:
            valid_ids = []
            for row in check_ids:
                valid_ids.append(row[0])
            self.close()
            raise UnmatchIdException(set(id_list).difference(set(valid_ids)))
        self._execute_query(
            "UPDATE " + TABLE_NAME + " SET enabled = %s, updatedAt=%s WHERE policyID IN %s",
            params=[enabled_str, get_now(), (*id_list,)],
            need_rollback=True,
        )

    # pylint: disable=C0103
    def get_policy(self, policyID: str) -> dict:
        """Retrieve a policy by a specified ID.

        Args:
            policyID (str): The ID of the policy to retrieve.

        Raises:
            IdNotFoundException: Raise when specified ID does not exist.

        Returns:
            dict: The retrieved policy.
        """

        self.open_db_connection()
        select_query = (
            "SELECT policyID, category, title, policy, enabled, createdAt, updatedAt "
            f"FROM {TABLE_NAME} "
            "WHERE policyID = %s"
        )
        self.execute_query_auto_retry_on_serializationfailure(select_query, params=[policyID])
        results = self.cur.fetchone()
        if results is None:
            self.close()
            raise IdNotFoundException(policyID)

        policy = self._normalize_db_result(results)
        self.logger.debug(f"Get Data : {policy}")
        self.close()
        return policy

    # pylint: disable=C0103, disable=W0102
    def get_all_policy(self, options: GetAllOption):
        """Get all policy policy
        Retrieves all policy policy matching the specified conditions from the policy database

        Args:
            options (GetAllOption): Options for get policies
        Returns:
            dict: Retrieved policy policy
        """
        self.open_db_connection()
        if options.fields:
            select_query = "SELECT " f"{', '.join(options.fields)} " f"FROM {TABLE_NAME} AS tbl_data "
        else:
            select_query = (
                "SELECT "
                "policyID,category,title,policy,enabled,createdAt,updatedAt "
                f"FROM {TABLE_NAME} AS tbl_data "
            )

        params = []
        search_conditions, where_conditions = self._create_search_conditions(
            options.category,
            options.enabled,
            options.subCategory,
            options.device,
            params,
        )

        if search_conditions:
            select_query += ", " + search_conditions

        if where_conditions:
            select_query += " WHERE " + where_conditions

        select_query += f" ORDER BY {options.sortBy} {options.orderBy}"
        select_query += f" LIMIT {options.limit or 'ALL'} OFFSET {options.offset}"

        self.execute_query_auto_retry_on_serializationfailure(select_query.strip(), params)
        results = self.cur.fetchall()
        policies = [self._normalize_db_result(row, options.fields) for row in results]

        self.logger.debug(f"Get Data: {policies}")

        self.close()
        return {"count": len(policies), "policies": policies}

    def _create_search_conditions(
        self,
        category: str,
        enabled: str,
        subCategory: str,
        device: str,
        params: list,
    ) -> tuple:
        """Create search and WHERE conditions for the get_all_policy method
         based on the input parameters.

        Args:
            category (str): Policy's category.
            enabled (str): Policy's enabled flag.
            subCategory (str): Policy's subCategory.
            device (str): Policy's device.
            params (list): List of parameters for query.

        Returns:
            tuple: Tuple with two strings, search conditions and WHERE conditions.
        """
        search_conditions = []

        # Creating search conditions query
        if subCategory or device:
            search_conditions.append("jsonb_each(tbl_data.policy) AS tbl_subCategory")
            if device:
                search_conditions.append("jsonb_each(tbl_subCategory.value) AS tbl_devices")

        # If subCategory or device has been specified adding to params
        where_conditions = self._handle_subCategory_device_params(subCategory, device, params)

        if not "all" in category:  # noqa:E713
            where_conditions.append("tbl_data.category IN %s")
            params.append(tuple(category))

        if enabled != "all":
            where_conditions.append("tbl_data.enabled = %s")
            params.append(enabled)

        return ", ".join(search_conditions), " AND ".join(where_conditions)

    def _handle_subCategory_device_params(self, subCategory: str, device: str, params: list) -> list:
        """Helper function to handle where_conditions and params for subCategory and device.

        Args:
            subCategory (str): Policy's subCategory.
            device (str): Policy's device.
            params (list): List of parameters for query.

        Returns:
            list: List of WHERE conditions related to subCategory and device.
        """
        where_conditions = []

        if subCategory and device:
            where_conditions.extend(["tbl_devices.key = %s", "tbl_subCategory.key = %s"])
            params.extend([device, subCategory])
        elif subCategory:
            where_conditions.append("tbl_subCategory.key = %s")
            params.append(subCategory)
        elif device:
            where_conditions.append("tbl_devices.key = %s")
            # fmt: off
            key_list = [
                "cpu", "memory", "storage", "gpu", "fpga", "accelerator", "dsp",
                "virtualMedia", "graphicController", "networkInterface"
            ]
            # fmt: on
            device_upper_dict = {key.upper(): key for key in key_list}
            device = device_upper_dict[device.upper()]
            params.append(device)

        return where_conditions

    # pylint: disable=C0103, disable=W0102
    def get_policy_count(self, options: GetAllOption):
        """Get policy total count
        Get the number of policy registerd in the database

        Args:
            options (GetAllOption): Options for get policies
        Returns:
            dict: Retrieved policy totalCount
        """
        self.open_db_connection()
        select_query = "SELECT COUNT(*) " f"FROM {TABLE_NAME} AS tbl_data "

        params = []
        search_conditions, where_conditions = self._create_search_conditions(
            options.category,
            options.enabled,
            options.subCategory,
            options.device,
            params,
        )

        if search_conditions:
            select_query += ", " + search_conditions

        if where_conditions:
            select_query += " WHERE " + where_conditions

        self.execute_query_auto_retry_on_serializationfailure(select_query.strip(), params)
        result = self.cur.fetchone()

        self.logger.debug("Get Data:", result[0])

        self.close()
        return {"totalCount": result[0]}

    def update(
        self,
        policyID: str,
        category: str,
        title: str,
        policy: dict,
        force: bool,
    ):  # pylint: disable=C0103
        """Update policy
        Updates the policy stored in the policy database.

        Args:
            policyID (str): ID of the policy to update
            category (str): Category of the policy to update
            title (str): Title of the policy to update
            policy (dict): Policy to update
            force (bool): Force Update Flag

        Raises:
            IdNotFoundException: Occurs when a non-existent ID has been specified
            DuplicatePolicyException: Occurs when the specified policy is duplicated
            with an already registered policy
        """

        get_policy = self.get_policy(policyID)

        # If category and policy has not been specified skipping validation
        if not (category is None and policy is None):
            # Validate specified category and policy
            # Otherwise, perform validation on the category and policy
            # conditions retrieved from the database for consistency checking
            validate_category_policy(
                (category or get_policy["category"]),
                (policy or get_policy["policy"]),
            )

        self.open_db_connection()

        params = []
        date = get_now()
        update_query = f"UPDATE {TABLE_NAME} SET "
        update_query += self._create_update_query(category, title, policy, policyID, params)

        update_query += ", updatedAt = %s WHERE policyID = %s" + (" AND enabled = False" if not force else "")
        params.extend([date, policyID])

        # If it completes successfully up to the commit, it will exit the while loop.
        while True:
            try:
                self._execute_query(update_query, params)
                self._check_update_result(policyID, policy)
                self.conn.commit()
                break
            except DuplicatePolicyException as err:
                self.conn.rollback()
                raise err
            except SerializationFailure:
                self.conn.rollback()
                continue
        self.close()

    def _check_update_result(self, policyID: str, policy: dict):
        """Check if it has been updated properly.

        Args:
            policyID (str): ID of the policy to update
            policy (dict): Policy to update
        Raises:
            InvalidOperationException: It occurs when trying to update active status conditions with force set to False.
        """
        # After updating, the number of updated records is returned
        if self.cur.rowcount == 0:
            raise InvalidOperationException(policyID)
        if policy:
            self.check_for_duplication_policy(policy=policy, policyID=policyID)

    def delete(self, policyID: str, force: bool):  # pylint: disable=C0103
        """Remove policy.
         Remove the specified policy.

        Args:
            policyID (str): ID of the policy you want to delete
            force (bool): Force delete Flag

        Raises:
            IdNotFoundException: Occurs when a non-existent ID is specified.
            InvalidOperationException: Occurs when a validity policy is specified with Force set to False.
        """

        _ = self.get_policy(policyID)
        self.open_db_connection()
        delete_query = f"DELETE FROM {TABLE_NAME} " "WHERE policyID = %s"
        if not force:
            delete_query += " AND enabled = False"

        self.execute_query_auto_retry_on_serializationfailure(delete_query, params=[policyID], auto_commit=True)
        try:
            self.get_policy(policyID)
        except IdNotFoundException:
            pass
        else:
            raise InvalidOperationException(policyID)

        self.close()

    def export(self):  # pylint: disable=W0622
        """Export Policy

        Returns:
            export_policies: export policies

        """
        export_policies = {}

        policies = self.get_all_policy(GetAllOption())
        export_policies = {
            "exportedCount": policies["count"],
            "policies": policies["policies"],
        }

        return export_policies

    def _import_policy(self, policy_list: list):
        """Import Policy

        Args:
            policy_list (list): Policies list

        Raises:
            err: Duplicated error

        Returns:
            list: Import result details list
        """
        # pylint: disable=C0103
        self.open_db_connection()
        details_result = []
        plugin = Plugin(BasePolicyPlugin, DbAccess(self.logger))
        for policy_data in policy_list:
            policy_rec = PolicyRecord(
                policy_data.get("policyID", ID_NOT_SPECIFIED),
                policy_data.get("category"),
                policy_data.get("title"),
                policy_data.get("policy"),
                policy_data.get("enabled"),
            )

            msg = "completed"
            old_policyID = policy_rec.policyID
            if policy_rec.policyID == ID_NOT_SPECIFIED:
                policy_rec.policyID = self._get_randomname()
                msg = f"New policyID has been issued: {policy_rec.policyID}"

            # First duplicate check with the database
            try:
                plugin.validate_dupliction(policy=policy_rec.policy)
            except DuplicatePolicyException:
                self._create_detail(
                    details_result,
                    policy_rec.policyID,
                    "Skipped due to duplicate database and input data",
                )
                continue
            self._import_insert_policy(policy_rec, details_result, old_policyID, msg)
        self.conn.commit()
        self.close()
        return details_result

    def import_policy(
        self,
        policy_list: list,
    ):
        """import policy

        Args:
            policy_list (list): Policies list

        Returns:
            list: Import result details list
        """
        while True:
            try:
                details_result = self._import_policy(policy_list)
                break
            except SerializationFailure:
                self.conn.rollback()
                continue
        return details_result

    def _import_insert_policy(
        self, policy_rec: PolicyRecord, details_result: list, old_policyID: str, msg: str
    ):  # pylint: disable=C0103
        """Insert policy from import file

        Args:
            policy_record (PolicyRecord): policy data record
            details_result (list): details result list
            old_policyID (str): old policy
            msg (str): message for detail resutl

        Raises:
            DuplicatePolicyException: Occurs when duplicated with DB for second time
        """
        is_policyID_reissued = False
        query_retry_cnt = 0
        self._execute_query("SAVEPOINT policy_savepoint")
        while True:
            try:
                self._insert_policy(policy_rec)
                if not is_policyID_reissued:
                    self._create_detail(details_result, old_policyID, msg)
                self.logger.debug(f"Added policy from import file (ID) : {policy_rec.policyID}")
                is_policyID_reissued = False
                break

            # If there is a duplicate check with the policyID on the DB side, reissue the ID.
            except psycopg2.IntegrityError:
                policy_rec.policyID = self._get_randomname()
                self.logger.debug(f"Reissued  policy (ID) : {policy_rec.policyID}")
                self._create_detail(
                    details_result,
                    old_policyID,
                    f"policyID was reissued because of duplication {policy_rec.policyID}",
                )

                self._execute_query("ROLLBACK TO SAVEPOINT policy_savepoint")
                is_policyID_reissued = True
                continue

            except DuplicatePolicyException as err:
                self.conn.rollback()
                self.close()
                raise DuplicatePolicyException(
                    [
                        {
                            "policyID": old_policyID,
                            "message": err.message,
                        }
                    ]
                ) from err
            # If a SerializationFailure occurs, catch the error and retry the query execution.
            # If it fails more than 5 times, start over from the beginning.
            except SerializationFailure as err:
                self._execute_query("ROLLBACK TO SAVEPOINT policy_savepoint")
                if query_retry_cnt >= LIMIT_RETRT_QUERY:
                    raise err
                time.sleep(INTERVAL_RETRY_QUERY)
                query_retry_cnt += 1
                continue

        self._execute_query("RELEASE SAVEPOINT policy_savepoint")

    def _create_detail(self, details: list, id_: str, msg: str):
        """Creating details result

        Args:
            details (list): details result list
            id_ (str): policyID
            msg (str): message
        """
        details.append({"policyID": id_, "message": msg})

    def _insert_policy(self, policy_record: PolicyRecord):
        """Insert a policy into database

        Args:
            policy_record (PolicyRecord): policy data record
        """
        insert_query = (
            f"INSERT INTO {TABLE_NAME} "
            "(policyID, category, title, policy, enabled, createdAt, updatedAt) "
            "VALUES"
            "(%s,%s,%s,%s,%s,%s,%s)"
        )

        self._execute_query(
            query=insert_query,
            params=[
                policy_record.policyID,
                policy_record.category,
                policy_record.title,
                json.dumps(policy_record.policy),
                policy_record.enabled,
                get_now(),
                get_now(),
            ],
        )
        self.check_for_duplication_policy(policy_record.policy, policy_record.policyID)

    def _execute_query(self, query, params=None, need_rollback=False):
        """Execute query.

        Args:
            query (str): Query string.
            params (Any, optional): Parameters. Defaults to None.
            need_rollback (bool, optional): Rollback on error. Defaults to False.

        Raises:
            error: psycopg2.ProgrammingError
        """
        self.logger.info(f"query : {query}, vars: {params}")
        try:
            result = self.cur.execute(query=query, vars=params)
        except psycopg2.ProgrammingError as error:
            msg = (
                "[E10004]Query failed:"
                + error.pgcode
                + " Check PostgreSQL's error code table \
                [https://pgsql-jp.github.io/current/html/errcodes-appendix.html]"
            )
            self.logger.error(msg)
            if need_rollback:
                self.conn.rollback()
            self.close()
            raise error

        return result

    def execute_query_auto_retry_on_serializationfailure(
        self,
        query,
        params=None,
        need_rollback=False,
        auto_commit=False,
    ):
        """Execute query.

        Args:
            query (str): Query string.
            params (Any, optional): Parameters. Defaults to None.
            need_rollback (bool, optional): Rollback on error. Defaults to False.
            auto_commit (bool, optional): auto commit flag. Defaults to False.
        """
        while True:
            try:
                self._execute_query(query, params, need_rollback)
                if auto_commit:
                    self.conn.commit()
                break
            except SerializationFailure:
                self.conn.rollback()
                continue

    def open_db_connection(self, cnt: int = 0):
        """Connect to the policy management database.
        Args:
            cnt (int): Connect DB retry count
        Raises:
            err: Error occurs when could not connect to Db
        """

        db_config = PolicyConfigReader().get_db_config
        try:
            self.conn = psycopg2.connect(**db_config)
            self.cur = self.conn.cursor(cursor_factory=DictCursor)
            self._execute_query("set transaction isolation level SERIALIZABLE")
        except psycopg2.OperationalError as err:
            if cnt >= LIMIT_RETRY_CONNECT:
                self.logger.error("[E10003]Could not connect to PolicyDB")
                raise err
            cnt += 1
            self.logger.info(f"Could not connect to PolicyDB.Reconnecting count: {cnt}")
            time.sleep(INTERVAL_RETRY_CONNECT)
            self.open_db_connection(cnt)

    def close(self):
        """Disconnect from the policy database."""
        self.cur.close()
        self.conn.close()
        self.logger.info("DB connection closed")

    def _get_randomname(self, length: int = IdParameter.LENGTH) -> str:
        """Generate a random string.

        Args:
            length (int): String length

        Returns:
            str: The generated string
        """
        randlst = [secrets.choice(string.hexdigits) for i in range(length)]
        return "".join(randlst).lower()

    def _normalize_db_result(self, row, fields: list = None) -> dict:
        """Normalize the order and key names of the retrieved policy

        Args:
            row (tuple): Row retrieved from the database
            fields (list, optional): List of fields for the SELECT query. Defaults to None.

        Returns:
            dict: Normalized policy
        """
        if fields:
            fields_lower = [f.lower() for f in fields]
            policy = dict(zip(fields_lower, row))
        else:
            policy = dict(row)

        # Map lowercased field names to their correct names
        field_mapping = {
            "policyid": "policyID",
            "createdat": "createdAt",
            "updatedat": "updatedAt",
        }

        for key in list(field_mapping.keys()):
            if key in policy:
                policy[field_mapping[key]] = policy.pop(key)

        # Format datetime values
        for field in ["createdAt", "updatedAt"]:  # pylint: disable=W0621 # NOQA
            if field in policy:
                policy[field] = policy[field].strftime(DATETIME_STR_FORMAT)

        # Reorder the dictionary keys
        ordered_policy = OrderedDict()
        if "policyID" in list(policy.keys()):
            ordered_policy["policyID"] = policy.pop("policyID")
        ordered_policy.update(policy)

        return dict(ordered_policy)

    def _create_update_query(  # pylint: disable=C0103
        self,
        category: str,
        title: str,
        policy: dict,
        policyID: str,
        params: list,
    ) -> str:
        """Create an update query

        Args:
            category (str): Policy's category
            title (str): Policy's title
            policy (dict): Policy
            policyID (str): Policy's ID
            params (list): List of parameters for query

        Returns:
            str: Created query
        """
        field_mapping = {
            "category": category,
            "title": title,
            "policy": json.dumps(policy) if policy else None,
        }

        update_query_fields = []

        for field_name, field_value in field_mapping.items():
            if field_value:
                update_query_fields.append(f"{field_name} = %s")
                params.append(field_value)

        # Check for duplicated policy if policy is not None
        if policy:
            self.check_for_duplication_policy(policy=policy, policyID=policyID)

        update_query = ", ".join(update_query_fields)

        return update_query

    def check_for_duplication_policy(self, policy: dict, policyID: str = None, assumed_count: int = 1):
        """Check for duplication of policy

        Args:
            policy (dict): policy
            policyID (str, optional): Define this parameter while using the update function.
            Defaults to None
            assumed_count (int, optional): Assumed count for check. Defaults to 1

        Raises:
            DuplicatePolicyException: Occurs when the policy is duplicated with a registered policy
        """
        check_duplicate_query = (
            f"SELECT policyID FROM {TABLE_NAME} AS "
            "tbl_data, jsonb_each(policy) AS tbl_subCategory, "
            "jsonb_each(tbl_subCategory.value) AS tbl_devices "
            "WHERE tbl_subCategory.key = %s AND tbl_devices.key IN %s"
        )

        # Extract sub_category from the policy
        sub_category, devices_dict = list(policy.items())[0]
        devices = list(devices_dict.keys())

        query_params = [sub_category, tuple(devices)]
        if policyID:
            check_duplicate_query += " AND tbl_data.policyID != %s"
            query_params.append(policyID)

        self._execute_query(check_duplicate_query, params=query_params)

        if self.cur.rowcount >= assumed_count:
            results = self.cur.fetchall()
            duplicated_ids = [row[0] for row in results]
            raise DuplicatePolicyException(
                (f"Specified policy is duplicate of {', '.join(set(duplicated_ids))}" " registered in the database")
            )
