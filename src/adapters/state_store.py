import boto3
import time
from decimal import Decimal
from typing import Any, Dict, List, Optional, Union
from botocore.exceptions import ClientError
from models.request import AccessRequest
from models.request_states import (
    STATE_ACTIVE,
    STATE_REVOKED,
    can_transition,
    canonicalize_status,
    is_valid_status,
    status_equivalents,
)

class StateStore:
    """
    The 'Memory' of the system.
    Adapter for DynamoDB that handles storing and retrieving access request state.
    """
    def __init__(self, table_name: str, region_name: str = "us-east-1"):
        self.dynamodb = boto3.resource("dynamodb", region_name=region_name)
        self.table = self.dynamodb.Table(table_name)
    
    def _float_to_decimal(self, val: float) -> Decimal:
        """DynamoDB requires Decimal for numbers, not Python floats."""
        return Decimal(str(val))

    def _normalize_for_ddb(self, value: Any) -> Any:
        if isinstance(value, float):
            return self._float_to_decimal(value)
        return value

    def _query_requests_index(
        self,
        *,
        index_name: str,
        partition_attr: str,
        partition_value: str,
        start_created_at: Optional[float] = None,
        end_created_at: Optional[float] = None,
        limit: int = 50,
        next_key: Optional[Dict[str, Any]] = None,
        ascending: bool = False,
    ) -> Dict[str, Any]:
        """
        Generic GSI query helper for API read paths.
        Supports partition-only, bounded time range, and pagination.
        """
        if limit <= 0:
            raise ValueError("limit must be greater than 0")
        if start_created_at is not None and end_created_at is not None and start_created_at > end_created_at:
            raise ValueError("start_created_at cannot be greater than end_created_at")

        expression_names: Dict[str, str] = {"#pk": partition_attr}
        expression_values: Dict[str, Any] = {":pk": partition_value}
        key_condition = "#pk = :pk"

        if start_created_at is not None and end_created_at is not None:
            expression_names["#created"] = "created_at"
            expression_values[":start"] = self._normalize_for_ddb(start_created_at)
            expression_values[":end"] = self._normalize_for_ddb(end_created_at)
            key_condition = "#pk = :pk AND #created BETWEEN :start AND :end"
        elif start_created_at is not None:
            expression_names["#created"] = "created_at"
            expression_values[":start"] = self._normalize_for_ddb(start_created_at)
            key_condition = "#pk = :pk AND #created >= :start"
        elif end_created_at is not None:
            expression_names["#created"] = "created_at"
            expression_values[":end"] = self._normalize_for_ddb(end_created_at)
            key_condition = "#pk = :pk AND #created <= :end"

        query_kwargs: Dict[str, Any] = {
            "IndexName": index_name,
            "KeyConditionExpression": key_condition,
            "ExpressionAttributeNames": expression_names,
            "ExpressionAttributeValues": expression_values,
            "Limit": limit,
            "ScanIndexForward": ascending,
        }
        if next_key:
            query_kwargs["ExclusiveStartKey"] = next_key

        try:
            response = self.table.query(**query_kwargs)
            return {
                "items": response.get("Items", []),
                "next_key": response.get("LastEvaluatedKey"),
            }
        except ClientError as e:
            raise Exception(f"Failed to query index {index_name}: {e}")

    def save_request(self, request: AccessRequest):
        """
        Writes a new access request to DynamoDB.
        Idempotent: If request_id exists, it overwrites (useful for status updates).
        """
        now = time.time()
        status = canonicalize_status(request.status)
        item = {
            "request_id": request.request_id,
            "principal_id": request.principal_id,
            "principal_type": request.principal_type,
            "permission_set_arn": request.permission_set_arn,
            "permission_set_name": request.permission_set_name,
            "account_id": request.account_id,
            "instance_arn": request.instance_arn,
            "rule_id": request.rule_id,
            "status": status,
            "ticket_id": request.ticket_id or "N/A",
            # Convert floats to Decimal for DynamoDB
            "requested_at": self._float_to_decimal(request.requested_at),
            "created_at": self._float_to_decimal(request.created_at if request.created_at is not None else request.requested_at),
            "updated_at": self._float_to_decimal(request.updated_at if request.updated_at is not None else now),
            "expires_at": self._float_to_decimal(request.expires_at),
            "ttl": int(request.expires_at + (86400 * 90)) # Auto-delete after 90 days
        }

        if request.slack_user_id:
            item["slack_user_id"] = request.slack_user_id
        if request.requester_slack_user_id:
            item["requester_slack_user_id"] = request.requester_slack_user_id
        if request.slack_response_url:
            item["slack_response_url"] = request.slack_response_url
        if request.approval_required:
            item["approval_required"] = request.approval_required
        if request.approval_channel:
            item["approval_channel"] = request.approval_channel
        if request.approver_group:
            item["approver_group"] = request.approver_group
        if request.approver_slack_user_id:
            item["approver_slack_user_id"] = request.approver_slack_user_id
        if request.approved_by:
            item["approved_by"] = request.approved_by
        if request.approved_at is not None:
            item["approved_at"] = self._float_to_decimal(request.approved_at)
        if request.denied_by:
            item["denied_by"] = request.denied_by
        if request.denied_at is not None:
            item["denied_at"] = self._float_to_decimal(request.denied_at)
        if request.reason:
            item["reason"] = request.reason
        if request.policy_hash:
            item["policy_hash"] = request.policy_hash
        if request.engine_version:
            item["engine_version"] = request.engine_version
        if request.evaluated_at:
            item["evaluated_at"] = request.evaluated_at
        if request.revoked_at is not None:
            item["revoked_at"] = self._float_to_decimal(request.revoked_at)

        try:
            self.table.put_item(Item=item)
        except ClientError as e:
            raise Exception(f"Failed to save state to DynamoDB: {e}")

    def update_status(
        self,
        request_id: str,
        new_status: str,
        extra_updates: Optional[Dict[str, Union[str, float, int, Decimal]]] = None,
    ):
        """
        Updates the status of a request (e.g., PENDING -> ACTIVE -> REVOKED).
        Optionally sets additional attributes provided via *extra_updates*.
        """
        canonical_new_status = canonicalize_status(new_status)
        if not is_valid_status(canonical_new_status):
            raise ValueError(f"Invalid status: {new_status}")

        # Fetch current item for optimistic locking
        item = self.get_request(request_id)
        if not item:
            raise ValueError(f"Request {request_id} not found")

        expression_names: Dict[str, str] = {"#s": "status", "#u": "updated_at"}
        expression_values: Dict[str, Any] = {
            ":status": canonical_new_status,
            ":updated_at": self._float_to_decimal(time.time()),
        }
        set_clauses = ["#s = :status", "#u = :updated_at"]

        if canonical_new_status == STATE_REVOKED and not (extra_updates and "revoked_at" in extra_updates):
            expression_names["#r"] = "revoked_at"
            expression_values[":revoked_at"] = self._float_to_decimal(time.time())
            set_clauses.append("#r = :revoked_at")

        if extra_updates:
            idx = 0
            for key, value in extra_updates.items():
                name_key = f"#k{idx}"
                value_key = f":v{idx}"
                expression_names[name_key] = key
                expression_values[value_key] = self._normalize_for_ddb(value)
                set_clauses.append(f"{name_key} = {value_key}")
                idx += 1

        # Build a ConditionExpression so the write only succeeds if the
        # current status still matches what we read (guards against TOCTOU).
        condition_expression = None
        if item and item.get("status"):
            current_status = canonicalize_status(item["status"])
            current_variants = sorted(status_equivalents(current_status))
            condition_checks = []
            for vidx, variant in enumerate(current_variants):
                key = f":cur_status_{vidx}"
                expression_values[key] = variant
                condition_checks.append(f"#s = {key}")
            condition_expression = " OR ".join(condition_checks)

        try:
            update_kwargs: Dict[str, Any] = {
                "Key": {"request_id": request_id},
                "UpdateExpression": f"SET {', '.join(set_clauses)}",
                "ExpressionAttributeNames": expression_names,
                "ExpressionAttributeValues": expression_values,
            }
            if condition_expression:
                update_kwargs["ConditionExpression"] = condition_expression
            self.table.update_item(**update_kwargs)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise ValueError(
                    f"Concurrent status change detected for {request_id}: "
                    f"status was modified after read. Retry the operation."
                )
            raise Exception(f"Failed to update status for {request_id}: {e}")

    def get_expired_active_requests(self) -> List[dict]:
        """
        THE JANITOR QUERY.
        Finds all requests where status='ACTIVE' AND expires_at < now.
        Uses the GSI 'ExpirationIndex' for efficiency.
        """
        now = self._float_to_decimal(time.time())
        
        try:
            response = self.table.query(
                IndexName="ExpirationIndex",
                KeyConditionExpression="#s = :active AND expires_at < :now",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":active": STATE_ACTIVE,
                    ":now": now
                }
            )
            return response.get("Items", [])
        except ClientError as e:
            print(f"Error querying expired requests: {e}")
            return []

    def list_requests_by_status(
        self,
        status: str,
        start_created_at: Optional[float] = None,
        end_created_at: Optional[float] = None,
        limit: int = 50,
        next_key: Optional[Dict[str, Any]] = None,
        ascending: bool = False,
    ) -> Dict[str, Any]:
        """
        API query path: list requests by status and optional created_at range.
        """
        canonical_status = canonicalize_status(status)
        if not is_valid_status(canonical_status):
            raise ValueError(f"Invalid status filter: {status}")

        return self._query_requests_index(
            index_name="StatusCreatedAtIndex",
            partition_attr="status",
            partition_value=canonical_status,
            start_created_at=start_created_at,
            end_created_at=end_created_at,
            limit=limit,
            next_key=next_key,
            ascending=ascending,
        )

    def list_requests_by_account(
        self,
        account_id: str,
        start_created_at: Optional[float] = None,
        end_created_at: Optional[float] = None,
        limit: int = 50,
        next_key: Optional[Dict[str, Any]] = None,
        ascending: bool = False,
    ) -> Dict[str, Any]:
        """
        API query path: list requests by account_id and optional created_at range.
        """
        if not account_id:
            raise ValueError("account_id is required")

        return self._query_requests_index(
            index_name="AccountCreatedAtIndex",
            partition_attr="account_id",
            partition_value=account_id,
            start_created_at=start_created_at,
            end_created_at=end_created_at,
            limit=limit,
            next_key=next_key,
            ascending=ascending,
        )

    def list_requests_by_requester(
        self,
        requester_slack_user_id: str,
        start_created_at: Optional[float] = None,
        end_created_at: Optional[float] = None,
        limit: int = 50,
        next_key: Optional[Dict[str, Any]] = None,
        ascending: bool = False,
    ) -> Dict[str, Any]:
        """
        API query path: list requests by requester Slack ID and optional created_at range.
        """
        if not requester_slack_user_id:
            raise ValueError("requester_slack_user_id is required")

        return self._query_requests_index(
            index_name="RequesterCreatedAtIndex",
            partition_attr="requester_slack_user_id",
            partition_value=requester_slack_user_id,
            start_created_at=start_created_at,
            end_created_at=end_created_at,
            limit=limit,
            next_key=next_key,
            ascending=ascending,
        )

    def list_requests_by_permission_set(
        self,
        permission_set_name: str,
        start_created_at: Optional[float] = None,
        end_created_at: Optional[float] = None,
        limit: int = 50,
        next_key: Optional[Dict[str, Any]] = None,
        ascending: bool = False,
    ) -> Dict[str, Any]:
        """
        API query path: list requests by permission set name and optional created_at range.
        """
        if not permission_set_name:
            raise ValueError("permission_set_name is required")

        return self._query_requests_index(
            index_name="RoleCreatedAtIndex",
            partition_attr="permission_set_name",
            partition_value=permission_set_name,
            start_created_at=start_created_at,
            end_created_at=end_created_at,
            limit=limit,
            next_key=next_key,
            ascending=ascending,
        )

    def get_request(self, request_id: str) -> Optional[dict]:
        """Fetches a single request item by request_id."""
        try:
            response = self.table.get_item(Key={"request_id": request_id})
            return response.get("Item")
        except ClientError as e:
            raise Exception(f"Failed to fetch request {request_id}: {e}")

    def transition_status_if_current(
        self,
        request_id: str,
        expected_status: str,
        new_status: str,
        extra_updates: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Atomically transitions a request status only if current status matches expected_status.
        Returns False when the condition fails (race-safe for approval button clicks).
        """
        expression_names = {"#status": "status"}
        expected_canonical = canonicalize_status(expected_status)
        new_canonical = canonicalize_status(new_status)

        if not is_valid_status(expected_canonical) or not is_valid_status(new_canonical):
            raise ValueError(f"Invalid status transition requested: {expected_status} -> {new_status}")
        if not can_transition(expected_canonical, new_canonical):
            raise ValueError(f"Invalid status transition requested: {expected_canonical} -> {new_canonical}")

        expression_values: Dict[str, Any] = {
            ":new_status": new_canonical,
            ":updated_at": self._float_to_decimal(time.time()),
        }
        set_clauses = ["#status = :new_status", "#updated_at = :updated_at"]
        expression_names["#updated_at"] = "updated_at"

        expected_variants = sorted(status_equivalents(expected_canonical))
        condition_checks = []
        for idx, value in enumerate(expected_variants):
            expected_key = f":expected_status_{idx}"
            expression_values[expected_key] = value
            condition_checks.append(f"#status = {expected_key}")

        if extra_updates:
            idx = 0
            for key, value in extra_updates.items():
                name_key = f"#k{idx}"
                value_key = f":v{idx}"
                expression_names[name_key] = key
                expression_values[value_key] = self._normalize_for_ddb(value)
                set_clauses.append(f"{name_key} = {value_key}")
                idx += 1

        if new_canonical == STATE_REVOKED and not (extra_updates and "revoked_at" in extra_updates):
            expression_names["#revoked_at"] = "revoked_at"
            expression_values[":revoked_at"] = self._float_to_decimal(time.time())
            set_clauses.append("#revoked_at = :revoked_at")

        try:
            self.table.update_item(
                Key={"request_id": request_id},
                UpdateExpression=f"SET {', '.join(set_clauses)}",
                ConditionExpression=" OR ".join(condition_checks),
                ExpressionAttributeNames=expression_names,
                ExpressionAttributeValues=expression_values
            )
            return True
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False
            raise Exception(f"Failed to transition status for {request_id}: {e}")
