import boto3
import time
from decimal import Decimal
from typing import List, Optional
from botocore.exceptions import ClientError
from src.models.request import AccessRequest

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

    def save_request(self, request: AccessRequest):
        """
        Writes a new access request to DynamoDB.
        Idempotent: If request_id exists, it overwrites (useful for status updates).
        """
        item = {
            "request_id": request.request_id,
            "principal_id": request.principal_id,
            "principal_type": request.principal_type,
            "permission_set_arn": request.permission_set_arn,
            "permission_set_name": request.permission_set_name,
            "account_id": request.account_id,
            "instance_arn": request.instance_arn,
            "rule_id": request.rule_id,
            "status": request.status,
            "ticket_id": request.ticket_id or "N/A",
            # Convert floats to Decimal for DynamoDB
            "requested_at": self._float_to_decimal(request.requested_at),
            "expires_at": self._float_to_decimal(request.expires_at),
            "ttl": int(request.expires_at + (86400 * 90)) # Auto-delete after 90 days
        }

        try:
            self.table.put_item(Item=item)
        except ClientError as e:
            raise Exception(f"Failed to save state to DynamoDB: {e}")

    def update_status(self, request_id: str, new_status: str):
        """
        Updates just the status of a request (e.g., PENDING -> ACTIVE -> REVOKED).
        """
        try:
            self.table.update_item(
                Key={"request_id": request_id},
                UpdateExpression="set #s = :status",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":status": new_status}
            )
        except ClientError as e:
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
                    ":active": "ACTIVE",
                    ":now": now
                }
            )
            return response.get("Items", [])
        except ClientError as e:
            print(f"Error querying expired requests: {e}")
            return []