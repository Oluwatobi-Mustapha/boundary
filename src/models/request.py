from dataclasses import dataclass, field
from typing import Optional
import time
import uuid

@dataclass
class AccessRequest:
    """
    Represents an access request within the system.
    This mirrors the DynamoDB schema we designed in DATABASE_SCHEMA.md.
    
    Attributes:
        request_id: Unique UUID for the request.
        principal_id: The AWS Identity Center User GUID.
        principal_type: Usually 'USER'.
        permission_set_arn: The immutable ARN of the requested permission set.
        account_id: The target 12-digit AWS Account ID.
        instance_arn: The ARN of the SSO instance.
        rule_id: The ID of the rule from access_rules.yaml that authorized this.
        status: The current state (PENDING, ACTIVE, REVOKED, ERROR).
        ticket_id: Optional reference to an external ticket (Jira/ServiceNow).
        requested_at: Unix timestamp of the request creation.
        expires_at: Unix timestamp when access must be revoked.
    """
    request_id: str
    principal_id: str
    principal_type: str
    permission_set_arn: str
    account_id: str
    instance_arn: str
    rule_id: str
    status: str = "PENDING"
    ticket_id: Optional[str] = None
    requested_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    
    @staticmethod
    def create_id() -> str:
        """Generates a unique ID for the request."""
        return str(uuid.uuid4())

    def is_expired(self) -> bool:
        """Checks if the current time has passed the expiration timestamp."""
        return time.time() > self.expires_at