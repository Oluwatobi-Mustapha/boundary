from dataclasses import dataclass, field
from typing import Optional
import time
import uuid

from models.request_states import STATE_PENDING_APPROVAL, canonicalize_status


@dataclass
class AccessRequest:
    """
    Represents an access request within the system.
    This mirrors the DynamoDB schema we designed in DATABASE_SCHEMA.md.
    
    Attributes:
        request_id: Unique UUID for the request.
        principal_id: The AWS Identity Center User GUID.
        principal_type: Usually 'USER'.
        slack_user_id: Slack user ID for requester notifications (optional).
        permission_set_arn: The immutable ARN of the requested permission set.
        permission_set_name: Human-readable name (e.g., ReadOnlyAccess) used for policy matching.
        account_id: The target 12-digit AWS Account ID.
        instance_arn: The ARN of the SSO instance.
        rule_id: The ID of the rule from access_rules.yaml that authorized this.
        status: The current state in the access lifecycle.
        ticket_id: Optional reference to an external ticket (Jira/ServiceNow).
        requested_at: Unix timestamp of the request creation.
        expires_at: Unix timestamp when access must be revoked.
    """
    request_id: str
    principal_id: str
    principal_type: str
    permission_set_arn: str
    permission_set_name: str
    account_id: str
    instance_arn: str
    rule_id: str
    status: str = STATE_PENDING_APPROVAL
    ticket_id: Optional[str] = None
    slack_user_id: Optional[str] = None
    requester_slack_user_id: Optional[str] = None
    slack_response_url: Optional[str] = None
    approval_required: bool = False
    approval_channel: Optional[str] = None
    approver_group: Optional[str] = None
    approver_slack_user_id: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[float] = None
    denied_by: Optional[str] = None
    denied_at: Optional[float] = None
    reason: Optional[str] = None
    policy_hash: Optional[str] = None
    engine_version: Optional[str] = None
    evaluated_at: Optional[str] = None
    revoked_at: Optional[float] = None
    requested_at: float = field(default_factory=time.time)
    created_at: Optional[float] = None
    updated_at: Optional[float] = None
    expires_at: float = 0.0

    def __post_init__(self) -> None:
        # Keep storage canonical while accepting legacy values.
        self.status = canonicalize_status(self.status)

        # Backward-compatible audit aliases.
        if not self.requester_slack_user_id and self.slack_user_id:
            self.requester_slack_user_id = self.slack_user_id
        if self.requester_slack_user_id and not self.slack_user_id:
            self.slack_user_id = self.requester_slack_user_id

        # Immutable creation timestamp alias for future indexing/API.
        if self.created_at is None:
            self.created_at = self.requested_at

    @staticmethod
    def create_id() -> str:
        """Generates a unique ID for the request."""
        return str(uuid.uuid4())

    def is_expired(self) -> bool:
        """Checks if the current time has passed the expiration timestamp."""
        return time.time() > self.expires_at
