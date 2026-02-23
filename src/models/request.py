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
        permission_set_name: Human-readable name (e.g., ReadOnlyAccess) used for policy matching.
        account_id: The target 12-digit AWS Account ID.
        instance_arn: The ARN of the SSO instance.
        rule_id: The ID of the rule from access_rules.yaml that authorized this.
        status: The current state (PENDING_APPROVAL, APPROVED, ACTIVE, REVOKED, DENIED, ERROR).
        ticket_id: Optional reference to an external ticket (Jira/ServiceNow).
        requested_at: Unix timestamp of the request creation.
        expires_at: Unix timestamp when access must be revoked.
        created_at: Unix timestamp for DynamoDB record creation (defaults to requested_at).
        updated_at: Unix timestamp of last status update.
        slack_user_id: Slack user ID of the requesting user.
        requester_slack_user_id: Slack user ID used for requester-based queries.
        slack_response_url: Slack webhook URL for async replies.
        approval_required: Whether this request requires human approval.
        approval_channel: Slack channel for approval notifications.
        approver_group: IDP group authorized to approve.
        approver_slack_user_id: Slack user ID of the approver.
        approved_by: Identifier of who approved the request.
        approved_at: Unix timestamp of approval.
        denied_by: Identifier of who denied the request.
        denied_at: Unix timestamp of denial.
        reason: Human-readable reason for the decision.
        policy_hash: SHA256 hash of the evaluated policy file.
        engine_version: Version of the policy engine that evaluated this request.
        evaluated_at: ISO 8601 timestamp of when evaluation occurred.
        revoked_at: Unix timestamp of when access was revoked.
    """
    request_id: str
    principal_id: str
    principal_type: str
    permission_set_arn: str
    permission_set_name: str
    account_id: str
    instance_arn: str
    rule_id: str
    status: str = "PENDING"
    ticket_id: Optional[str] = None
    requested_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    # DynamoDB record timestamps
    created_at: Optional[float] = None
    updated_at: Optional[float] = None
    # Slack integration fields
    slack_user_id: Optional[str] = None
    requester_slack_user_id: Optional[str] = None
    slack_response_url: Optional[str] = None
    # Approval workflow fields
    approval_required: Optional[bool] = None
    approval_channel: Optional[str] = None
    approver_group: Optional[str] = None
    approver_slack_user_id: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[float] = None
    denied_by: Optional[str] = None
    denied_at: Optional[float] = None
    # Audit / evaluation metadata
    reason: Optional[str] = None
    policy_hash: Optional[str] = None
    engine_version: Optional[str] = None
    evaluated_at: Optional[str] = None
    revoked_at: Optional[float] = None

    @staticmethod
    def create_id() -> str:
        """Generates a unique ID for the request."""
        return str(uuid.uuid4())

    def is_expired(self) -> bool:
        """Checks if the current time has passed the expiration timestamp."""
        return time.time() > self.expires_at