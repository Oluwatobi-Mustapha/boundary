"""
Boundary v1.0 contract constants.

These values are intentionally centralized so test and runtime can enforce
the same domain/API contract.
"""

CONTRACT_VERSION = "1.0.0"

# Canonical request lifecycle states for v1.
REQUEST_STATUS_VALUES = (
    "PENDING_APPROVAL",
    "APPROVED",
    "ACTIVE",
    "REVOKED",
    "DENIED",
    "ERROR",
)

# Immutable audit evidence fields expected on request records.
IMMUTABLE_AUDIT_FIELDS = (
    "requester_slack_user_id",
    "approver_slack_user_id",
    "ticket_id",
    "rule_id",
    "requested_at",
    "created_at",
    "updated_at",
    "account_id",
    "permission_set_name",
    "reason",
)

# Frozen JSON payload key sets for API responses.
API_LIST_RESPONSE_KEYS = (
    "items",
    "next_token",
    "count",
    "generated_at",
)

API_METRICS_RESPONSE_KEYS = (
    "total_requests",
    "by_status",
    "created_after",
    "created_before",
    "generated_at",
)

# Frozen CSV export header order.
CSV_EXPORT_COLUMNS = (
    "request_id",
    "status",
    "created_at",
    "updated_at",
    "requested_at",
    "expires_at",
    "revoked_at",
    "account_id",
    "permission_set_name",
    "requester_slack_user_id",
    "approver_slack_user_id",
    "rule_id",
    "reason",
    "ticket_id",
)
