# Boundary v1.0 Contract

This document freezes the v1.0 behavior for domain state and read API payloads.
Any change here is a breaking change and requires a version bump.

## 1) Canonical Request States

Canonical values:

- `PENDING_APPROVAL`
- `APPROVED`
- `ACTIVE`
- `REVOKED`
- `DENIED`
- `ERROR`

Notes:

- Legacy alias `PENDING` is accepted and normalized to `PENDING_APPROVAL`.
- New state names are not allowed in v1.

## 2) Allowed Status Transitions

- `PENDING_APPROVAL` -> `APPROVED`, `ACTIVE`, `DENIED`, `ERROR`
- `APPROVED` -> `ACTIVE`, `ERROR`
- `ACTIVE` -> `REVOKED`, `ERROR`
- `DENIED` -> terminal
- `REVOKED` -> terminal
- `ERROR` -> terminal
- Same-state writes are allowed for idempotency.

## 3) Immutable Audit Evidence Fields

The following fields are required as stable evidence fields in v1 request records:

- `requester_slack_user_id`
- `approver_slack_user_id`
- `ticket_id`
- `rule_id`
- `requested_at`
- `created_at`
- `updated_at`
- `account_id`
- `permission_set_name`
- `reason`

## 4) Read API Response Shapes

Contract header on all read API responses:

- `X-Boundary-Contract-Version: 1.0.0`

### `GET /api/requests`

JSON keys are fixed (order in payload construction):

- `items`
- `next_token`
- `count`
- `generated_at`

### `GET /api/metrics`

JSON keys are fixed:

- `total_requests`
- `by_status`
- `created_after`
- `created_before`
- `generated_at`

### `GET /api/exports.csv`

CSV header columns are fixed:

- `request_id`
- `status`
- `created_at`
- `updated_at`
- `requested_at`
- `expires_at`
- `revoked_at`
- `account_id`
- `permission_set_name`
- `requester_slack_user_id`
- `approver_slack_user_id`
- `rule_id`
- `reason`
- `ticket_id`

### Error payload shape

For all error responses, JSON shape is fixed:

- `{ "error": "<message>" }`

## 5) Enforcement

The contract is enforced by tests:

- `tests/test_v1_contract.py`

If these tests fail, the change is contract-breaking for v1 and must not be merged
without an explicit contract version decision.
