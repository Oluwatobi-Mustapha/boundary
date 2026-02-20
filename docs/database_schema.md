# Database Schema — ActiveRequests

## Overview

The `ActiveRequests` table stores the live state of all granted access requests.
It is the system of record used by Boundary to determine:

- Which access grants are currently active
- When access must be revoked
- How to safely recover state after a bot crash or restart

This table is not an audit log.  
It only tracks current and pending access grants.

---

## Table: ActiveRequests

### Primary Key

- **Partition Key (PK):**
  - `request_id` (string, UUID)

Each access request is uniquely identified by a generated `request_id`.
This enables fast, idempotent lookups and safe state recovery.

There is no Sort Key on the base table because each item represents
a single independent access request.

---

## Global Secondary Indexes (GSI)

### GSI: ExpirationIndex

This index enables efficient discovery of expired access grants.

- **GSI Partition Key:**  
  - `status` (string)

- **GSI Sort Key:**  
  - `expires_at` (number, Unix epoch seconds)

#### Purpose

The most frequent query executed by Boundary is:

> "Find all ACTIVE requests that have expired so access can be revoked."

This index supports the following query pattern:

- `status = "ACTIVE"`
- `expires_at <= current_time`

This allows the revocation worker to run safely every minute
without scanning the entire table.

---

## Attributes

| Attribute Name | Type | Description |
| --- | --- | --- |
| `request_id` | String | Unique identifier for the access request |
| `principal_id` | String | CRITICAL: The User GUID (Identity Store ID) who received access |
| `principal_type` | String | Usually "USER" (Could be GROUP in rare cases) |
| `eligible_group_id` | String | The Group ID that matched the rule (for auditing) |
| `permission_set_arn` | String | CRITICAL: The ARN of the Permission Set (Immutable) |
| `account_id` | String | AWS account ID where access was granted |
| `instance_arn` | String | The SSO Instance ARN (Required for API calls) |
| `status` | String | PENDING, ACTIVE, REVOKED, ERROR |
| `ticket_id` | String | Approval or change-management reference |
| `rule_id` | String | ID of the rule from access_rules.yaml |
| `requested_at` | Number | Request creation time (epoch seconds) |
| `expires_at` | Number | Time when access must be revoked |
| `revoked_at` | Number | Time when access was actually revoked |
| `ttl` | Number | DynamoDB TTL attribute (e.g., expires_at + 90 days) for auto-deletion |
| `slack_user_id` | String | The Slack ID (e.g., U123456) for ChatOps mapping and DMs. **ACTIVE:** Used by SlackWorkflow for identity translation chain (Slack ID → Email → AWS Principal ID). |
| `slack_response_url` | String | Temporary webhook for asynchronous Slack replies. **ACTIVE:** Used by SlackWorkflow to send success/error messages after policy evaluation. Validated to prevent URL injection attacks. |
| `slack_channel_id` | String | Slack channel where the request originated (for approvals). **RESERVED:** Not yet used by current implementation. |

---

## Primary Access Patterns

### 1. Create Access Request

- Insert new item with status = PENDING or ACTIVE
- Resolve Names to ARNs before inserting.

### 2. Recover After Bot Crash

- Query ExpirationIndex for expired ACTIVE requests
- Revoke access and update status to REVOKED

### 3. Revoke Expired Access

- Query ExpirationIndex where status is ACTIVE and time < Now.
- For each result:
  - Call sso-admin:DeleteAccountAssignment using principal_id and permission_set_arn.
  - Update status to REVOKED and set revoked_at.

### 4. Idempotent Updates

- All operations reference request_id
- Safe retries without duplicating access grants

### 5. Asynchronous ChatOps Notifications

- **SlackWorkflow** reads `slack_response_url` to send final provision/deny messages back to the user after policy evaluation completes
- **SlackWorkflow** uses `slack_user_id` to initiate identity translation chain: Slack User ID → Email (via SlackAdapter) → AWS Principal ID (via IdentityStoreAdapter)
- The Janitor (future) will read `slack_user_id` to send a direct message when access is automatically revoked
- **PII Protection:** Emails and AWS Principal IDs derived from `slack_user_id` are logged at DEBUG level only, never at INFO/WARNING in production

---

## Security Notes

### Slack Field Usage

- `slack_response_url` is validated against `https://hooks.slack.com/` prefix before use to prevent URL injection attacks
- `slack_user_id` is validated against format `^U[A-Z0-9]{10}$` in SlackAdapter
- All Slack-related fields are optional (system supports CLI-based requests without Slack metadata)

---

## Design Principles

- Time-based state, not timers
- Crash-safe by default
- Optimized for least-privilege enforcement at scale
- Designed for thousands of AWS accounts
