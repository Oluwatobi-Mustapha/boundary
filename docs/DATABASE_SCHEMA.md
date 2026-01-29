# Database Schema — ActiveRequests

## Overview

The `ActiveRequests` table stores the **live state** of all granted access requests.
It is the system of record used by ***Boundary*** to determine:

- Which access grants are currently active
- When access must be revoked
- How to safely recover state after a bot crash or restart

This table is **not an audit log**.  
It only tracks **current and pending access grants**.

---

## Table: ActiveRequests

### Primary Key

- **Partition Key (PK):**
  - `request_id` (string, UUID)

Each access request is uniquely identified by a generated `request_id`.
This enables fast, idempotent lookups and safe state recovery.

There is **no Sort Key** on the base table because each item represents
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

The most frequent query executed by ***Boundary*** is:

> “Find all ACTIVE requests that have expired so access can be revoked.”

This index supports the following query pattern:

- `status = "ACTIVE"`
- `expires_at <= current_time`

This allows the revocation worker to run safely every minute
without scanning the entire table.

---

## Attributes

| Attribute Name        | Type    | Description |
|----------------------|---------|-------------|
| `request_id`         | String  | Unique identifier for the access request |
| `subject_id`         | String  | Group or user requesting access |
| `rule_name`          | String  | Name of the access rule that allowed the request |
| `ticket_id`          | String  | Approval or change-management reference |
| `account_id`         | String  | AWS account where access was granted |
| `permission_set`     | String  | AWS IAM Identity Center permission set |
| `status`             | String  | `PENDING`, `ACTIVE`, or `REVOKED` |
| `requested_at`       | Number  | Request creation time (epoch seconds) |
| `expires_at`         | Number  | Time when access must be revoked |
| `revoked_at`         | Number  | Time when access was actually revoked |
| `approval_required`  | Boolean | Whether approval was required for this request |

---

## Primary Access Patterns

### 1. Create Access Request
- Insert new item with `status = PENDING` or `ACTIVE`
- Populate `expires_at` based on policy constraints

### 2. Recover After Bot Crash
- Query `ExpirationIndex` for expired ACTIVE requests
- Revoke access and update `status` to `REVOKED`

### 3. Revoke Expired Access
- Query `ExpirationIndex`
- For each result:
  - Revoke IAM Identity Center assignment
  - Update `status` and set `revoked_at`

### 4. Idempotent Updates
- All operations reference `request_id`
- Safe retries without duplicating access grants

---

## Design Principles

- **Time-based state, not timers**
- **Crash-safe by default**
- **Optimized for least-privilege enforcement at scale**
- **Designed for thousands of AWS accounts**
