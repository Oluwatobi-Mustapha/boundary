# Boundary Bot (The Janitor)

This module deploys the automated component of **Boundary**.

It runs a scheduled cleanup process that revokes expired access grants and keeps the system in a consistent state.

---

## Components

- **AWS Lambda**  
  Hosts the `src/janitor.py` logic.

- **EventBridge Scheduler**  
  Triggers the Lambda on a fixed schedule (default every minute).

- **IAM Role**  
  Grants the Lambda permission to revoke Identity Center assignments and update DynamoDB state.

---

## Architecture

- **Runtime:** Python 3.11+
- **Trigger:** `rate(1 minute)`
- **Permissions Required:**
  - `sso:DeleteAccountAssignment`
  - `dynamodb:Query`
  - `dynamodb:UpdateItem` (Active Requests Table)

---

## Inputs

| Name | Description |
| ---- | ----------- |
| `dynamodb_table_name` | The name of the state store table to scan. |
| `lambda_timeout` | Maximum duration for the janitor run (default: `60s`). |
| `schedule_expression` | EventBridge schedule expression (default: `rate(1 minute)`). |

***Shared locals/tags/naming conventions (used when >1 live root exists)***
