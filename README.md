# Boundary

Boundary is an AWS-focused, policy-driven JIT access broker.  
It grants short-lived IAM Identity Center access from Slack, enforces approval for high-risk requests, revokes expired grants automatically, and exposes read-only audit views.

`[ 🎥 Placeholder: 60-second Demo Video ]`  
`[ 📸 Placeholder: High-Level Architecture Diagram ]`


- [Quick Start Guide](README_QUICKSTART.md)

---

## Status

- `v1` pilot-ready  
- AWS-only scope  
- Primary user interface: Slack  

---

## What Boundary Does

- Evaluates access requests against `config/access_rules.yaml`
- Provisions IAM Identity Center account assignments when allowed
- Supports approval workflow for sensitive permissions
- Revokes expired access on schedule (Janitor)
- Stores request lifecycle and audit evidence in DynamoDB
- Exposes read-only Audit API and Dashboard

---

## Interfaces

1. **Slack (`/boundary`)**  
   End-user request, approval, and notification flow.

2. **CLI (`src/main.py`, `src/janitor.py`, `demo.py`)**  
   Operator testing and local workflow validation.

3. **Web Dashboard (`/dashboard`)**  
   Read-only audit visibility.

---

## Architecture (High Level)

`[ 📸 Placeholder: Detailed Architecture Diagram (API Gateway → SQS → Lambdas → DynamoDB → EventBridge) ]`

1. Slack slash command hits API Gateway `POST /webhook`
2. `slack_bot` verifies Slack signature and enqueues request in SQS
3. `workflow_manager`:
   - resolves user/group identity
   - evaluates policy engine
   - provisions assignment (or marks pending approval/deny)
   - persists request state in DynamoDB
4. `janitor` (EventBridge schedule) revokes expired `ACTIVE` requests
5. `audit_api` and `audit_dashboard` read from DynamoDB with IAM auth + app RBAC/ABAC

---

## Prerequisites

- AWS Organization + IAM Identity Center enabled
- Slack app (slash command + interactivity)
- Terraform 1.6+
- Python 3.11+
- AWS CLI authenticated to the target account/region

---

## Deploy (Dev)

### 1. Copy vars template

```bash
cp terraform/live/envs/dev/terraform.tfvars.example terraform/live/envs/dev/terraform.tfvars
```

### 2. Set required values in `terraform/live/envs/dev/terraform.tfvars`

- `boundary_secrets.STAGING_OU_ID`
- `boundary_secrets.PROD_OU_ID`
- `boundary_secrets.AWS_SSO_START_URL`
- `boundary_secrets.AUDIT_API_PRINCIPAL_MAP` (explicit caller ARNs)

### 3. Apply

Navigate to environment directory:

```bash
cd terraform/live/envs/dev
```

Run Terraform workflow:

```bash
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

Return to previous directory:

```bash
cd -
```

### 4. Useful outputs

```bash
terraform -chdir=terraform/live/envs/dev output -json
```

---

## Slack Setup

- Slash command Request URL → Terraform output `slack_webhook_url`
- Interactivity Request URL → same `/webhook` endpoint

Required scopes:
- `chat:write`
- `im:write`
- `users:read`
- `users:read.email`

Invite app to approval channel:

```text
/invite @Boundary JIT
```

---

## Slack Request Syntax

```text
/boundary <AccountID> <PermissionSet> <Hours> [TicketID]
```

Accepted forms:

```text
/boundary 123456789012 ReadOnlyAccess 0.5
/boundary request 111122223333 AdministratorAccess 0.5 INC-12345
/boundary 111122223333 AdministratorAccess 0.5 ticket INC-12345
```

---

## CLI Usage

### Local demo (no live AWS writes)

```bash
PYTHONPATH=src python3 demo.py --debug
```

### Live request path (operator testing)

```bash
python3 src/main.py --help
```

### Janitor path

```bash
python3 src/janitor.py --help
```

---

## Audit API

Base URL from Terraform output `audit_api_base_url`.

Endpoints:

- `GET /api/requests`
- `GET /api/requests/{request_id}`
- `GET /api/metrics`
- `GET /api/exports.csv`

Notes:

- API Gateway auth is `AWS_IAM`
- App-level RBAC/ABAC enforced via `AUDIT_API_PRINCIPAL_MAP`
- Deny-by-default for unmapped principals
- Wildcard principal mapping disabled unless explicitly enabled
- `/api/requests` and `/api/exports.csv` require one primary filter:
  - `status`
  - `account_id`
  - `permission_set_name`
  - `requester_slack_user_id`

---

## Audit Dashboard

Base URL from Terraform output `audit_dashboard_url`.

Routes:

- `GET /dashboard`
- `GET /dashboard/requests/{request_id}`

For browser use (SigV4 proxy):

```bash
python3 scripts/dashboard_proxy.py \
  --dashboard-url "$(terraform -chdir=terraform/live/envs/dev output -raw audit_dashboard_url)" \
  --open
```

---

## Security Model

- Fail-closed default deny
- Deterministic rule evaluation (ordered by YAML sequence)
- Ticket + human approval supported for sensitive roles
- Auto-revocation via scheduled janitor
- Canonicalized and validated request lifecycle states
- Read APIs authenticated and scope-filtered (RBAC + ABAC)
- Contract header/version enforced for API responses

---

## Validation and Smoke Tests

```bash
pytest -q
terraform -chdir=terraform/live/envs/dev validate
terraform fmt -check -recursive terraform
```

---

## Operations

Key alarms:

- `boundary-dev-janitor-errors`
- `boundary-dev-janitor-slack-notify-failures`
