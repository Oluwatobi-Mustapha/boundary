# Boundary

> **Serverless Just-In-Time (JIT) access broker for AWS.**  
> Slack-native ChatOps, deterministic policy-as-code, and automated zero-trust revocation for IAM Identity Center.

Boundary eliminates standing privileges in AWS environments.  
Developers request short-lived IAM Identity Center access directly from Slack.  
Requests are evaluated against a deterministic YAML policy, provisioned automatically, and revoked when their TTL expires — with no manual cleanup required.

`[ 🎥 60-second Demo Video ]`  
`[ 📸 Hero Image: Slack "Access Granted" Block with Login Button ]`

---

## Why Boundary?

Standing access is the #1 identity risk in cloud environments.  
Boundary enforces:

- **Default Deny**
- **Time-bound access**
- **Deterministic evaluation**
- **Automated revocation**
- **Full audit traceability**

No permanent roles. No forgotten access. No spreadsheet tracking.

---

## Key Features

- **Slack-Native ChatOps**  
  End-to-end request, approval, provisioning, and notification via `/boundary`.

- **Deterministic Policy-as-Code**  
  Rules defined in `config/access_rules.yaml`.  
  Supports attribute-based controls (Tags, OUs) and strict duration capping.

- **Human-in-the-Loop Approvals**  
  Optional Slack approval workflow for high-risk roles (e.g., `AdministratorAccess`).

- **The Janitor Service**  
  EventBridge-driven automated revocation guarantees expired access is removed.

- **Audit-Ready by Design**  
  Every evaluation emits a structured JSON artifact and persists state in DynamoDB.  
  Includes a SigV4-authenticated read-only Audit API and dashboard.

---

## Architecture

`[ 📸 High-Level Architecture Diagram ]`

1. **Request**  
   Slack slash command → API Gateway (`POST /webhook`).

2. **Ingest**  
   `slack_bot` verifies Slack HMAC signature and enqueues the request into SQS.

3. **Evaluate & Provision**  
   `workflow_manager`:
   - Resolves Identity Store GUID  
   - Evaluates deterministic YAML policy  
   - Provisions IAM Identity Center account assignment  
   - Persists request state in DynamoDB  

4. **Revoke**  
   `janitor` (EventBridge cron) queries a DynamoDB GSI (Global Secondary Index)  
   for expired `ACTIVE` requests and revokes them.

5. **Audit**  
   `audit_api` and `dashboard` read from DynamoDB.  
   Protected by IAM SigV4 authentication and application-level RBAC/ABAC.

---

## Security Model

Boundary is designed for enterprise security teams.

- **Fail-Closed Evaluation**  
  Unmapped principals are denied by default.

- **Deterministic Rule Ordering**  
  Policy evaluation follows strict YAML sequence — no ambiguity.

- **Zero Standing Privileges**  
  All access is time-bound and automatically revoked.

- **Tamper-Resistant APIs**  
  SigV4 authentication + scope-filtered reads.  
  Versioned contract headers enforce API compatibility.

- **Least Privilege Infrastructure**  
  Terraform-managed deployment with narrowly scoped IAM execution roles.

---

# Quick Start

## Prerequisites

- AWS Organization + IAM Identity Center enabled
- Slack App (Slash command + Interactivity)
  - Required scopes:
    - `chat:write`
    - `im:write`
    - `users:read`
    - `users:read.email`
- Terraform 1.6+
- Python 3.11+

---

## 1. Configuration

Copy the variables template:

```bash
cp terraform/live/envs/dev/terraform.tfvars.example terraform/live/envs/dev/terraform.tfvars
```

Edit `terraform.tfvars` and define:

- Organizational Units (OUs)
- IAM Identity Center Start URL
- Audit principals

---

## 2. Deploy

```bash
cd terraform/live/envs/dev
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

Retrieve generated outputs:

```bash
terraform output -json
```

Outputs include:

- `slack_webhook_url`
- `audit_dashboard_url`
- Environment-specific endpoints

---

## 3. Slack Integration

Configure your Slack App:

- **Slash Command URL** → `slack_webhook_url`
- **Interactivity & Shortcuts URL** → `slack_webhook_url`

Invite the bot to your approval channel:

```plaintext
/invite @Boundary JIT
```

---

# Usage

## Slack Command Syntax

```plaintext
/boundary <AccountID> <PermissionSet> <Hours> [TicketID]
```

## Examples

```plaintext
/boundary 123456789012 ReadOnlyAccess 0.5
/boundary 111122223333 AdministratorAccess 2 INC-12345
```

📸 *Placeholder: CLI Audit Table Screenshot*

---

## CLI & Local Testing

### Local Policy Evaluation (No AWS Writes)

```bash
PYTHONPATH=src python3 demo.py --debug
```

### Manually Trigger Janitor

```bash
python3 src/janitor.py --dynamo-table <table_name>
```

---

## Audit API & Dashboard

📸 *Placeholder: Web Dashboard Screenshot*

Boundary exposes a read-only audit dashboard for security teams.

Access locally via SigV4 proxy:

```bash
python3 scripts/dashboard_proxy.py \
  --dashboard-url "$(terraform -chdir=terraform/live/envs/dev output -raw audit_dashboard_url)" \
  --open
```

---

## Operations & Testing

### Validation

```bash
pytest -q
terraform -chdir=terraform/live/envs/dev validate
```

### Built-In CloudWatch Alarms

Provisioned automatically:

- `boundary-dev-janitor-errors`
- `boundary-dev-janitor-slack-notify-failures`

These monitor revocation failures and Slack notification delivery errors.
