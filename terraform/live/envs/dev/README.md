# Development Environment (Dev)

This is the sandbox for the **Boundary Access System**.

All changes to **Permission Sets**, **Groups**, or **Policies** must be applied here first before promotion to higher environments.

---

## Purpose

This environment exists to:

- Validate Terraform module changes.
- Test new IAM policies without affecting production workloads.
- Verify the Python Policy Engine integration.

---

## Configuration

This root expects a `terraform.tfvars` file.

A safe template is provided:

- `terraform.tfvars.example` (committed)

To run locally:

```bash
cp terraform.tfvars.example terraform.tfvars
```

***Then edit `terraform.tfvars` to match your environment. This file is ignored by Git and should not be committed.***

First-time checklist before `plan/apply`:

- Set `boundary_secrets.STAGING_OU_ID` in `terraform.tfvars` to the OU/root used for staging allow rules.
- Set `boundary_secrets.PROD_OU_ID` in `terraform.tfvars` to the OU/root used for production deny rules.
- Set `boundary_secrets.AWS_SSO_START_URL` in `terraform.tfvars` to your IAM Identity Center User portal URL.
- Ensure the approval channel configured in `config/access_rules.yaml` exists (default: `#security-approvals`).
- Invite the Slack app to that channel: `/invite @Boundary JIT`.

![alt text](image.png)

---

## Apply Instructions

Run Terraform in the following order:

### 1) Initialize

```bash
terraform init
```

### 2) Plan

```bash
terraform plan -out=tfplan
```

### 3) Apply

```bash
terraform apply tfplan
```

---

## Slack Command Format

Use the slash command with this shape:

```text
/boundary <AccountID> <PermissionSet> <Hours> [TicketID]
```

Examples:

```text
/boundary 037302670236 ReadOnlyAccess 0.5
/boundary 037302670236 AdministratorAccess 0.5 INC-12345
```

If the policy rule has `ticket_required: true`, the ticket value is mandatory.

---

## State Backends

- This environment uses the S3 backend bucket provisioned during the Bootstrap phase.

- Ensure `backend.tf` is configured with the correct bucket name.

---

## Audit API (Step 4)

After apply, Terraform outputs `audit_api_base_url`.

Read-only endpoints:

- `GET /api/requests`
- `GET /api/requests/{id}`
- `GET /api/metrics`
- `GET /api/exports.csv`

Important:

- These routes use `AWS_IAM` auth at API Gateway (authenticated callers only).
- App-level RBAC + ABAC is enforced via `boundary_secrets.AUDIT_API_PRINCIPAL_MAP`.
- Deny-by-default: if a caller ARN is not mapped, access is rejected.

Minimum query filter for `/api/requests` and `/api/exports.csv`:

- one of `status`, `account_id`, `permission_set_name`, `requester_slack_user_id`

Optional filters:

- `created_after`, `created_before`, `page_size`, `next_token`

---

## Audit Dashboard (Step 5)

After apply, Terraform outputs `audit_dashboard_url`.
Terraform also outputs `audit_read_invoke_policy_arn`.

Dashboard routes:

- `GET /dashboard`
- `GET /dashboard/requests/{request_id}`

Views included:

- Active Access
- Pending Approvals (with age/SLA badges)
- Recent Revocations
- Denials by Reason
- Request detail page (timeline/evidence fields)

Important:

- These routes also use `AWS_IAM` auth at API Gateway.
- App-level RBAC + ABAC is enforced with the same `AUDIT_API_PRINCIPAL_MAP`.
- If caller ARN is unmapped, dashboard access is denied.
- Attach `audit_read_invoke_policy_arn` to the IAM roles/users that should open the API/dashboard.

### Open Dashboard in Browser (recommended)

Because routes use `AWS_IAM`, direct browser calls are unsigned by default.
Use the local signed proxy:

```bash
python3 scripts/dashboard_proxy.py \
  --dashboard-url "$(terraform -chdir=terraform/live/envs/dev output -raw audit_dashboard_url)" \
  --open
```

This keeps backend auth strict while making the UI work like a normal web app locally.
