# Boundary Quickstart (AWS, v1)

1. From repo root:
```bash
cp terraform/live/envs/dev/terraform.tfvars.example terraform/live/envs/dev/terraform.tfvars
```

2. Edit `terraform/live/envs/dev/terraform.tfvars` and set:
- `boundary_secrets.STAGING_OU_ID`
- `boundary_secrets.PROD_OU_ID`
- `boundary_secrets.AWS_SSO_START_URL`
- `boundary_secrets.AUDIT_API_PRINCIPAL_MAP`

3. Deploy:
```bash
terraform -chdir=terraform/live/envs/dev init
terraform -chdir=terraform/live/envs/dev plan -out=tfplan
terraform -chdir=terraform/live/envs/dev apply tfplan
```

4. Slack app setup:
- Slash command Request URL = Terraform output `slack_webhook_url`
- Interactivity Request URL = same `/webhook`
- Invite app to approvals channel: `/invite @Boundary JIT`

5. First request in Slack:
```text
/boundary <AccountID> ReadOnlyAccess 0.5
```

6. Open dashboard:
```bash
python3 scripts/dashboard_proxy.py \
  --dashboard-url "$(terraform -chdir=terraform/live/envs/dev output -raw audit_dashboard_url)" \
  --open
```

7. Quick health check:
```bash
scripts/smoke_audit_role_matrix.sh
```
