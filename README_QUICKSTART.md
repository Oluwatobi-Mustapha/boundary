# Boundary Quickstart (Dev Deploy)

1. From repo root, create local tfvars:
```bash
cp terraform/live/envs/dev/terraform.tfvars.example terraform/live/envs/dev/terraform.tfvars
```

2. Edit `terraform/live/envs/dev/terraform.tfvars` and set:
- `boundary_secrets.STAGING_OU_ID`
- `boundary_secrets.PROD_OU_ID`
- `boundary_secrets.AWS_SSO_START_URL`
- `boundary_secrets.AUDIT_API_PRINCIPAL_MAP`
- `permission_sets` keys you want to allow in Slack (default: `ReadOnlyAccess`, `AdministratorAccess`, `PowerUserAccess`)

3. Deploy dev:
```bash
terraform -chdir=terraform/live/envs/dev init
terraform -chdir=terraform/live/envs/dev plan -out=tfplan
terraform -chdir=terraform/live/envs/dev apply tfplan
```

4. Configure Slack app:
- Slash command Request URL = `$(terraform -chdir=terraform/live/envs/dev output -raw slack_webhook_url)`
- Interactivity Request URL = same `/webhook` endpoint
- Invite bot to approval channel:
```text
/invite @Boundary JIT
```

5. Submit test requests in Slack:
```text
/boundary 220065406396 ReadOnlyAccess 0.02
/boundary request 220065406396 AdministratorAccess 0.5 INC-12345
```

6. Open audit dashboard (signed local proxy):
```bash
python3 scripts/dashboard_proxy.py \
  --dashboard-url "$(terraform -chdir=terraform/live/envs/dev output -raw audit_dashboard_url)" \
  --open
```

7. Optional smoke check:
```bash
scripts/smoke_audit_role_matrix.sh
```

8. Update deploys after code changes:
```bash
terraform -chdir=terraform/live/envs/dev plan -out=tfplan
terraform -chdir=terraform/live/envs/dev apply tfplan
```
