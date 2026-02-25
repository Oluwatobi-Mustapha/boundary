# Boundary v1.0 Release Checklist

This checklist is the minimum release gate for v1.0.

## 1. Preconditions

- Worktree is clean enough to identify release changes.
- `terraform/live/envs/dev/terraform.tfvars` has correct `boundary_secrets` values.
- Required IAM caller roles exist:
  - `BoundarySecurityAdminApiRole`
  - `BoundaryAuditorApiRole`
  - `BoundaryViewerApiRole`
- Required invoke policies are attached to those roles.

## 2. Code Quality Gate

Run from repo root:

```bash
pytest -q
terraform -chdir=terraform/live/envs/dev validate
terraform -chdir=terraform fmt -check -recursive
```

## 3. Deploy Gate (Dev)

```bash
terraform -chdir=terraform/live/envs/dev init
terraform -chdir=terraform/live/envs/dev plan -out=tfplan
terraform -chdir=terraform/live/envs/dev apply tfplan
```

Capture outputs for audit records:

```bash
terraform -chdir=terraform/live/envs/dev output -raw audit_api_base_url
terraform -chdir=terraform/live/envs/dev output -raw audit_dashboard_url
terraform -chdir=terraform/live/envs/dev output -json > /tmp/boundary-dev-outputs.json
```

## 4. Role Matrix Smoke (Required)

Run the one-command smoke matrix:

```bash
scripts/smoke_audit_role_matrix.sh
```

If your current credentials cannot read Terraform state, pass endpoints directly:

```bash
scripts/smoke_audit_role_matrix.sh \
  --api-base "https://<api-id>.execute-api.us-east-1.amazonaws.com/api" \
  --dashboard-url "https://<api-id>.execute-api.us-east-1.amazonaws.com/dashboard"
```

Expected results:

- `BoundarySecurityAdminApiRole`: requests/metrics/exports/dashboard = `200`
- `BoundaryAuditorApiRole`: requests/metrics/exports/dashboard = `200`
- `BoundaryViewerApiRole`: requests/dashboard = `200`, metrics/exports = `403`

## 5. Human Workflow Smoke (Required)

Validate these three flows in Slack:

- ReadOnly: request -> granted -> revoked message
- PowerUser: request -> granted -> revoked message
- Admin: request -> pending approval -> approve -> active -> revoked

Record request IDs and timestamps for release evidence.

## 6. Alarm and Janitor Health Gate

Required alarms:

- `boundary-dev-janitor-errors`
- `boundary-dev-janitor-slack-notify-failures`

Health checks:

```bash
aws cloudwatch describe-alarms --alarm-names boundary-dev-janitor-errors boundary-dev-janitor-slack-notify-failures --query 'MetricAlarms[*].[AlarmName,StateValue]' --output table
aws logs tail /aws/lambda/boundary-dev-janitor --since 20m --format short
```

Release only if alarms are `OK` and no repeated runtime import errors appear.

## 7. Security and Access Gate

- `AUDIT_API_PRINCIPAL_MAP` contains only approved caller ARNs.
- Wildcard principal mapping is disabled in normal operation.
- No broad invoke policies attached where role-specific policy exists.
- No secrets committed to Git.

## 8. Release Artifacts

- Update changelog entry for the release.
- Tag release commit:

```bash
git tag -a v1.0.0 -m "Boundary v1.0.0"
git push origin v1.0.0
```

## 9. Rollback Plan (Required before release)

If release fails:

1. Re-apply previous known-good commit.
2. Re-run `terraform plan` and `terraform apply`.
3. Confirm `boundary-dev-janitor-errors` returns to `OK`.
4. Re-run `scripts/smoke_audit_role_matrix.sh`.

## 10. Release Complete Criteria

v1.0 is complete only when all are true:

- Code/test/terraform gates pass.
- Role matrix smoke passes.
- Human workflow smoke passes.
- Alarm and Janitor health gates pass.
- Rollback plan validated and documented.

