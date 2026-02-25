#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Boundary v1 smoke check: IAM role matrix for audit API + dashboard.

Usage:
  scripts/smoke_audit_role_matrix.sh [options]

Options:
  --account-id <id>       AWS account ID hosting the IAM roles.
                          Default: caller identity account.
  --region <region>       AWS region for execute-api signing.
                          Default: AWS_REGION/AWS_DEFAULT_REGION/us-east-1.
  --api-base <url>        Audit API base URL (e.g. https://.../api).
  --dashboard-url <url>   Dashboard URL (e.g. https://.../dashboard).
  --terraform-dir <path>  Terraform directory for outputs fallback.
                          Default: terraform/live/envs/dev.
  -h, --help              Show this help.

Notes:
  - Caller must be allowed to assume:
      BoundarySecurityAdminApiRole
      BoundaryAuditorApiRole
      BoundaryViewerApiRole
  - If terraform output is not readable in your current creds, pass --api-base
    and --dashboard-url explicitly.
EOF
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 2
  fi
}

ACCOUNT_ID=""
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
API_BASE=""
DASHBOARD_URL=""
TERRAFORM_DIR="terraform/live/envs/dev"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --account-id)
      ACCOUNT_ID="$2"
      shift 2
      ;;
    --region)
      REGION="$2"
      shift 2
      ;;
    --api-base)
      API_BASE="$2"
      shift 2
      ;;
    --dashboard-url)
      DASHBOARD_URL="$2"
      shift 2
      ;;
    --terraform-dir)
      TERRAFORM_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

require_cmd aws
require_cmd curl

if [[ -z "$ACCOUNT_ID" ]]; then
  ACCOUNT_ID="$(aws sts get-caller-identity --query 'Account' --output text)"
fi

if [[ -z "$API_BASE" ]]; then
  set +e
  API_BASE="$(terraform -chdir="$TERRAFORM_DIR" output -raw audit_api_base_url 2>/dev/null)"
  set -e
fi
if [[ -z "$DASHBOARD_URL" ]]; then
  set +e
  DASHBOARD_URL="$(terraform -chdir="$TERRAFORM_DIR" output -raw audit_dashboard_url 2>/dev/null)"
  set -e
fi

if [[ -z "$API_BASE" || -z "$DASHBOARD_URL" ]]; then
  echo "Could not resolve endpoints. Pass --api-base and --dashboard-url explicitly." >&2
  exit 2
fi

tmp_body="$(mktemp)"
trap 'rm -f "$tmp_body"' EXIT

assume_role() {
  local role_name="$1"
  local session_name="boundary-smoke-${role_name}-$(date +%s)"
  local creds
  creds="$(aws sts assume-role \
    --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/${role_name}" \
    --role-session-name "$session_name" \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
    --output text)"

  read -r ROLE_AK ROLE_SK ROLE_ST <<< "$creds"
}

signed_get_status() {
  local url="$1"
  local status
  status="$(curl -sS -o "$tmp_body" -w "%{http_code}" \
    --aws-sigv4 "aws:amz:${REGION}:execute-api" \
    --user "${ROLE_AK}:${ROLE_SK}" \
    -H "x-amz-security-token: ${ROLE_ST}" \
    "$url" || true)"
  echo "$status"
}

RESULTS=()
FAILURES=0

record_check() {
  local role="$1"
  local check="$2"
  local expected="$3"
  local actual="$4"
  local outcome="PASS"
  if [[ "$expected" != "$actual" ]]; then
    outcome="FAIL"
    FAILURES=$((FAILURES + 1))
  fi
  RESULTS+=("$(printf "%-30s %-30s expected=%-3s actual=%-3s %s" "$role" "$check" "$expected" "$actual" "$outcome")")
}

run_role_checks() {
  local role="$1"
  shift
  assume_role "$role"

  while [[ $# -gt 0 ]]; do
    local check_name="$1"
    local endpoint="$2"
    local expected="$3"
    shift 3

    local target
    if [[ "$endpoint" == /dashboard* ]]; then
      target="${DASHBOARD_URL}${endpoint#/dashboard}"
    else
      target="${API_BASE}${endpoint}"
    fi
    local actual
    actual="$(signed_get_status "$target")"
    record_check "$role" "$check_name" "$expected" "$actual"
  done
}

echo "Boundary v1 smoke matrix"
echo "  account_id:    $ACCOUNT_ID"
echo "  region:        $REGION"
echo "  audit_api:     $API_BASE"
echo "  dashboard:     $DASHBOARD_URL"
echo

run_role_checks "BoundarySecurityAdminApiRole" \
  "requests" "/requests?status=ACTIVE" "200" \
  "metrics" "/metrics" "200" \
  "exports" "/exports.csv?status=ACTIVE" "200" \
  "dashboard" "/dashboard" "200"

run_role_checks "BoundaryAuditorApiRole" \
  "requests" "/requests?status=ACTIVE" "200" \
  "metrics" "/metrics" "200" \
  "exports" "/exports.csv?status=ACTIVE" "200" \
  "dashboard" "/dashboard" "200"

run_role_checks "BoundaryViewerApiRole" \
  "requests" "/requests?status=ACTIVE" "200" \
  "metrics" "/metrics" "403" \
  "exports" "/exports.csv?status=ACTIVE" "403" \
  "dashboard" "/dashboard" "200"

printf "%s\n" "${RESULTS[@]}"
echo

if [[ "$FAILURES" -gt 0 ]]; then
  echo "Smoke matrix failed: $FAILURES check(s) did not match expected status." >&2
  exit 1
fi

echo "Smoke matrix passed."

