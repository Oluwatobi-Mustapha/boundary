#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, Optional, Tuple

import boto3
from rich.console import Console
from rich.table import Table

from adapters.aws_orgs import AWSOrganizationsAdapter
from adapters.identity_store_adapter import IdentityStoreAdapter
from adapters.slack_adapter import SlackAdapter
from adapters.state_store import StateStore
from core.engine import PolicyEngine
from models.request_states import (
    STATE_ACTIVE,
    STATE_DENIED,
    STATE_PENDING_APPROVAL,
    STATE_REVOKED,
    canonicalize_status,
)
from ui.printer import print_banner
from workflows.access_workflow import SlackWorkflow, get_bot_token


ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_TERRAFORM_DIR = os.path.join(ROOT_DIR, "terraform", "live", "envs", "dev")
DEFAULT_CONFIG_PATH = os.path.join(ROOT_DIR, "config", "access_rules.yaml")
DEFAULT_RESPONSE_URL = "https://hooks.slack.com/services/T00000000/B00000000/LOCALCLI"


class CLISlackWorkflow(SlackWorkflow):
    """
    Reuses the exact Slack workflow logic while redirecting Slack notifications
    to local console output for CLI runs.
    """

    def __init__(self, *args: Any, console: Console, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.console = console

    def _send_slack_reply(
        self,
        response_url: str,
        message: str,
        is_success: bool = True,
        max_retries: int = 3,
        login_url: Optional[str] = None,
    ) -> None:
        _ = response_url, max_retries
        label = "Slack reply"
        style = "green" if is_success else "red"
        self.console.print(f"[{style}]{label}:[/{style}] {message}")
        if login_url:
            self.console.print(f"[cyan]Login URL:[/cyan] {login_url}")

    def _send_slack_dm(self, slack_user_id: str, message: str, login_url: Optional[str] = None) -> None:
        self.console.print(f"[cyan]Slack DM -> {slack_user_id}:[/cyan] {message}")
        if login_url:
            self.console.print(f"[cyan]Login URL:[/cyan] {login_url}")

    def _send_approval_request(self, request: Any, decision: Any) -> None:
        duration_hours = round(getattr(decision, "effective_duration_hours", 0.0) or 0.0, 2)
        self.console.print(
            "[yellow]Approval request emitted:[/yellow] "
            f"{request.request_id} ({request.permission_set_name}, {duration_hours}h)"
        )


def _set_env_if_missing(name: str, value: Optional[str]) -> None:
    if value and not os.environ.get(name):
        os.environ[name] = value


def _extract_tfvar_string(path: str, key: str) -> Optional[str]:
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    match = re.search(rf'^\s*{re.escape(key)}\s*=\s*"([^"]+)"', content, re.MULTILINE)
    return match.group(1) if match else None


def _derive_instance_arn_from_permission_set_arn(permission_set_arn: str) -> Optional[str]:
    match = re.search(r":permissionSet/(ssoins-[^/]+)/ps-[^/]+$", permission_set_arn)
    if not match:
        return None
    return f"arn:aws:sso:::instance/{match.group(1)}"


def _terraform_output_json(terraform_dir: str) -> Dict[str, Any]:
    try:
        out = subprocess.check_output(
            ["terraform", f"-chdir={terraform_dir}", "output", "-json"],
            stderr=subprocess.STDOUT,
            text=True,
        )
        return json.loads(out)
    except FileNotFoundError as exc:
        raise RuntimeError("terraform not found on PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"terraform output failed: {exc.output.strip()}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError("terraform output returned invalid JSON") from exc


def _sync_env_from_terraform(terraform_dir: str, console: Console) -> None:
    outputs = _terraform_output_json(terraform_dir)

    def _output_value(name: str) -> Any:
        node = outputs.get(name, {})
        if isinstance(node, dict):
            return node.get("value")
        return None

    group_ids = _output_value("group_ids") or {}
    permission_set_arns = _output_value("permission_set_arns") or {}

    _set_env_if_missing("DYNAMODB_TABLE", _output_value("dynamodb_table_name"))
    _set_env_if_missing("BOUNDARY_DEVELOPERS_ID", group_ids.get("Boundary-Developers"))
    _set_env_if_missing("BOUNDARY_SECURITY_ADMINS_ID", group_ids.get("Boundary-Security-Admins"))

    for name, arn in permission_set_arns.items():
        _set_env_if_missing(f"PERMISSION_SET_{name}", arn)

    if permission_set_arns and not os.environ.get("SSO_INSTANCE_ARN"):
        first_arn = next(iter(permission_set_arns.values()))
        instance_arn = _derive_instance_arn_from_permission_set_arn(str(first_arn))
        _set_env_if_missing("SSO_INSTANCE_ARN", instance_arn)

    tfvars_path = os.path.join(terraform_dir, "terraform.tfvars")
    _set_env_if_missing("PROD_OU_ID", _extract_tfvar_string(tfvars_path, "PROD_OU_ID"))
    _set_env_if_missing("AWS_SSO_START_URL", _extract_tfvar_string(tfvars_path, "AWS_SSO_START_URL"))

    console.print(f"[dim]Synced runtime env from Terraform dir: {terraform_dir}[/dim]")


def _discover_identity_center_defaults() -> Tuple[str, str]:
    client = boto3.client("sso-admin")
    response = client.list_instances()
    instances = response.get("Instances", [])
    if not instances:
        raise RuntimeError("No IAM Identity Center instance discovered in this account/region.")
    first = instances[0]
    identity_store_id = first.get("IdentityStoreId")
    instance_arn = first.get("InstanceArn")
    if not identity_store_id or not instance_arn:
        raise RuntimeError("Identity Center instance missing IdentityStoreId or InstanceArn.")
    return identity_store_id, instance_arn


def _resolve_identity_center(identity_store_id: Optional[str], sso_instance_arn: Optional[str]) -> Tuple[str, str]:
    resolved_identity = identity_store_id or os.environ.get("IDENTITY_STORE_ID")
    resolved_instance = sso_instance_arn or os.environ.get("SSO_INSTANCE_ARN")
    if resolved_identity and resolved_instance:
        return resolved_identity, resolved_instance

    discovered_identity, discovered_instance = _discover_identity_center_defaults()
    return resolved_identity or discovered_identity, resolved_instance or discovered_instance


def _require_policy_env() -> None:
    required = ["BOUNDARY_DEVELOPERS_ID", "BOUNDARY_SECURITY_ADMINS_ID", "PROD_OU_ID"]
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise RuntimeError(
            "Missing policy environment variables: "
            + ", ".join(missing)
            + ". Set them or run with Terraform sync enabled."
        )


def _build_runtime(
    args: argparse.Namespace,
    console: Console,
    *,
    need_workflow: bool,
    need_orgs: bool,
) -> Tuple[Optional[CLISlackWorkflow], StateStore, Optional[AWSOrganizationsAdapter]]:
    if not args.no_terraform_sync:
        _sync_env_from_terraform(args.terraform_dir, console)

    dynamo_table = args.dynamo_table or os.environ.get("DYNAMODB_TABLE")
    if not dynamo_table:
        raise RuntimeError("DynamoDB table not configured. Set --dynamo-table or DYNAMODB_TABLE.")

    state_store = StateStore(table_name=dynamo_table)
    orgs = AWSOrganizationsAdapter() if (need_orgs or need_workflow) else None

    if not need_workflow:
        return None, state_store, orgs

    identity_store_id, sso_instance_arn = _resolve_identity_center(args.identity_store_id, args.sso_instance_arn)
    _set_env_if_missing("IDENTITY_STORE_ID", identity_store_id)
    _set_env_if_missing("SSO_INSTANCE_ARN", sso_instance_arn)

    _require_policy_env()

    bot_token = args.bot_token or os.environ.get("SLACK_BOT_TOKEN")
    if not bot_token:
        bot_token = get_bot_token()

    slack_adapter = SlackAdapter(bot_token)
    identity_adapter = IdentityStoreAdapter(identity_store_id)
    engine = PolicyEngine(args.config_path)
    workflow = CLISlackWorkflow(
        slack_adapter=slack_adapter,
        identity_adapter=identity_adapter,
        engine=engine,
        orgs_adapter=orgs,
        state_store=state_store,
        bot_token=bot_token,
        console=console,
    )
    return workflow, state_store, orgs


def _as_plain(value: Any) -> Any:
    if isinstance(value, Decimal):
        if value % 1 == 0:
            return int(value)
        return float(value)
    return value


def _fmt_epoch(value: Any) -> str:
    value = _as_plain(value)
    if value in (None, "", 0):
        return "-"
    try:
        ts = float(value)
        return datetime.fromtimestamp(ts, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError):
        return str(value)


def _status_style(status: str) -> str:
    canonical = canonicalize_status(status)
    if canonical == STATE_ACTIVE:
        return "green"
    if canonical == STATE_PENDING_APPROVAL:
        return "yellow"
    if canonical == STATE_REVOKED:
        return "cyan"
    if canonical == STATE_DENIED:
        return "red"
    return "white"


def _print_request_item(console: Console, item: Dict[str, Any], heading: str) -> None:
    print_banner(console)
    console.print(f"[bold]{heading}[/bold]\n")

    status = canonicalize_status(str(item.get("status", "")))
    status_text = f"[{_status_style(status)}]{status}[/{_status_style(status)}]" if status else "-"

    rows = [
        ("Request ID", str(item.get("request_id", "-"))),
        ("Status", status_text),
        ("Account", str(item.get("account_id", "-"))),
        ("Permission Set", str(item.get("permission_set_name", "-"))),
        ("Principal ID", str(item.get("principal_id", "-"))),
        ("Requester Slack", str(item.get("requester_slack_user_id") or item.get("slack_user_id") or "-")),
        ("Approver Slack", str(item.get("approver_slack_user_id", "-"))),
        ("Ticket", str(item.get("ticket_id", "-"))),
        ("Reason", str(item.get("reason", "-"))),
        ("Requested At", _fmt_epoch(item.get("requested_at"))),
        ("Expires At", _fmt_epoch(item.get("expires_at"))),
        ("Approved At", _fmt_epoch(item.get("approved_at"))),
        ("Denied At", _fmt_epoch(item.get("denied_at"))),
        ("Revoked At", _fmt_epoch(item.get("revoked_at"))),
    ]

    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column(style="white")
    for key, val in rows:
        table.add_row(key, val)
    console.print(table)


def _run_request(args: argparse.Namespace, console: Console) -> int:
    workflow, state_store, _ = _build_runtime(args, console, need_workflow=True, need_orgs=False)
    assert workflow is not None

    request_id = args.request_id or f"req-cli-{uuid.uuid4().hex[:12]}"
    command_parts = [args.account_id, args.permission_set, str(args.hours)]
    if args.ticket_id:
        command_parts.append(args.ticket_id)

    event = {
        "request_type": "access_request",
        "request_id": request_id,
        "user_id": args.slack_user_id,
        "command_text": " ".join(command_parts),
        "response_url": args.response_url,
    }
    workflow.process_request(event)

    item = state_store.get_request(request_id)
    if not item:
        console.print(
            "[red]No request record was persisted.[/red] "
            "The workflow likely rejected input before state write."
        )
        return 3

    _print_request_item(console, item, "Boundary Request Result")
    status = canonicalize_status(str(item.get("status", "")))
    if status in {STATE_ACTIVE, STATE_PENDING_APPROVAL}:
        return 0
    if status == STATE_DENIED:
        return 2
    return 3


def _run_approval(args: argparse.Namespace, console: Console, action: str) -> int:
    workflow, state_store, _ = _build_runtime(args, console, need_workflow=True, need_orgs=False)
    assert workflow is not None

    event = {
        "request_type": "approval_action",
        "request_id": args.request_id,
        "action": action,
        "approver_slack_user_id": args.approver_slack_user_id,
    }
    workflow.process_approval_action(event)

    item = state_store.get_request(args.request_id)
    if not item:
        console.print(f"[red]Request not found:[/red] {args.request_id}")
        return 1

    _print_request_item(console, item, f"Boundary {action.title()} Result")
    status = canonicalize_status(str(item.get("status", "")))
    if action == "approve":
        return 0 if status == STATE_ACTIVE else 1
    return 0 if status == STATE_DENIED else 1


def _run_status(args: argparse.Namespace, console: Console) -> int:
    _, state_store, _ = _build_runtime(args, console, need_workflow=False, need_orgs=False)
    item = state_store.get_request(args.request_id)
    if not item:
        console.print(f"[red]Request not found:[/red] {args.request_id}")
        return 1
    _print_request_item(console, item, "Boundary Request Status")
    return 0


def _run_revoke(args: argparse.Namespace, console: Console) -> int:
    _, state_store, orgs = _build_runtime(args, console, need_workflow=False, need_orgs=True)
    assert orgs is not None

    item = state_store.get_request(args.request_id)
    if not item:
        console.print(f"[red]Request not found:[/red] {args.request_id}")
        return 1

    current_status = canonicalize_status(str(item.get("status", "")))
    if current_status != STATE_ACTIVE:
        console.print(f"[red]Request is not ACTIVE:[/red] {args.request_id} ({current_status})")
        _print_request_item(console, item, "Boundary Revoke Skipped")
        return 1

    if args.dry_run:
        console.print(f"[yellow]Dry run:[/yellow] would revoke request {args.request_id}")
        _print_request_item(console, item, "Boundary Revoke Preview")
        return 0

    orgs.remove_user_from_account(
        principal_id=str(item["principal_id"]),
        account_id=str(item["account_id"]),
        permission_set_arn=str(item["permission_set_arn"]),
        instance_arn=str(item["instance_arn"]),
        principal_type=str(item.get("principal_type", "USER")),
    )
    state_store.update_status(
        args.request_id,
        STATE_REVOKED,
        extra_updates={
            "revoked_at": time.time(),
            "reason": args.reason,
        },
    )

    refreshed = state_store.get_request(args.request_id) or item
    _print_request_item(console, refreshed, "Boundary Revoke Result")
    return 0


def _run_janitor(args: argparse.Namespace, console: Console) -> int:
    if not args.no_terraform_sync:
        _sync_env_from_terraform(args.terraform_dir, console)
    dynamo_table = args.dynamo_table or os.environ.get("DYNAMODB_TABLE")
    if not dynamo_table:
        raise RuntimeError("DynamoDB table not configured. Set --dynamo-table or DYNAMODB_TABLE.")

    # Import lazily to avoid janitor logger side effects for other subcommands.
    from janitor import run_revocation_loop

    result = run_revocation_loop(table_name=dynamo_table, dry_run=args.dry_run)
    print_banner(console)
    console.print(f"[bold]Boundary Janitor Result[/bold]\n{json.dumps(result, indent=2, sort_keys=True)}")
    if int(result.get("errors", 0)) > 0:
        return 1
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Boundary operator CLI (Slack-equivalent request lifecycle + revocation)."
    )
    parser.add_argument(
        "--terraform-dir",
        default=DEFAULT_TERRAFORM_DIR,
        help=f"Terraform env dir used to hydrate runtime env (default: {DEFAULT_TERRAFORM_DIR})",
    )
    parser.add_argument(
        "--no-terraform-sync",
        action="store_true",
        help="Skip automatic env hydration from terraform output/tfvars.",
    )
    parser.add_argument(
        "--config-path",
        default=DEFAULT_CONFIG_PATH,
        help=f"Policy config path (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument("--dynamo-table", help="Override DynamoDB table name.")
    parser.add_argument("--identity-store-id", help="Override Identity Store ID.")
    parser.add_argument("--sso-instance-arn", help="Override IAM Identity Center instance ARN.")
    parser.add_argument("--bot-token", help="Override Slack bot token (xoxb-...).")

    subparsers = parser.add_subparsers(dest="command", required=True)

    request_parser = subparsers.add_parser("request", help="Submit a request through the Slack workflow.")
    request_parser.add_argument("slack_user_id", help="Requester Slack user ID (e.g., U12345678).")
    request_parser.add_argument("account_id", help="Target AWS account ID.")
    request_parser.add_argument("permission_set", help="Permission set name (e.g., ReadOnlyAccess).")
    request_parser.add_argument("hours", type=float, help="Requested duration in hours.")
    request_parser.add_argument("ticket_id", nargs="?", default=None, help="Optional ticket ID.")
    request_parser.add_argument("--request-id", help="Optional explicit request ID.")
    request_parser.add_argument(
        "--response-url",
        default=DEFAULT_RESPONSE_URL,
        help=f"Slack response_url shape used by workflow validation (default: {DEFAULT_RESPONSE_URL})",
    )

    approve_parser = subparsers.add_parser("approve", help="Approve a pending request.")
    approve_parser.add_argument("request_id", help="Request ID to approve.")
    approve_parser.add_argument("approver_slack_user_id", help="Approver Slack user ID.")

    deny_parser = subparsers.add_parser("deny", help="Deny a pending request.")
    deny_parser.add_argument("request_id", help="Request ID to deny.")
    deny_parser.add_argument("approver_slack_user_id", help="Approver Slack user ID.")

    status_parser = subparsers.add_parser("status", help="Show full status/details for a request.")
    status_parser.add_argument("request_id", help="Request ID to inspect.")

    revoke_parser = subparsers.add_parser("revoke", help="Revoke an ACTIVE request immediately.")
    revoke_parser.add_argument("request_id", help="Request ID to revoke.")
    revoke_parser.add_argument("--dry-run", action="store_true", help="Preview revoke without AWS write.")
    revoke_parser.add_argument(
        "--reason",
        default="Revoked manually via boundary CLI.",
        help="Audit reason stored on the request item.",
    )

    janitor_parser = subparsers.add_parser("janitor", help="Run janitor-style expiration revoke loop now.")
    janitor_parser.add_argument("--dry-run", action="store_true", help="Scan only, do not revoke.")

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    console = Console(highlight=False)

    try:
        if args.command == "request":
            return _run_request(args, console)
        if args.command == "approve":
            return _run_approval(args, console, "approve")
        if args.command == "deny":
            return _run_approval(args, console, "deny")
        if args.command == "status":
            return _run_status(args, console)
        if args.command == "revoke":
            return _run_revoke(args, console)
        if args.command == "janitor":
            return _run_janitor(args, console)
        parser.error(f"Unknown command: {args.command}")
        return 2
    except Exception as exc:
        console.print(f"[bold red]Boundary CLI error:[/bold red] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
