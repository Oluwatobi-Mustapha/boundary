"""
Smoke tests for the three proven JIT flows using mocked adapters.

These tests exercise:
1) ReadOnly grant -> revoke
2) PowerUser grant -> revoke
3) Admin request -> pending approval -> approve -> active -> revoke
"""
import os
import sys
from typing import Dict, List, Tuple

import pytest

# Ensure imports resolve like the Lambda package layout.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

# Prevent boto3 from trying EC2 metadata in local test runs.
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")

from src.core.engine import PolicyEngine
from src.models.aws_context import AWSAccountContext
from src.workflows.access_workflow import SlackWorkflow
from src import janitor
from src.models.request_states import STATE_DENIED


REQUESTER_SLACK_ID = "UREQUESTER1"
APPROVER_SLACK_ID = "UAPPROVER1"
VALID_RESPONSE_URL = "https://hooks.slack.com/services/T000/B000/xyz"


class FakeSlackAdapter:
    def __init__(self, emails: Dict[str, str]):
        self.emails = emails

    def get_user_email(self, slack_user_id: str) -> str:
        return self.emails[slack_user_id]


class FakeIdentityStoreAdapter:
    def __init__(self, email_to_user_id: Dict[str, str], memberships: Dict[str, List[str]]):
        self.email_to_user_id = email_to_user_id
        self.memberships = memberships

    def get_user_id_by_email(self, email: str) -> str:
        return self.email_to_user_id[email]

    def get_user_group_memberships(self, aws_user_id: str) -> List[str]:
        return self.memberships.get(aws_user_id, [])


class FakeOrgsAdapter:
    def __init__(self, account_tags: Dict[str, str]):
        self.account_tags = account_tags
        self.assign_calls: List[dict] = []

    def build_account_context(self, account_id: str) -> AWSAccountContext:
        return AWSAccountContext(
            ou_path_ids=["r-9e0f", "ou-9e0f-06fgnz07"],
            tags=self.account_tags,
        )

    def assign_user_to_account(
        self,
        principal_id: str,
        account_id: str,
        permission_set_arn: str,
        instance_arn: str,
        principal_type: str = "USER",
    ) -> None:
        self.assign_calls.append(
            {
                "principal_id": principal_id,
                "account_id": account_id,
                "permission_set_arn": permission_set_arn,
                "instance_arn": instance_arn,
                "principal_type": principal_type,
            }
        )


class FakeWorkflowStateStore:
    def __init__(self):
        self.items: Dict[str, dict] = {}

    def save_request(self, request) -> None:
        self.items[request.request_id] = {
            "request_id": request.request_id,
            "principal_id": request.principal_id,
            "principal_type": request.principal_type,
            "permission_set_arn": request.permission_set_arn,
            "permission_set_name": request.permission_set_name,
            "account_id": request.account_id,
            "instance_arn": request.instance_arn,
            "rule_id": request.rule_id,
            "status": request.status,
            "ticket_id": request.ticket_id,
            "slack_user_id": request.slack_user_id,
            "slack_response_url": request.slack_response_url,
            "approval_required": request.approval_required,
            "approval_channel": request.approval_channel,
            "approver_group": request.approver_group,
            "approved_by": request.approved_by,
            "approved_at": request.approved_at,
            "denied_by": request.denied_by,
            "denied_at": request.denied_at,
            "reason": request.reason,
            "policy_hash": request.policy_hash,
            "engine_version": request.engine_version,
            "evaluated_at": request.evaluated_at,
            "requester_slack_user_id": request.requester_slack_user_id,
            "approver_slack_user_id": request.approver_slack_user_id,
            "created_at": request.created_at,
            "updated_at": request.updated_at,
            "revoked_at": request.revoked_at,
            "requested_at": request.requested_at,
            "expires_at": request.expires_at,
        }

    def get_request(self, request_id: str):
        return self.items.get(request_id)

    def transition_status_if_current(
        self,
        request_id: str,
        expected_status: str,
        new_status: str,
        extra_updates=None,
    ) -> bool:
        item = self.items.get(request_id)
        if not item or item.get("status") != expected_status:
            return False
        item["status"] = new_status
        if extra_updates:
            item.update(extra_updates)
        return True

    def update_status(self, request_id: str, new_status: str, extra_updates=None) -> None:
        self.items[request_id]["status"] = new_status
        if extra_updates:
            self.items[request_id].update(extra_updates)


class FakeJanitorOrgsAdapter:
    def __init__(self):
        self.remove_calls: List[dict] = []

    def remove_user_from_account(
        self,
        principal_id: str,
        account_id: str,
        permission_set_arn: str,
        instance_arn: str,
        principal_type: str = "USER",
    ) -> None:
        self.remove_calls.append(
            {
                "principal_id": principal_id,
                "account_id": account_id,
                "permission_set_arn": permission_set_arn,
                "instance_arn": instance_arn,
                "principal_type": principal_type,
            }
        )


class FakeJanitorStateStore:
    def __init__(self, item: dict):
        self.item = item
        self.status_updates: List[Tuple[str, str]] = []

    def get_expired_active_requests(self):
        return [self.item]

    def update_status(self, request_id: str, new_status: str, extra_updates=None):
        self.item["status"] = new_status
        if extra_updates:
            self.item.update(extra_updates)
        self.status_updates.append((request_id, new_status))


@pytest.fixture
def configured_env(monkeypatch):
    env = {
        "BOUNDARY_DEVELOPERS_ID": "dev-group-id",
        "BOUNDARY_SECURITY_ADMINS_ID": "sec-group-id",
        "STAGING_OU_ID": "ou-9e0f-06fgnz07",
        "PROD_OU_ID": "ou-9e0f-prod00001",
        "SSO_INSTANCE_ARN": "arn:aws:sso:::instance/ssoins-1234567890abcdef",
        "ReadOnlyAccess": "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-readonly",
        "PowerUserAccess": "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-poweruser",
        "AdministratorAccess": "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-admin",
        "AWS_SSO_START_URL": "https://d-90660198e6.awsapps.com/start",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return env


def _make_workflow(account_tags: Dict[str, str]):
    slack = FakeSlackAdapter(
        {
            REQUESTER_SLACK_ID: "requester@example.com",
            APPROVER_SLACK_ID: "approver@example.com",
        }
    )
    identity = FakeIdentityStoreAdapter(
        {
            "requester@example.com": "aws-user-requester",
            "approver@example.com": "aws-user-approver",
        },
        {
            "aws-user-requester": ["dev-group-id"],
            "aws-user-approver": ["sec-group-id"],
        },
    )
    engine = PolicyEngine("config/access_rules.yaml")
    orgs = FakeOrgsAdapter(account_tags=account_tags)
    state = FakeWorkflowStateStore()
    workflow = SlackWorkflow(
        slack_adapter=slack,
        identity_adapter=identity,
        engine=engine,
        orgs_adapter=orgs,
        state_store=state,
        bot_token="xoxb-test",
    )
    return workflow, orgs, state


def _run_janitor_revoke(monkeypatch, item: dict):
    fake_orgs = FakeJanitorOrgsAdapter()
    fake_state = FakeJanitorStateStore(item)
    notifications = []

    monkeypatch.setattr(janitor, "AWSOrganizationsAdapter", lambda: fake_orgs)
    monkeypatch.setattr(janitor, "StateStore", lambda table_name: fake_state)
    monkeypatch.setattr(
        janitor,
        "notify_revocation",
        lambda slack_user_id, req_item: notifications.append((slack_user_id, req_item["request_id"])),
    )

    result = janitor.run_revocation_loop(table_name="boundary-dev-state", dry_run=False)
    return result, fake_orgs, fake_state, notifications


def test_readonly_grant_and_revoke_flow(configured_env, monkeypatch):
    workflow, orgs, state = _make_workflow({"Environment": "Prod"})
    replies = []
    workflow._send_slack_reply = lambda response_url, message, is_success=True, max_retries=3, login_url=None: replies.append(  # noqa: E501
        {"message": message, "success": is_success, "login_url": login_url}
    )

    workflow.process_request(
        {
            "user_id": REQUESTER_SLACK_ID,
            "command_text": "request 512539654006 ReadOnlyAccess 0.5",
            "response_url": VALID_RESPONSE_URL,
        }
    )

    assert len(state.items) == 1
    item = next(iter(state.items.values()))
    assert item["status"] == "ACTIVE"
    assert item["permission_set_name"] == "ReadOnlyAccess"
    assert len(orgs.assign_calls) == 1
    assert any("Access Granted" in r["message"] for r in replies)

    result, fake_orgs, fake_state, notifications = _run_janitor_revoke(monkeypatch, item)
    assert result["status"] == "success"
    assert result["revoked"] == 1
    assert fake_orgs.remove_calls[0]["account_id"] == "512539654006"
    assert fake_state.item["status"] == "REVOKED"
    assert notifications == [(REQUESTER_SLACK_ID, item["request_id"])]


def test_poweruser_grant_and_revoke_flow(configured_env, monkeypatch):
    workflow, orgs, state = _make_workflow({"Environment": "Dev"})
    replies = []
    workflow._send_slack_reply = lambda response_url, message, is_success=True, max_retries=3, login_url=None: replies.append(  # noqa: E501
        {"message": message, "success": is_success, "login_url": login_url}
    )

    workflow.process_request(
        {
            "user_id": REQUESTER_SLACK_ID,
            "command_text": "request 184425328037 PowerUserAccess 0.5",
            "response_url": VALID_RESPONSE_URL,
        }
    )

    assert len(state.items) == 1
    item = next(iter(state.items.values()))
    assert item["status"] == "ACTIVE"
    assert item["permission_set_name"] == "PowerUserAccess"
    assert len(orgs.assign_calls) == 1
    assert any("Access Granted" in r["message"] for r in replies)

    result, fake_orgs, fake_state, notifications = _run_janitor_revoke(monkeypatch, item)
    assert result["status"] == "success"
    assert result["revoked"] == 1
    assert fake_orgs.remove_calls[0]["account_id"] == "184425328037"
    assert fake_state.item["status"] == "REVOKED"
    assert notifications == [(REQUESTER_SLACK_ID, item["request_id"])]


def test_admin_pending_approval_approve_active_revoke_flow(configured_env, monkeypatch):
    workflow, orgs, state = _make_workflow({"Environment": "Sandbox"})
    replies = []
    approval_posts = []
    dms = []

    workflow._send_slack_reply = lambda response_url, message, is_success=True, max_retries=3, login_url=None: replies.append(  # noqa: E501
        {"message": message, "success": is_success, "login_url": login_url}
    )
    workflow._send_approval_request = lambda request, decision: approval_posts.append(
        {"request_id": request.request_id, "channel": decision.approval_channel}
    )
    workflow._send_slack_dm = lambda slack_user_id, message, login_url=None: dms.append(
        {"slack_user_id": slack_user_id, "message": message, "login_url": login_url}
    )

    workflow.process_request(
        {
            "user_id": REQUESTER_SLACK_ID,
            "command_text": "request 220065406396 AdministratorAccess 0.5 CHG-20260223-001",
            "response_url": VALID_RESPONSE_URL,
        }
    )

    assert len(state.items) == 1
    item = next(iter(state.items.values()))
    assert item["status"] == "PENDING_APPROVAL"
    assert item["ticket_id"] == "CHG-20260223-001"
    assert orgs.assign_calls == []
    assert len(approval_posts) == 1
    assert approval_posts[0]["channel"] == "#security-approvals"
    assert any("Approval Required" in r["message"] for r in replies)

    workflow.process_approval_action(
        {
            "request_id": item["request_id"],
            "action": "approve",
            "approver_slack_user_id": APPROVER_SLACK_ID,
        }
    )

    assert state.items[item["request_id"]]["status"] == "ACTIVE"
    assert len(orgs.assign_calls) == 1
    assert orgs.assign_calls[0]["account_id"] == "220065406396"
    assert any("Access Approved & Provisioned" in dm["message"] for dm in dms)

    result, fake_orgs, fake_state, notifications = _run_janitor_revoke(
        monkeypatch, state.items[item["request_id"]]
    )
    assert result["status"] == "success"
    assert result["revoked"] == 1
    assert fake_orgs.remove_calls[0]["account_id"] == "220065406396"
    assert fake_state.item["status"] == "REVOKED"
    assert notifications == [(REQUESTER_SLACK_ID, item["request_id"])]


def test_denied_request_is_persisted_with_reason(configured_env):
    workflow, orgs, state = _make_workflow({"Environment": "Dev"})
    del orgs  # only validating state persistence behavior here
    replies = []
    workflow._send_slack_reply = lambda response_url, message, is_success=True, max_retries=3, login_url=None: replies.append(  # noqa: E501
        {"message": message, "success": is_success}
    )

    # Admin requires Sandbox tag + ticket; this request should deny and be persisted.
    workflow.process_request(
        {
            "user_id": REQUESTER_SLACK_ID,
            "command_text": "request 184425328037 AdministratorAccess 0.5",
            "response_url": VALID_RESPONSE_URL,
        }
    )

    assert len(state.items) == 1
    item = next(iter(state.items.values()))
    assert item["status"] == STATE_DENIED
    assert isinstance(item.get("reason"), str) and item["reason"]
    assert any("Access Denied" in r["message"] for r in replies)
