"""
Tests for P0 fix: Permission set env var lookup must use PERMISSION_SET_ prefix
to prevent user-controlled exfiltration of arbitrary environment variables.
"""
import os
import sys
import types
import pytest
from unittest.mock import MagicMock, patch
from dataclasses import dataclass, field
from typing import Optional

_src = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
for p in (_src, _root):
    if p not in sys.path:
        sys.path.insert(0, p)

# ── Build stub modules with real exception classes ────────────────────────


class _SlackAPIError(Exception):
    pass


class _IdentityStoreError(Exception):
    pass


class _AWSResourceNotFoundError(Exception):
    pass


# adapters.slack_adapter
_slack_mod = types.ModuleType("adapters.slack_adapter")
_slack_mod.SlackAdapter = MagicMock
_slack_mod.SlackAPIError = _SlackAPIError
sys.modules["adapters.slack_adapter"] = _slack_mod

# adapters.identity_store_adapter
_id_mod = types.ModuleType("adapters.identity_store_adapter")
_id_mod.IdentityStoreAdapter = MagicMock
_id_mod.IdentityStoreError = _IdentityStoreError
sys.modules["adapters.identity_store_adapter"] = _id_mod

# adapters.aws_orgs
_orgs_mod = types.ModuleType("adapters.aws_orgs")
_orgs_mod.AWSOrganizationsAdapter = MagicMock
_orgs_mod.AWSResourceNotFoundError = _AWSResourceNotFoundError
sys.modules["adapters.aws_orgs"] = _orgs_mod

# adapters.state_store
_state_mod = types.ModuleType("adapters.state_store")
_state_mod.StateStore = MagicMock
sys.modules["adapters.state_store"] = _state_mod

# adapters (package)
_adapters_pkg = types.ModuleType("adapters")
sys.modules["adapters"] = _adapters_pkg

# core.engine
_engine_mod = types.ModuleType("core.engine")
_engine_mod.PolicyEngine = MagicMock
sys.modules["core.engine"] = _engine_mod
sys.modules["core"] = types.ModuleType("core")

# models.request_states — provide real constants
_states_mod = types.ModuleType("models.request_states")
_states_mod.STATE_ACTIVE = "ACTIVE"
_states_mod.STATE_APPROVED = "APPROVED"
_states_mod.STATE_DENIED = "DENIED"
_states_mod.STATE_ERROR = "ERROR"
_states_mod.STATE_PENDING_APPROVAL = "PENDING_APPROVAL"
_states_mod.canonicalize_status = lambda s: s
sys.modules["models.request_states"] = _states_mod


# models.request — provide a real dataclass
@dataclass
class AccessRequest:
    request_id: str = ""
    principal_id: str = ""
    principal_type: str = ""
    permission_set_arn: str = ""
    permission_set_name: str = ""
    account_id: str = ""
    instance_arn: str = ""
    rule_id: str = ""
    ticket_id: Optional[str] = None
    slack_user_id: str = ""
    requester_slack_user_id: str = ""
    requested_at: float = 0.0
    expires_at: float = 0.0
    status: str = ""
    reason: str = ""
    slack_response_url: str = ""
    approval_required: bool = False
    approval_channel: str = ""
    approver_group: str = ""
    policy_hash: str = ""
    engine_version: str = ""
    evaluated_at: float = 0.0


_request_mod = types.ModuleType("models.request")
_request_mod.AccessRequest = AccessRequest
sys.modules["models.request"] = _request_mod
sys.modules["models"] = types.ModuleType("models")

# Also register under src.models.* for imports that use that prefix
sys.modules["src.models"] = sys.modules["models"]
sys.modules["src.models.request"] = sys.modules["models.request"]
sys.modules["src.models.request_states"] = sys.modules["models.request_states"]

# validators — use the real validators
import src.validators as _real_validators  # noqa: E402
sys.modules["validators"] = _real_validators

# boto3 stub (SSM client at module scope)
_mock_boto3 = MagicMock()
sys.modules["boto3"] = _mock_boto3

# Now import access_workflow
from workflows.access_workflow import SlackWorkflow, WorkflowError  # noqa: E402


def _build_workflow():
    """Create a SlackWorkflow with all adapters mocked."""
    slack = MagicMock()
    identity = MagicMock()
    engine = MagicMock()
    orgs = MagicMock()
    state = MagicMock()
    wf = SlackWorkflow(
        slack_adapter=slack,
        identity_adapter=identity,
        engine=engine,
        orgs_adapter=orgs,
        state_store=state,
        bot_token="xoxb-fake",
    )
    return wf, slack, identity, engine, orgs, state


def _base_event(account_id="123456789012", perm_set="ReadOnlyAccess", hours="1"):
    return {
        "user_id": "U12345ABCD",
        "command_text": f"{account_id} {perm_set} {hours}",
        "response_url": "https://hooks.slack.com/actions/T0/B0/xxxx",
    }


class TestPermissionSetEnvLookupPrefixed:
    """Ensure the PERMISSION_SET_ prefix is used for env var lookup."""

    @patch.dict(os.environ, {
        "PERMISSION_SET_ReadOnlyAccess": "arn:aws:sso:::permissionSet/ssoins-123/ps-ro",
        "SSO_INSTANCE_ARN": "arn:aws:sso:::instance/ssoins-123",
    }, clear=False)
    def test_valid_permission_set_resolved_via_prefix(self):
        """Permission set name is looked up with PERMISSION_SET_ prefix."""
        wf, slack, identity, engine, orgs, state = _build_workflow()

        slack.get_user_email.return_value = "dev@example.com"
        identity.get_user_id_by_email.return_value = "aws-user-id"
        identity.get_user_group_memberships.return_value = ["group-1"]

        decision = MagicMock()
        decision.effect = "ALLOW"
        decision.approval_required = False
        decision.rule_id = "rule-1"
        decision.reason = "allowed"
        decision.effective_duration_hours = 1.0
        decision.effective_expires_at = None
        decision.policy_hash = "abc"
        decision.engine_version = "1.0"
        decision.evaluated_at = 1000.0
        engine.evaluate.return_value = decision

        wf.process_request(_base_event())

        # Provisioning should have been called with the prefixed ARN value
        orgs.assign_user_to_account.assert_called_once()
        call_kwargs = orgs.assign_user_to_account.call_args
        assert call_kwargs[1]["permission_set_arn"] == "arn:aws:sso:::permissionSet/ssoins-123/ps-ro"

    @patch.dict(os.environ, {
        "AWS_SECRET_ACCESS_KEY": "super-secret-key",
        "SSO_INSTANCE_ARN": "arn:aws:sso:::instance/ssoins-123",
    }, clear=False)
    def test_arbitrary_env_var_not_leaked(self):
        """Attacker supplying 'AWS_SECRET_ACCESS_KEY' as permission set name
        must NOT cause the real env var value to be read."""
        wf, slack, identity, engine, orgs, state = _build_workflow()

        slack.get_user_email.return_value = "attacker@example.com"
        identity.get_user_id_by_email.return_value = "aws-user-id"
        identity.get_user_group_memberships.return_value = ["group-1"]

        event = _base_event(perm_set="AWS_SECRET_ACCESS_KEY")
        wf.process_request(event)

        # Provisioning must NOT have been called (lookup should fail)
        orgs.assign_user_to_account.assert_not_called()

    @patch.dict(os.environ, {
        "SSO_INSTANCE_ARN": "arn:aws:sso:::instance/ssoins-123",
    }, clear=False)
    def test_missing_permission_set_returns_config_error(self):
        """When the prefixed env var doesn't exist, a config error is returned."""
        wf, slack, identity, engine, orgs, state = _build_workflow()

        slack.get_user_email.return_value = "dev@example.com"
        identity.get_user_id_by_email.return_value = "aws-user-id"
        identity.get_user_group_memberships.return_value = ["group-1"]

        event = _base_event(perm_set="NonExistentSet")
        wf.process_request(event)

        # Should not have provisioned anything
        orgs.assign_user_to_account.assert_not_called()

    @patch.dict(os.environ, {
        "ReadOnlyAccess": "arn:aws:sso:::permissionSet/ssoins-123/ps-old-unprefixed",
        "SSO_INSTANCE_ARN": "arn:aws:sso:::instance/ssoins-123",
    }, clear=False)
    def test_unprefixed_env_var_not_used(self):
        """Even if an unprefixed env var exists, it must NOT be used."""
        wf, slack, identity, engine, orgs, state = _build_workflow()

        slack.get_user_email.return_value = "dev@example.com"
        identity.get_user_id_by_email.return_value = "aws-user-id"
        identity.get_user_group_memberships.return_value = ["group-1"]

        event = _base_event(perm_set="ReadOnlyAccess")
        wf.process_request(event)

        # Without PERMISSION_SET_ReadOnlyAccess, provisioning should NOT happen
        orgs.assign_user_to_account.assert_not_called()
