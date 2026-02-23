import urllib.request
import urllib.error
import json
import logging
import random
import time
import os
import uuid
import boto3
from typing import Dict, Any, Optional

from adapters.slack_adapter import SlackAdapter, SlackAPIError
from adapters.identity_store_adapter import IdentityStoreAdapter, IdentityStoreError
from adapters.aws_orgs import AWSOrganizationsAdapter, AWSResourceNotFoundError
from adapters.state_store import StateStore
from core.engine import PolicyEngine
from models.request import AccessRequest
from models.request_states import (
    STATE_ACTIVE,
    STATE_APPROVED,
    STATE_DENIED,
    STATE_ERROR,
    STATE_PENDING_APPROVAL,
    canonicalize_status,
)
from validators import validate_duration, validate_account_id

logger = logging.getLogger(__name__)

# Warm start cache for SSM parameter
ssm = boto3.client('ssm')
CACHED_BOT_TOKEN = None

def get_bot_token():
    global CACHED_BOT_TOKEN
    if CACHED_BOT_TOKEN:
        return CACHED_BOT_TOKEN
    
    logger.info("Cold Start: Fetching Slack bot token from SSM Parameter Store...")
    try:
        response = ssm.get_parameter(
            Name='/boundary/slack/bot_token',
            WithDecryption=True
        )
        CACHED_BOT_TOKEN = response['Parameter']['Value']
        return CACHED_BOT_TOKEN
    except Exception as e:
        logger.error(f"Failed to fetch bot token: {e}")
        raise

class WorkflowError(Exception):
    """Base exception for workflow errors."""
    pass

class SlackWorkflow:
    def __init__(self, slack_adapter: SlackAdapter, identity_adapter: IdentityStoreAdapter,
                 engine: PolicyEngine, orgs_adapter: AWSOrganizationsAdapter, state_store: StateStore,
                 bot_token: Optional[str] = None):
        self.slack = slack_adapter
        self.identity = identity_adapter
        self.engine = engine
        self.orgs = orgs_adapter
        self.state = state_store
        self.bot_token = bot_token or get_bot_token()
        self.sso_start_url = os.environ.get("AWS_SSO_START_URL", "").strip()

    def _validate_response_url(self, url: str) -> None:
        if not url or not url.startswith("https://hooks.slack.com/"):
            raise WorkflowError("Invalid Slack response URL")

    def _send_slack_reply(
        self,
        response_url: str,
        message: str,
        is_success: bool = True,
        max_retries: int = 3,
        login_url: Optional[str] = None
    ) -> None:
        self._validate_response_url(response_url)
        
        color = "#2EB67D" if is_success else "#E01E5A"
        payload = {
            "response_type": "ephemeral",
            "attachments": [
                {
                    "color": color,
                    "text": message
                }
            ]
        }

        if login_url and login_url.startswith("https://"):
            payload["attachments"][0]["actions"] = [
                {
                    "type": "button",
                    "text": "Click Here to Login",
                    "url": login_url,
                    "style": "primary"
                }
            ]
        
        for attempt in range(1, max_retries + 1):
            req = urllib.request.Request(
                response_url,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            
            try:
                with urllib.request.urlopen(req, timeout=10):  # nosec B310
                    logger.debug("Slack reply sent successfully")
                    return
                    
            except urllib.error.HTTPError as e:
                if attempt == max_retries:
                    logger.error(f"Failed to send Slack reply after {max_retries} attempts: HTTP {e.code}")
                    return

                backoff = 2 ** (attempt - 1)
                jitter = random.uniform(0, backoff * 0.5)
                time.sleep(backoff + jitter)

            except urllib.error.URLError:
                if attempt == max_retries:
                    logger.error(f"Network error sending Slack reply after {max_retries} attempts")
                    return

                backoff = 2 ** (attempt - 1)
                jitter = random.uniform(0, backoff * 0.5)
                time.sleep(backoff + jitter)

    @staticmethod
    def _is_valid_slack_user_id(slack_user_id: str) -> bool:
        return (
            isinstance(slack_user_id, str)
            and len(slack_user_id) >= 9
            and slack_user_id[0] in {"U", "W"}
        )

    def _slack_api_post(self, method: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        req = urllib.request.Request(
            f"https://slack.com/api/{method}",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.bot_token}",
                "Content-Type": "application/json; charset=utf-8"
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as response:  # nosec B310
                body = json.loads(response.read().decode("utf-8"))
                if not body.get("ok"):
                    raise WorkflowError(f"Slack API error: {body.get('error', 'unknown_error')}")
                return body
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="ignore")
            raise WorkflowError(f"Slack API HTTP error {e.code}: {error_body}") from e
        except urllib.error.URLError as e:
            raise WorkflowError(f"Slack API network error: {e}") from e

    def _resolve_dm_channel(self, slack_user_id: str) -> str:
        try:
            body = self._slack_api_post("conversations.open", {"users": slack_user_id})
            channel_id = body.get("channel", {}).get("id")
            if channel_id:
                return channel_id
        except Exception as e:
            logger.warning(f"Failed to open DM channel for {slack_user_id}, falling back to App Home: {e}")
        return slack_user_id

    def _send_slack_dm(self, slack_user_id: str, message: str, login_url: Optional[str] = None) -> None:
        if not self._is_valid_slack_user_id(slack_user_id):
            raise WorkflowError(f"Invalid Slack user ID format: {slack_user_id}")

        channel = self._resolve_dm_channel(slack_user_id)
        payload: Dict[str, Any] = {"channel": channel, "text": message}
        if login_url and login_url.startswith("https://"):
            payload["blocks"] = [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": message}
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Click Here to Login"},
                            "url": login_url,
                            "style": "primary"
                        }
                    ]
                }
            ]
        self._slack_api_post("chat.postMessage", payload)

    def _send_approval_request(self, request: AccessRequest, decision: Any) -> None:
        if not decision.approval_channel:
            raise WorkflowError("Approval is required by policy, but no approval channel is configured.")

        ticket_line = f"\n*Ticket:* `{request.ticket_id}`" if request.ticket_id else ""
        duration_hours = round(decision.effective_duration_hours or 0.0, 2)
        message = (
            f"*Approval Required* for `{request.permission_set_name}`\n"
            f"*Request:* `{request.request_id}`\n"
            f"*Requester:* <@{request.slack_user_id}>\n"
            f"*Account:* `{request.account_id}`\n"
            f"*Duration:* `{duration_hours} hours`"
            f"{ticket_line}"
        )
        payload = {
            "channel": decision.approval_channel,
            "text": message,
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": message}
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "action_id": "boundary_approve",
                            "text": {"type": "plain_text", "text": "Approve"},
                            "style": "primary",
                            "value": request.request_id
                        },
                        {
                            "type": "button",
                            "action_id": "boundary_deny",
                            "text": {"type": "plain_text", "text": "Deny"},
                            "style": "danger",
                            "value": request.request_id
                        }
                    ]
                }
            ]
        }
        self._slack_api_post("chat.postMessage", payload)

    def _resolve_group_id_from_alias(self, group_alias: Optional[str]) -> Optional[str]:
        if not group_alias:
            return None
        groups = self.engine.config.get("subjects", {}).get("groups", {})
        group_cfg = groups.get(group_alias, {})
        return group_cfg.get("id")

    def _is_approver_authorized(self, approver_slack_user_id: str, required_group_alias: Optional[str]) -> bool:
        required_group_id = self._resolve_group_id_from_alias(required_group_alias)
        if not required_group_id:
            logger.error(f"Approval group '{required_group_alias}' could not be resolved to a configured group ID.")
            return False

        try:
            approver_email = self.slack.get_user_email(approver_slack_user_id)
            approver_aws_user_id = self.identity.get_user_id_by_email(approver_email)
            approver_group_ids = self.identity.get_user_group_memberships(approver_aws_user_id)
            return required_group_id in approver_group_ids
        except Exception as e:
            logger.warning(f"Failed to authorize approver {approver_slack_user_id}: {e}")
            return False

    def _provision_access(self, principal_id: str, account_id: str, permission_set_arn: str, instance_arn: str) -> None:
        self.orgs.assign_user_to_account(
            principal_id=principal_id,
            account_id=account_id,
            permission_set_arn=permission_set_arn,
            instance_arn=instance_arn,
            principal_type="USER"
        )

    def process_request(self, event: Dict[str, Any]) -> None:
        slack_user_id = event.get('user_id')
        command_text = event.get('command_text', '')
        response_url = event.get('response_url')
        account_id = "unknown"
        permission_set = "unknown"

        if not slack_user_id or not response_url:
            logger.error("Missing required fields in event payload")
            return
        
        try:
            self._validate_response_url(response_url)
        except WorkflowError as e:
            logger.error(f"Invalid response_url: {e}")
            return

        logger.info("Starting access request workflow")

        try:
            # 1. Identity Translation
            email = self.slack.get_user_email(slack_user_id)
            aws_user_id = self.identity.get_user_id_by_email(email)

            group_ids = self.identity.get_user_group_memberships(aws_user_id)
            if not group_ids:
                raise WorkflowError("You are not a member of any authorized groups.")

            # 2. Command Parsing
            parts = command_text.split()
            if parts and parts[0].lower() == 'request':
                parts = parts[1:]

            if len(parts) < 3:
                raise WorkflowError("Usage: /boundary <AccountID> <PermissionSet> <Hours> [TicketID]")

            try:
                account_id = validate_account_id(parts[0])
                permission_set = parts[1]
                duration_hours = validate_duration(float(parts[2]))
            except ValueError as e:
                raise WorkflowError(f"Invalid input: {e}")

            ticket_id = None
            optional_parts = parts[3:]
            if optional_parts:
                if len(optional_parts) == 1:
                    ticket_value = optional_parts[0]
                elif len(optional_parts) == 2 and optional_parts[0].lower() == "ticket":
                    ticket_value = optional_parts[1]
                else:
                    raise WorkflowError(
                        "Usage: /boundary <AccountID> <PermissionSet> <Hours> [TicketID]\n"
                        "Examples: /boundary 123456789012 AdministratorAccess 1 INC-12345\n"
                        "          /boundary 123456789012 AdministratorAccess 1 ticket INC-12345"
                    )

                if ticket_value.lower().startswith("ticket="):
                    ticket_value = ticket_value.split("=", 1)[1]

                ticket_id = ticket_value.strip() or None
                if not ticket_id:
                    raise WorkflowError("Ticket ID is empty. Provide a value like INC-12345.")
                if len(ticket_id) > 128:
                    raise WorkflowError("Ticket ID is too long (max 128 characters).")

            # Use a dedicated prefix to prevent user-controlled input from reading
            # arbitrary environment variables (e.g. AWS_SECRET_ACCESS_KEY).
            env_key = f"PERMISSION_SET_{permission_set}"
            permission_set_arn = os.environ.get(env_key)
            if not permission_set_arn:
                raise WorkflowError(
                    f"Configuration Error: Could not find the true AWS ARN for '{permission_set}'. "
                    f"Contact your admin — no ARN mapping found for '{permission_set}'."
                )

            # 3. Policy Evaluation
            aws_context = self.orgs.build_account_context(account_id)
            decision = None
            request = None
            deny_reasons = []
            first_denied_candidate = None
            first_denied_decision = None

            for group_id in group_ids:
                candidate = AccessRequest(
                    request_id=f"req-{uuid.uuid4().hex[:16]}",
                    principal_id=group_id,
                    principal_type="GROUP",
                    permission_set_arn=permission_set_arn,
                    permission_set_name=permission_set,
                    account_id=account_id,
                    instance_arn=os.environ['SSO_INSTANCE_ARN'],
                    rule_id="",
                    ticket_id=ticket_id,
                    slack_user_id=slack_user_id,
                    requested_at=time.time(),
                    expires_at=time.time() + (duration_hours * 3600)
                )

                temp_decision = self.engine.evaluate(candidate, aws_context)
                if temp_decision.effect == "ALLOW":
                    decision = temp_decision
                    request = candidate
                    break
                if first_denied_candidate is None:
                    first_denied_candidate = candidate
                    first_denied_decision = temp_decision
                reason = (temp_decision.reason or "").strip()
                if reason and reason.lower() != "denied by default policy.":
                    deny_reasons.append(reason)

            if not decision or decision.effect == "DENY":
                deny_reason = deny_reasons[0] if deny_reasons else "None of your groups are authorized for this request."
                denied_request = first_denied_candidate
                if denied_request is None:
                    denied_request = AccessRequest(
                        request_id=f"req-{uuid.uuid4().hex[:16]}",
                        principal_id=aws_user_id,
                        principal_type="USER",
                        permission_set_arn=permission_set_arn,
                        permission_set_name=permission_set,
                        account_id=account_id,
                        instance_arn=os.environ['SSO_INSTANCE_ARN'],
                        rule_id="",
                        ticket_id=ticket_id,
                        slack_user_id=slack_user_id,
                        requester_slack_user_id=slack_user_id,
                        requested_at=time.time(),
                        expires_at=time.time() + (duration_hours * 3600)
                    )
                denied_request.principal_id = aws_user_id
                denied_request.principal_type = "USER"
                denied_request.slack_response_url = response_url
                denied_request.status = STATE_DENIED
                denied_request.reason = deny_reason
                if first_denied_decision:
                    denied_request.rule_id = first_denied_decision.rule_id or denied_request.rule_id
                    denied_request.policy_hash = first_denied_decision.policy_hash
                    denied_request.engine_version = first_denied_decision.engine_version
                    denied_request.evaluated_at = first_denied_decision.evaluated_at
                try:
                    self.state.save_request(denied_request)
                except Exception as persist_error:
                    logger.warning(f"Failed to persist denied request audit record: {persist_error}")
                self._send_slack_reply(
                    response_url,
                    f"❌ *Access Denied*\n*Reason:* {deny_reason}",
                    is_success=False
                )
                return

            if request is None:
                raise WorkflowError("Request creation failed unexpectedly.")

            request.rule_id = decision.rule_id or ""
            request.principal_id = aws_user_id
            request.principal_type = "USER"
            request.requester_slack_user_id = slack_user_id
            request.slack_response_url = response_url
            request.approval_required = decision.approval_required
            request.approval_channel = decision.approval_channel
            request.approver_group = decision.approver_group
            request.reason = decision.reason
            request.policy_hash = decision.policy_hash
            request.engine_version = decision.engine_version
            request.evaluated_at = decision.evaluated_at
            if decision.effective_expires_at:
                request.expires_at = decision.effective_expires_at

            if decision.approval_required:
                request.status = STATE_PENDING_APPROVAL
                self.state.save_request(request)
                try:
                    self._send_approval_request(request, decision)
                except Exception as e:
                    logger.error(f"Failed to post approval request for {request.request_id}: {e}")
                    self.state.update_status(
                        request.request_id,
                        STATE_ERROR,
                        extra_updates={"reason": "Failed to post approval request to Slack channel."}
                    )
                    raise WorkflowError(
                        "Failed to route approval request to the security channel. Please contact support."
                    )
                self._send_slack_reply(
                    response_url,
                    (
                        "⏳ *Approval Required*\n"
                        f"Your request `{request.request_id}` is pending Security Team approval."
                    ),
                    is_success=True
                )
                return

            # 4. Provisioning + state persistence
            try:
                self._provision_access(
                    principal_id=request.principal_id,
                    account_id=request.account_id,
                    permission_set_arn=request.permission_set_arn,
                    instance_arn=request.instance_arn
                )
                request.status = STATE_ACTIVE
                self.state.save_request(request)
            except Exception as e:
                logger.error(f"Failed during AWS provisioning or state save: {e}")
                self._send_slack_reply(
                    response_url,
                    "❌ *System Error*\nProvisioning failed after policy evaluation. Please contact support.",
                    is_success=False
                )
                return

            # 5. Success Notification
            formatted_duration = round(decision.effective_duration_hours or duration_hours, 2)
            success_msg = (
                f"✅ *Access Granted!*\n"
                f"*Account:* `{account_id}`\n"
                f"*Role:* `{permission_set}`\n"
                f"*Duration:* `{formatted_duration} hours`\n"
                f"*Status:* Active & Provisioned\n"
                f"*Note:* Revocation blocks new sessions at expiry. "
                f"If you already started a session, it may remain active until its normal session expiration."
            )
            self._send_slack_reply(
                response_url,
                success_msg,
                is_success=True,
                login_url=self.sso_start_url if self.sso_start_url else None
            )

        except (SlackAPIError, IdentityStoreError, WorkflowError, AWSResourceNotFoundError) as e:
            logger.warning(f"Workflow error: {type(e).__name__}")
            if isinstance(e, SlackAPIError):
                user_msg = "Unable to retrieve your Slack profile."
            elif isinstance(e, IdentityStoreError):
                user_msg = "Unable to map your identity to AWS."
            elif isinstance(e, AWSResourceNotFoundError):
                user_msg = f"AWS Account '{account_id}' could not be found or analyzed."
            else:
                user_msg = str(e)
            
            self._send_slack_reply(response_url, f"⚠️ {user_msg}", is_success=False)
            
        except Exception as e:
            logger.error(f"Unexpected workflow error: {type(e).__name__}", exc_info=True)
            self._send_slack_reply(
                response_url,
                "⚠️ An unexpected error occurred. Please contact support.",
                is_success=False
            )

    def process_approval_action(self, event: Dict[str, Any]) -> None:
        request_id = event.get("request_id", "")
        action = str(event.get("action", "")).lower()
        approver_slack_user_id = event.get("approver_slack_user_id", "")

        if action not in {"approve", "deny"} or not request_id or not approver_slack_user_id:
            logger.error("Invalid approval action payload")
            return

        item = self.state.get_request(request_id)
        if not item:
            logger.warning(f"Approval action for unknown request_id: {request_id}")
            return

        current_status = item.get("status")
        if canonicalize_status(current_status) != STATE_PENDING_APPROVAL:
            logger.info(f"Ignoring approval action for {request_id}; status is {current_status}")
            return

        required_group_alias = item.get("approver_group")
        if approver_slack_user_id == item.get("slack_user_id"):
            logger.warning(f"Self-approval attempt by {approver_slack_user_id} for {request_id}")
            try:
                self._send_slack_dm(
                    approver_slack_user_id,
                    f"❌ You cannot approve your own request `{request_id}`."
                )
            except Exception:
                logger.warning("Failed to notify self-approver via Slack DM")
            return

        if not self._is_approver_authorized(approver_slack_user_id, required_group_alias):
            logger.warning(f"Unauthorized approval attempt by {approver_slack_user_id} for {request_id}")
            try:
                self._send_slack_dm(
                    approver_slack_user_id,
                    f"❌ You are not authorized to approve request `{request_id}`."
                )
            except Exception:
                logger.warning("Failed to notify unauthorized approver via Slack DM")
            return

        if action == "deny":
            updated = self.state.transition_status_if_current(
                request_id=request_id,
                expected_status=STATE_PENDING_APPROVAL,
                new_status=STATE_DENIED,
                extra_updates={
                    "approver_slack_user_id": approver_slack_user_id,
                    "denied_by": approver_slack_user_id,
                    "denied_at": time.time(),
                    "reason": "Denied by approver in Slack."
                }
            )
            if not updated:
                logger.info(f"Approval decision race detected for {request_id}; request already decided.")
                return

            requester = item.get("slack_user_id")
            if requester:
                try:
                    self._send_slack_dm(
                        requester,
                        (
                            f"❌ Access request `{request_id}` was denied.\n"
                            f"Account: {item.get('account_id', 'unknown')}\n"
                            f"Role: {item.get('permission_set_name', 'requested')}"
                        )
                    )
                except Exception as e:
                    logger.warning(f"Denied request {request_id}, but failed to notify requester: {e}")
            return

        updated = self.state.transition_status_if_current(
            request_id=request_id,
            expected_status=STATE_PENDING_APPROVAL,
            new_status=STATE_APPROVED,
            extra_updates={
                "approver_slack_user_id": approver_slack_user_id,
                "approved_by": approver_slack_user_id,
                "approved_at": time.time()
            }
        )
        if not updated:
            logger.info(f"Approval decision race detected for {request_id}; request already decided.")
            return

        try:
            self._provision_access(
                principal_id=item["principal_id"],
                account_id=item["account_id"],
                permission_set_arn=item["permission_set_arn"],
                instance_arn=item["instance_arn"]
            )
            self.state.update_status(request_id, STATE_ACTIVE)
        except Exception as e:
            logger.error(f"Provisioning failed after approval for {request_id}: {e}")
            self.state.update_status(
                request_id,
                STATE_ERROR,
                extra_updates={"reason": "Provisioning failed after approval."}
            )
            requester = item.get("slack_user_id")
            if requester:
                try:
                    self._send_slack_dm(
                        requester,
                        (
                            f"⚠️ Request `{request_id}` was approved, but provisioning failed.\n"
                            "Please contact support."
                        )
                    )
                except Exception:
                    logger.warning(f"Failed to notify requester about post-approval failure for {request_id}")
            return

        requester = item.get("slack_user_id")
        if requester:
            try:
                self._send_slack_dm(
                    requester,
                    (
                        "✅ Access Approved & Provisioned!\n"
                        f"Account: {item.get('account_id', 'unknown')}\n"
                        f"Role: {item.get('permission_set_name', 'requested')}\n"
                        f"Request: {request_id}\n"
                        "*Note:* Revocation blocks new sessions at expiry. "
                        "If you already started a session, it may remain active until its normal session expiration."
                    ),
                    login_url=self.sso_start_url if self.sso_start_url else None
                )
            except Exception as e:
                logger.warning(f"Approved {request_id}, but failed to notify requester: {e}")


def lambda_handler(event, context):
    try:
        # Bootstrap configuration
        bot_token = get_bot_token()
        identity_store_id = os.environ['IDENTITY_STORE_ID']
        _ = os.environ['SSO_INSTANCE_ARN']
        dynamo_table = os.environ['DYNAMODB_TABLE']
        config_path = os.environ.get('ACCESS_RULES_PATH', 'access_rules.yaml')

        # Instantiate adapters and engine
        slack_adapter = SlackAdapter(bot_token)
        identity_adapter = IdentityStoreAdapter(identity_store_id)
        engine = PolicyEngine(config_path)
        orgs_adapter = AWSOrganizationsAdapter()
        state_store = StateStore(table_name=dynamo_table)
        workflow = SlackWorkflow(
            slack_adapter,
            identity_adapter,
            engine,
            orgs_adapter,
            state_store,
            bot_token=bot_token
        )
    except Exception as e:
        logger.error(f"CRITICAL: Failed to bootstrap the workflow environment: {e}")
        raise

    for record in event.get('Records', []):
        try:
            raw_body = record.get('body', '{}')
            ticket = json.loads(raw_body)
            request_type = ticket.get("request_type", "access_request")
            if request_type == "approval_action":
                workflow.process_approval_action(ticket)
            else:
                workflow.process_request(ticket)
        except Exception as e:
            logger.error(f"Unexpected error processing record: {e}")
            raise
