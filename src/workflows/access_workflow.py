import urllib.request
import urllib.error
import json
import logging
import random
import time
import os
import uuid
import boto3
from typing import Dict, Any

from src.adapters.slack_adapter import SlackAdapter, SlackAPIError
from src.adapters.identity_store_adapter import IdentityStoreAdapter, IdentityStoreError
from src.adapters.aws_orgs import AWSOrganizationsAdapter, AWSResourceNotFoundError
from src.core.engine import PolicyEngine
from src.models.request import AccessRequest
from src.validators import validate_duration, validate_account_id

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
                 engine: PolicyEngine, orgs_adapter: AWSOrganizationsAdapter):
        """
        Orchestrates Slack-to-AWS identity mapping and access provisioning.
        
        Args:
            slack_adapter: Adapter for Slack API operations
            identity_adapter: Adapter for AWS Identity Store operations
            engine: Policy evaluation engine
            orgs_adapter: AWS Organizations adapter for account context
        """
        self.slack = slack_adapter
        self.identity = identity_adapter
        self.engine = engine
        self.orgs = orgs_adapter

    def _validate_response_url(self, url: str) -> None:
        """
        Validates Slack response_url to prevent URL injection attacks.
        
        Args:
            url: The response_url from Slack
            
        Raises:
            WorkflowError: If URL is invalid or not from Slack
        """
        if not url or not url.startswith("https://hooks.slack.com/"):
            raise WorkflowError("Invalid Slack response URL")

    def _send_slack_reply(self, response_url: str, message: str, is_success: bool = True, max_retries: int = 3) -> None:
        """
        Sends asynchronous reply to Slack using response_url webhook.
        
        Args:
            response_url: Slack webhook URL
            message: Message to send
            is_success: Whether this is a success or error message
            max_retries: Maximum retry attempts
        """
        # Validate URL to prevent injection attacks
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
                    return  # Fail-open: don't crash workflow if notification fails
                
                backoff = 2 ** (attempt - 1)
                jitter = random.uniform(0, backoff * 0.5)
                logger.warning(f"Slack reply failed (HTTP {e.code}), retrying... (Attempt {attempt}/{max_retries})")
                time.sleep(backoff + jitter)
                
            except urllib.error.URLError:
                if attempt == max_retries:
                    logger.error(f"Network error sending Slack reply after {max_retries} attempts")
                    return  # Fail-open: don't crash workflow if notification fails
                
                backoff = 2 ** (attempt - 1)
                jitter = random.uniform(0, backoff * 0.5)
                logger.warning(f"Network error sending Slack reply, retrying... (Attempt {attempt}/{max_retries})")
                time.sleep(backoff + jitter)

    def process_request(self, event: Dict[str, Any]) -> None:
        """
        Main entry point for processing Slack access requests.
        
        Expected event payload:
        {
            "user_id": "U1234",
            "command_text": "<AccountID> <PermissionSet> <Hours>",
            "response_url": "https://hooks.slack.com/..."
        }
        
        Args:
            event: Event payload from Slack Bot Lambda
        """
        slack_user_id = event.get('user_id')
        command_text = event.get('command_text', '')
        response_url = event.get('response_url')

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
            logger.debug("Identity mapped successfully")
            
            # 2. Fetch user's group memberships
            group_ids = self.identity.get_user_group_memberships(aws_user_id)
            if not group_ids:
                raise WorkflowError("You are not a member of any authorized groups.")
            logger.info(f"User belongs to {len(group_ids)} group(s)")

            # 2. Command Parsing
            parts = command_text.split()
            if len(parts) < 3:
                raise WorkflowError("Usage: /boundary <AccountID> <PermissionSet> <Hours>")
            
            try:
                account_id = validate_account_id(parts[0])
                permission_set = parts[1]
                duration_hours = validate_duration(float(parts[2]))
            except ValueError as e:
                raise WorkflowError(f"Invalid input: {e}")

            # 3. Policy Evaluation
            logger.info(f"Fetching AWS Context for account {account_id}...")
            aws_context = self.orgs.build_account_context(account_id)

            # Evaluate policy for each group the user belongs to
            decision = None
            
            for group_id in group_ids:
                request = AccessRequest(
                    request_id=f"req-{uuid.uuid4().hex[:16]}",
                    principal_id=group_id,
                    principal_type="GROUP",
                    permission_set_arn=f"arn:aws:sso:::permissionSet/{permission_set}",
                    permission_set_name=permission_set,
                    account_id=account_id,
                    instance_arn=os.environ['SSO_INSTANCE_ARN'],
                    rule_id="",  # Will be populated by policy engine on ALLOW
                    requested_at=time.time(),
                    expires_at=time.time() + (duration_hours * 3600)
                )
                
                temp_decision = self.engine.evaluate(request, aws_context)
                
                if temp_decision.effect == "ALLOW":
                    decision = temp_decision
                    logger.info(f"Access authorized by group: {group_id}")
                    break
            
            if not decision or decision.effect == "DENY":
                self._send_slack_reply(
                    response_url,
                    "❌ *Access Denied*\n*Reason:* None of your groups are authorized for this request.",
                    is_success=False
                )
                return

            # Populate rule_id for audit trail
            request.rule_id = decision.rule_id or ""

            # 4. Success Notification
            success_msg = (
                f"✅ *Access Granted!*\n"
                f"*Account:* `{account_id}`\n"
                f"*Role:* `{permission_set}`\n"
                f"*Duration:* `{decision.effective_duration_hours} hours`\n"
                f"*Status:* Provisioning... (WIP)"
            )
            self._send_slack_reply(response_url, success_msg, is_success=True)

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


def lambda_handler(event, context):
    """
    Lambda entry point for workflow processing.
    
    Args:
        event: SQS event containing access request tickets
        context: Lambda context object
    """
    try:
        # Bootstrap configuration
        bot_token = get_bot_token()
        identity_store_id = os.environ['IDENTITY_STORE_ID']
        _ = os.environ['SSO_INSTANCE_ARN']  # Validate presence at bootstrap
        config_path = os.environ.get('ACCESS_RULES_PATH', 'config/access_rules.yaml')
        
        # Instantiate adapters and engine
        slack_adapter = SlackAdapter(bot_token)
        identity_adapter = IdentityStoreAdapter(identity_store_id)
        engine = PolicyEngine(config_path)
        orgs_adapter = AWSOrganizationsAdapter()
        
        workflow = SlackWorkflow(slack_adapter, identity_adapter, engine, orgs_adapter)

    except KeyError as e:
        logger.error(f"CRITICAL: Missing required environment variable: {e}")
        raise
    except Exception as e:
        logger.error(f"CRITICAL: Failed to bootstrap the workflow environment: {e}")
        raise

    for record in event.get('Records', []):
        try:
            raw_body = record.get('body', '{}')
            ticket = json.loads(raw_body)
            logger.info(f"Processing ticket from SQS: {record.get('messageId')}")
            workflow.process_request(ticket)
        except json.JSONDecodeError:
            logger.error("Failed to parse SQS message body as JSON. Discarding message.")
        except Exception as e:
            logger.error(f"Unexpected error processing record: {e}")
            raise
