import urllib.request
import urllib.error
import json
import logging
import random
import time
from typing import Dict, Any

from src.adapters.slack_adapter import SlackAdapter, SlackAPIError
from src.adapters.identity_store_adapter import IdentityStoreAdapter, IdentityStoreError
from src.validators import validate_duration

logger = logging.getLogger(__name__)

class WorkflowError(Exception):
    """Base exception for workflow errors."""
    pass

class SlackWorkflow:
    def __init__(self, slack_adapter: SlackAdapter, identity_adapter: IdentityStoreAdapter):
        """
        Orchestrates Slack-to-AWS identity mapping and access provisioning.
        
        Args:
            slack_adapter: Adapter for Slack API operations
            identity_adapter: Adapter for AWS Identity Store operations
        """
        self.slack = slack_adapter
        self.identity = identity_adapter

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
                with urllib.request.urlopen(req, timeout=10) as response:  # nosec B310
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
                
            except urllib.error.URLError as e:
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
            "command_text": "AdministratorAccess 2",
            "response_url": "https://hooks.slack.com/..."
        }
        
        Args:
            event: Event payload from Slack Bot Lambda
        """
        slack_user_id = event.get('user_id')
        command_text = event.get('command_text', '')
        response_url = event.get('response_url')

        # Validate required fields
        if not all([slack_user_id, response_url]):
            logger.error("Missing required fields in event payload")
            return
        
        # Validate response_url BEFORE try block to avoid unhandled exceptions in error handlers
        try:
            self._validate_response_url(response_url)
        except WorkflowError as e:
            logger.error(f"Invalid response_url: {e}")
            return

        logger.info("Starting access request workflow")

        try:
            # 1. Identity Translation Chain
            email = self.slack.get_user_email(slack_user_id)
            aws_principal_id = self.identity.get_user_id_by_email(email)
            
            # Log at DEBUG level to avoid PII exposure
            logger.debug("Identity mapped successfully")

            # 2. Command Parsing
            parts = command_text.split()
            if len(parts) < 2:
                raise WorkflowError("Usage: /boundary <PermissionSet> <Hours>")
            
            permission_set = parts[0]
            
            # Validate duration using validators module
            try:
                duration_hours = float(parts[1])
                validate_duration(duration_hours)
            except ValueError as e:
                raise WorkflowError(f"Invalid duration: {e}")

            # 3. Policy Evaluation (STUB - to be implemented)
            # from src.workflow import AccessWorkflow
            # from src.models.request import AccessRequest
            # request = AccessRequest(principal_id=aws_principal_id, ...)
            # result = policy_workflow.handle_request(request)
            
            decision_is_allow = True
            decision_reason = "Policy evaluation passed"
            
            if not decision_is_allow:
                self._send_slack_reply(
                    response_url,
                    f"❌ Access Denied: {decision_reason}",
                    is_success=False
                )
                return

            # 4. Provisioning (STUB - to be implemented)
            # sso_adapter.create_account_assignment(...)
            # dynamodb_adapter.save_active_request(...)

            # 5. Success Notification
            success_msg = (
                f"✅ Access Granted!\n"
                f"*Role:* {permission_set}\n"
                f"*Duration:* {duration_hours} hours\n"
                f"*Status:* Provisioning..."
            )
            self._send_slack_reply(response_url, success_msg, is_success=True)

        except (SlackAPIError, IdentityStoreError, WorkflowError) as e:
            # Expected errors - log type but don't expose details to user
            logger.warning(f"Workflow error: {type(e).__name__}")
            
            # Map exceptions to user-friendly messages (no PII)
            if isinstance(e, SlackAPIError):
                user_msg = "Unable to retrieve your Slack profile. Please try again."
            elif isinstance(e, IdentityStoreError):
                user_msg = "Unable to map your identity to AWS. Please contact your administrator."
            elif isinstance(e, WorkflowError):
                # WorkflowError messages are safe (no PII)
                user_msg = str(e)
            else:
                user_msg = "An error occurred processing your request."
            
            self._send_slack_reply(response_url, f"⚠️ {user_msg}", is_success=False)
            
        except Exception as e:
            # Unexpected errors - log with full context but don't expose details
            logger.error(f"Unexpected workflow error: {type(e).__name__}", exc_info=True)
            self._send_slack_reply(
                response_url,
                "⚠️ An unexpected error occurred. Please contact support.",
                is_success=False
            )
