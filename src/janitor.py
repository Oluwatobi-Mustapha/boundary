import sys
import os
import argparse
import logging
import json
import time
import urllib.request
import urllib.error

import boto3

# --- PATH FIX ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# ----------------

from adapters.aws_orgs import AWSOrganizationsAdapter
from adapters.state_store import StateStore
from models.request_states import STATE_REVOKED

# --- LOGGING CONFIGURATION ---
# We configure this globally so it applies to both CLI and Lambda contexts. 
logger = logging.getLogger()

ssm = boto3.client("ssm")
SLACK_API_BASE = "https://slack.com/api"
DEFAULT_SLACK_SSM_PARAM = "/boundary/slack/bot_token"
_cached_bot_token = None

# 1. FORCE the log level to INFO. 
#    AWS Lambda defaults to WARNING, which swallows our heartbeat logs.
log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
logger.setLevel(getattr(logging, log_level))

# 2. Add a handler only if none exists (Prevent duplicate logs in CLI).
#    In Lambda, a handler already exists, so this block is skipped, 
#    but the setLevel above ensures the existing handler sees our INFO logs.
if not logger.handlers:
    console_handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
# -----------------------------

def get_bot_token() -> str:
    """
    Fetches Slack bot token from SSM and caches it for warm starts.
    """
    global _cached_bot_token
    if _cached_bot_token:
        return _cached_bot_token

    parameter_name = os.environ.get("SLACK_BOT_TOKEN_PARAM", DEFAULT_SLACK_SSM_PARAM)
    response = ssm.get_parameter(Name=parameter_name, WithDecryption=True)
    _cached_bot_token = response["Parameter"]["Value"]
    return _cached_bot_token

def _is_valid_slack_user_id(slack_user_id: str) -> bool:
    return (
        isinstance(slack_user_id, str)
        and len(slack_user_id) >= 9
        and slack_user_id[0] in {"U", "W"}
    )

def _slack_api_post(method: str, token: str, payload: dict) -> dict:
    """
    Calls a Slack Web API method and returns the decoded body.
    """
    req = urllib.request.Request(
        f"{SLACK_API_BASE}/{method}",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json; charset=utf-8"
        },
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=10) as response:  # nosec B310
        body = json.loads(response.read().decode("utf-8"))
        if not body.get("ok"):
            raise Exception(f"{method} failed: {body.get('error', 'unknown_error')}")
        return body

def _resolve_dm_channel(token: str, slack_user_id: str) -> str:
    """
    Opens (or fetches) the bot-user DM channel.
    Falls back to user ID (App Home target) if DM open fails.
    """
    try:
        body = _slack_api_post("conversations.open", token, {"users": slack_user_id})
        channel_id = body.get("channel", {}).get("id")
        if channel_id:
            return channel_id
    except Exception as e:
        logger.warning(f"Failed to open DM channel for {slack_user_id}, falling back to App Home: {e}")

    return slack_user_id

def notify_revocation(slack_user_id: str, item: dict) -> None:
    """
    Sends a calm DM to the requester after successful revocation.
    """
    if not _is_valid_slack_user_id(slack_user_id):
        raise ValueError(f"Invalid Slack user ID format: {slack_user_id}")

    token = get_bot_token()
    channel = _resolve_dm_channel(token, slack_user_id)
    permission_set_name = item.get("permission_set_name", "requested")
    account_id = item.get("account_id", "unknown")
    request_id = item.get("request_id", "unknown")

    message = (
        "Access update: your temporary AWS access has now ended and was revoked.\n"
        f"Account: {account_id}\n"
        f"Role: {permission_set_name}\n"
        f"Request: {request_id}\n"
        "Revocation blocks new sessions now. If you already had an active session, "
        "it may remain usable until its normal session expiry."
    )

    _slack_api_post("chat.postMessage", token, {"channel": channel, "text": message})

    logger.info(f"Slack revocation notification sent to {slack_user_id} for {request_id}")

def run_revocation_loop(table_name: str, dry_run: bool = False):
    """
    Core logic separated from the entry point so it can be called by CLI or Lambda.
    """
    logger.info("🧹 Janitor starting up...")
    
    # 1. Initialize Adapters
    try:
        adapter = AWSOrganizationsAdapter()
        state_store = StateStore(table_name=table_name)
    except Exception as e:
        logger.error(f"Failed to initialize adapters: {e}")
        return {"status": "error", "message": str(e)}

    # 2. Find Expired Requests
    logger.info("Querying for expired active requests...")
    expired_requests = state_store.get_expired_active_requests()
    
    if not expired_requests:
        logger.info("✨ No expired requests found. Clean system.")
        return {"status": "success", "revoked": 0, "errors": 0}

    logger.info(f"Found {len(expired_requests)} requests to revoke.")

    # 3. Revocation Loop
    revocation_count = 0
    error_count = 0

    for item in expired_requests:
        req_id = item['request_id']
        principal = item['principal_id']
        account = item['account_id']
        
        logger.info(f"Processing Revocation: {req_id} (User: {principal}, Account: {account})")

        if dry_run:
            logger.info("DRY RUN: Skipping actual API calls.")
            continue

        try:
            # A. Revoke in AWS
            adapter.remove_user_from_account(
                principal_id=principal,
                account_id=account,
                permission_set_arn=item['permission_set_arn'],
                instance_arn=item['instance_arn'],
                principal_type=item.get('principal_type', 'USER')
            )

            # B. Update DB Status
            state_store.update_status(
                req_id,
                STATE_REVOKED,
                extra_updates={
                    "revoked_at": time.time(),
                    "reason": "Expired temporary access revoked by janitor."
                }
            )
            logger.info(f"✅ Successfully revoked {req_id}")
            revocation_count += 1

            # C. Notify requester in Slack (best-effort only)
            slack_user_id = item.get("slack_user_id")
            if slack_user_id:
                try:
                    notify_revocation(slack_user_id, item)
                except Exception as notify_err:
                    logger.warning(
                        f"Revoked {req_id}, but failed to send Slack revocation notification: {notify_err}"
                    )
            else:
                logger.info(f"Revoked {req_id}, but no slack_user_id was stored on the request item.")

        except Exception as e:
            logger.error(f"❌ Failed to revoke {req_id}: {e}")
            error_count += 1

    logger.info(f"Janitor Run Complete. Revoked: {revocation_count}, Errors: {error_count}")
    
    return {
        "status": "success" if error_count == 0 else "partial_failure",
        "revoked": revocation_count,
        "errors": error_count
    }

# --- ENTRY POINT 1: AWS LAMBDA ---
def lambda_handler(event, context):
    """
    AWS Lambda calls this function automatically.
    """
    # In Lambda, we get configuration from Environment Variables
    table_name = os.environ.get("DYNAMODB_TABLE")
    if not table_name:
        logger.error("CRITICAL: DYNAMODB_TABLE environment variable not set.")
        raise ValueError("CRITICAL: DYNAMODB_TABLE environment variable not set.")
    
    return run_revocation_loop(table_name=table_name, dry_run=False)

# --- ENTRY POINT 2: LOCAL CLI ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Boundary: The Janitor (Revocation Worker)")
    parser.add_argument("--dynamo-table", required=True, help="The DynamoDB table name to scan")
    parser.add_argument("--dry-run", action="store_true", help="Scan only, do not revoke")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)

    result = run_revocation_loop(args.dynamo_table, args.dry_run)
    
    # Map result to exit code for CI/CD
    if result["errors"] > 0:
        sys.exit(1)
    sys.exit(0)
