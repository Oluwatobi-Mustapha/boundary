import json
import logging
import boto3
import os
import time
import hmac
import hashlib
import base64
import urllib.parse

# --- 1. GLOBAL SCOPE (Cold Start Initialization) ---
logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

# Initialize the AWS SDK clients outside the handler
ssm_client = boto3.client('ssm')
lambda_client = boto3.client('lambda')

# This is our in-memory cache
CACHED_SLACK_SECRET = None 
# ---------------------------------------------------

def verify_slack_signature(headers: dict, body: str, secret: str) -> bool:
    """
    Cryptographically proves the request came from Slack and prevents replay attacks.
    """
    timestamp = headers.get('x-slack-request-timestamp')
    slack_signature = headers.get('x-slack-signature')

    if not timestamp or not slack_signature:
        return False

    # 1. Defeat the Replay Attack (5-minute window)
    if abs(time.time() - int(timestamp)) > 60 * 5:
        logger.warning("Replay attack detected or extreme clock drift!")
        return False

    # 2. Reconstruct the base string Slack used to create the signature
    sig_basestring = f"v0:{timestamp}:{body}"

    # 3. Calculate our own HMAC-SHA256 signature
    my_signature = 'v0=' + hmac.new(
        secret.encode('utf-8'),
        sig_basestring.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    # 4. Compare securely (hmac.compare_digest prevents timing attacks)
    return hmac.compare_digest(my_signature, slack_signature)

def lambda_handler(event, context):
    global CACHED_SLACK_SECRET
    
    logger.info("Slack Bot received an event!")
    
    # --- 2. WARM START CHECK ---
    if CACHED_SLACK_SECRET is None:
        logger.info("Cold Start: Fetching Slack Secret from AWS SSM...")
        try:
            # The Waiter uses their new IAM badge to open the SSM vault!
            response = ssm_client.get_parameter(
                Name='/boundary/slack/signing_secret', 
                WithDecryption=True
            )
            CACHED_SLACK_SECRET = response['Parameter']['Value']
        except Exception as e:
            logger.error(f"Failed to fetch secret: {e}")
            return {"statusCode": 500, "body": "Internal Server Error"}
    else:
        logger.info("Warm Start: Using cached Slack Secret.")
        
    # --- 3. THE SLACK MATH ---
    headers = {k.lower(): v for k, v in event.get('headers', {}).items()}
    raw_body = event.get('body', '')

    if not verify_slack_signature(headers, raw_body, CACHED_SLACK_SECRET):
        logger.error("🚨 Invalid Slack Signature! Dropping request.")
        return {"statusCode": 401, "body": "Unauthorized"}
        
    logger.info("✅ Slack Signature Verified!")
    
    # --- 4. DECODE AND PARSE THE PAYLOAD ---
    if event.get('isBase64Encoded', False):
        logger.info("Decoding Base64 payload from API Gateway...")
        decoded_body = base64.b64decode(raw_body).decode('utf-8')
    else:
        decoded_body = raw_body

    parsed_body = urllib.parse.parse_qs(decoded_body)
    
    user_id = parsed_body.get('user_id', [''])[0]
    command_text = parsed_body.get('text', [''])[0]
    response_url = parsed_body.get('response_url', [''])[0]
    
    logger.info(f"User {user_id} requested: {command_text}")

    # --- 5. THE DECOUPLING ---
    policy_engine_arn = os.environ.get('POLICY_ENGINE_ARN')
    
    if not policy_engine_arn:
        logger.error("CRITICAL: POLICY_ENGINE_ARN environment variable is missing!")
        return {"statusCode": 500, "body": "System Configuration Error"}

    try:
        logger.info(f"Asynchronously invoking Policy Engine: {policy_engine_arn}")
        # Fire and Forget!
        lambda_client.invoke(
            FunctionName=policy_engine_arn,
            InvocationType='Event', 
            Payload=json.dumps({
                "user_id": user_id,
                "command_text": command_text,
                "response_url": response_url # Passing the walkie-talkie to the Chef
            })
        )
    except Exception as e:
        logger.error(f"Failed to trigger Policy Engine: {e}")
        return {"statusCode": 500, "body": "Internal queuing error."}
    
    # We return IMMEDIATELY so Slack doesn't time out.
    return {
        "statusCode": 200,
        "body": "Got it! 🕵️ Evaluating your access request in the background..."
    }