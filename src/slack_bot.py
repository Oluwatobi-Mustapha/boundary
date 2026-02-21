import json
import os
import base64
import urllib.parse
import logging
import boto3
import hmac
import hashlib
import time
import uuid

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

# --- 1. THE WARM START CACHE ---
# Initialize the boto3 clients OUTSIDE the handler so they stay warm between invocations
ssm = boto3.client('ssm')
sqs = boto3.client('sqs')

CACHED_SLACK_SECRET = None

def get_slack_secret():
    global CACHED_SLACK_SECRET
    if CACHED_SLACK_SECRET:
        return CACHED_SLACK_SECRET
    
    logger.info("Cold Start: Fetching Slack secret from SSM Parameter Store...")
    try:
        response = ssm.get_parameter(
            Name='/boundary/slack/signing_secret',
            WithDecryption=True
        )
        CACHED_SLACK_SECRET = response['Parameter']['Value']
        return CACHED_SLACK_SECRET
    except Exception as e:
        logger.error(f"Failed to fetch secret: {e}")
        raise

def verify_slack_signature(headers: dict, body: str, secret: str) -> bool:
    slack_signature = headers.get('x-slack-signature', '')
    slack_request_timestamp = headers.get('x-slack-request-timestamp', '0')

    # Validate timestamp is numeric before conversion
    try:
        timestamp_int = int(slack_request_timestamp)
    except (ValueError, TypeError):
        logger.error("Invalid timestamp format in Slack signature")
        return False

    if abs(time.time() - timestamp_int) > 60 * 5:
        logger.error("Signature verification failed: Timestamp is older than 5 minutes. Possible replay attack!")
        return False

    sig_basestring = f"v0:{slack_request_timestamp}:{body}"
    my_signature = 'v0=' + hmac.new(
        secret.encode('utf-8'),
        sig_basestring.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(my_signature, slack_signature)

def lambda_handler(event, context):
    try:
        slack_secret = get_slack_secret()
    except Exception:
        return {"statusCode": 500, "body": "Configuration Error"}

    # --- 2. DECODE THE PAYLOAD FIRST ---
    raw_body = event.get('body', '')
    
    if event.get('isBase64Encoded', False):
        decoded_body = base64.b64decode(raw_body).decode('utf-8')
    else:
        decoded_body = raw_body

    # --- 3. THE SLACK MATH ---
    headers = {k.lower(): v for k, v in event.get('headers', {}).items()}

    if not verify_slack_signature(headers, decoded_body, slack_secret):
        logger.error("Invalid Slack Signature! Dropping request.")
        return {
            "statusCode": 401, 
            "body": "Request verification failed. Please contact your administrator if this persists."
        }
        
    logger.info("Slack Signature Verified!")
    
    # --- 4. PARSE THE 1990s STRING ---
    parsed_body = urllib.parse.parse_qs(decoded_body)
    
    user_id = parsed_body.get('user_id', [''])[0]
    command_text = parsed_body.get('text', [''])[0]
    response_url = parsed_body.get('response_url', [''])[0]
    
    # --- 5. INPUT VALIDATION ---
    if not user_id or not command_text or not response_url:
        logger.error("Missing required fields in Slack payload")
        return {
            "statusCode": 400,
            "body": "Invalid request format. Please check your command and try again."
        }
    
    # --- 6. THE METAL TICKET RAIL (SQS) ---
    queue_url = os.environ.get('WORKFLOW_QUEUE_URL')
    
    if not queue_url:
        logger.error("CRITICAL: WORKFLOW_QUEUE_URL environment variable is missing!")
        return {
            "statusCode": 500, 
            "body": "System configuration error. Please contact your administrator."
        }

    # Generate unique request ID for tracing
    request_id = str(uuid.uuid4())
    
    order_ticket = {
        "request_id": request_id,
        "user_id": user_id,
        "command_text": command_text,
        "response_url": response_url
    }

    try:
        logger.info(f"Sending access request to workflow queue (request_id: {request_id})")
        sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(order_ticket),
            MessageAttributes={
                'user_id': {'StringValue': user_id, 'DataType': 'String'},
                'request_type': {'StringValue': 'access_request', 'DataType': 'String'},
                'request_id': {'StringValue': request_id, 'DataType': 'String'}
            }
        )
    except Exception as e:
        logger.error(f"Failed to write to SQS: {e}")
        logger.debug(f"Failed message: {json.dumps(order_ticket)}")
        return {
            "statusCode": 500,
            "body": "System temporarily unavailable. Please try again in a moment."
        }
        
    # --- 7. THE 3-SECOND RULE ---
    # We successfully put the ticket on the rail. Instantly return 200 OK!
    return {
        "statusCode": 200,
        "body": "Access request received. Your request is being processed and you will be notified shortly."
    }
