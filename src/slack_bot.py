import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Temporary placeholder for the Slack Bot endpoint.
    Returns a 200 OK so API Gateway doesn't crash.
    """
    logger.info("Slack Bot received an event!")
    logger.info(json.dumps(event))
    
    return {
        "statusCode": 200,
        "body": json.dumps({"message": "Boundary Slack Bot is alive."})
    }