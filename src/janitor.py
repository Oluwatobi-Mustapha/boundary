import sys
import os
import argparse
import logging
import time

# --- PATH FIX ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# ----------------

from src.adapters.aws_orgs import AWSOrganizationsAdapter
from src.adapters.state_store import StateStore

# Configure logging to work in both CLI and Lambda
logger = logging.getLogger()
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
                instance_arn=item['instance_arn']
            )

            # B. Update DB Status
            state_store.update_status(req_id, "REVOKED")
            logger.info(f"✅ Successfully revoked {req_id}")
            revocation_count += 1

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