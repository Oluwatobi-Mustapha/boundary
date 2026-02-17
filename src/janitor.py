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

def main():
    parser = argparse.ArgumentParser(description="Boundary: The Janitor (Revocation Worker)")
    parser.add_argument("--dynamo-table", required=True, help="The DynamoDB table name to scan")
    parser.add_argument("--dry-run", action="store_true", help="Scan only, do not revoke")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()

    # Setup Logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger("boundary.janitor")

    logger.info("🧹 Janitor starting up...")

    # 1. Initialize Adapters
    try:
        adapter = AWSOrganizationsAdapter()
        state_store = StateStore(table_name=args.dynamo_table)
    except Exception as e:
        logger.error(f"Failed to initialize adapters: {e}")
        sys.exit(1)

    # 2. Find Expired Requests
    # This uses the GSI (ExpirationIndex) to find only what needs to be cleaned.
    logger.info("Querying for expired active requests...")
    expired_requests = state_store.get_expired_active_requests()
    
    if not expired_requests:
        logger.info("✨ No expired requests found. Clean system.")
        sys.exit(0)

    logger.info(f"Found {len(expired_requests)} requests to revoke.")

    # 3. Revocation Loop
    revocation_count = 0
    error_count = 0

    for item in expired_requests:
        req_id = item['request_id']
        principal = item['principal_id']
        account = item['account_id']
        
        logger.info(f"Processing Revocation: {req_id} (User: {principal}, Account: {account})")

        if args.dry_run:
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

    if error_count > 0:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()