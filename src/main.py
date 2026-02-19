import sys
import os
import time
import argparse
import logging

# --- PATH FIX ---
# Ensures we can import from 'src' regardless of where the script is run
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# ----------------

from src.core.engine import PolicyEngine
from src.core.workflow import AccessWorkflow
from src.models.request import AccessRequest
from src.adapters.aws_orgs import AWSOrganizationsAdapter, AWSResourceNotFoundError
from src.adapters.state_store import StateStore
from src.ui.printer import print_verdict
from src.ui.json_logger import log_audit_event
from src.validators import validate_duration, validate_account_id, validate_arn

def main():
    parser = argparse.ArgumentParser(description="Boundary: Ephemeral Access System (Production)")
    parser.add_argument("--principal", required=True, help="The AWS Identity Center Group ID")
    parser.add_argument("--account", required=True, help="The Target AWS Account ID")
    parser.add_argument("--permission-set-arn", required=True, help="The ARN of the Permission Set requested")
    parser.add_argument("--instance-arn", required=True, help="The ARN of the SSO Instance")
    parser.add_argument("--duration", type=float, default=1.0, help="Requested duration in hours")
    parser.add_argument("--ticket", help="Jira/ServiceNow Ticket ID (if required)")
    parser.add_argument("--dynamo-table", required=True, help="The DynamoDB table name for state persistence")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()

    # Validate inputs immediately (Fail Fast)
    try:
        args.duration = validate_duration(args.duration)
        args.account = validate_account_id(args.account)
        args.permission_set_arn = validate_arn(args.permission_set_arn)
        args.instance_arn = validate_arn(args.instance_arn)
    except ValueError as e:
        parser.error(str(e))

    # Setup Logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger("boundary")

    try:
        # 1. INITIALIZE STACK
        logger.info("Initializing Policy Engine...")
        engine = PolicyEngine("config/access_rules.yaml")

        logger.info("Initializing AWS Adapter (Live)...")
        adapter = AWSOrganizationsAdapter()
        
        logger.info(f"Initializing State Store (Table: {args.dynamo_table})...")
        state_store = StateStore(table_name=args.dynamo_table)

        workflow = AccessWorkflow(engine, adapter)

        # 2. BUILD REQUEST
        req = AccessRequest(
            request_id=AccessRequest.create_id(),
            principal_id=args.principal,
            principal_type="GROUP", 
            permission_set_arn=args.permission_set_arn,
            permission_set_name="", 
            account_id=args.account,
            instance_arn=args.instance_arn,
            rule_id="unknown",
            ticket_id=args.ticket,
            requested_at=time.time(),
            expires_at=time.time() + (args.duration * 3600)
        )

        logger.info(f"Processing Request: {req.request_id}")

        # 3. EXECUTE WORKFLOW
        result = workflow.handle_request(req)

        # 4. OUTPUT RESULTS
        print_verdict(req, result, verbose=args.debug)
        logfile = log_audit_event(req, result)
        logger.info(f"Audit artifact written to: {logfile}")

        # 5. ACTION & PERSISTENCE
        if result.effect == "ALLOW":
            try:
                # --- CRITICAL FIX (H-1): Save state BEFORE provisioning ---
                # This prevents zombie access grants if DynamoDB write fails
                req.status = "PENDING"
                req.rule_id = result.rule_id or "unknown"
                
                logger.info("Saving access state to DynamoDB (PENDING)...")
                state_store.save_request(req)
                logger.info("✅ State saved. Proceeding to provision...")

                # --- A. PROVISION ACCESS ---
                logger.info("Provisioning access in AWS Identity Center...")
                adapter.assign_user_to_account(
                    principal_id=req.principal_id,
                    account_id=req.account_id,
                    permission_set_arn=req.permission_set_arn,
                    instance_arn=req.instance_arn
                )
                logger.info("✅ Access successfully provisioned in AWS.")

                # --- B. UPDATE STATUS TO ACTIVE ---
                logger.info("Updating status to ACTIVE...")
                state_store.update_status(req.request_id, "ACTIVE")
                logger.info("✅ Access grant complete.")
                
                sys.exit(0)

            except Exception as e:
                logger.error(f"❌ CRITICAL: Failed to provision or save state: {e}")
                # We fail closed here. If provisioning fails, we exit with error.
                sys.exit(3)
        elif result.effect == "DENY":
            sys.exit(2) 
        else:
            sys.exit(3)

    except AWSResourceNotFoundError as e:
        logger.error(f"AWS Infrastructure Error: {e}")
        sys.exit(3)
    except Exception:
        logger.exception("Unexpected System Failure")
        sys.exit(1)

if __name__ == "__main__":
    main()