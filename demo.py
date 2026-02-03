import sys
import time
from src.models.request import AccessRequest
from src.models.aws_context import AWSAccountContext
from src.core.engine import PolicyEngine
from src.core.workflow import AccessWorkflow
from src.ui.printer import print_verdict
from src.ui.json_logger import log_audit_event

class MockAdapter:
    """
    Stunt Double: Pretends to be AWS.
    Returns hardcoded facts that match our 'Staging ReadOnly' rule.
    """
    def get_permission_set_name(self, instance_arn, ps_arn) -> str:
        return "ReadOnlyAccess"

    def build_account_context(self, account_id) -> AWSAccountContext:
        # We pretend this account is in the Staging OU
        return AWSAccountContext(
            # SHOW FULL PATH: Root -> Infrastructure OU -> Staging OU
            ou_path_ids=["r-root-123", "ou-infra-456", "ou-rge5-12345"],
            tags={"Environment": "Staging"}
        )

if __name__ == "__main__":
    # --- SETUP ---
    print("Initializing Engine...")
    engine = PolicyEngine("config/access_rules.yaml")
    adapter = MockAdapter()
    workflow = AccessWorkflow(engine, adapter)

    # --- FAKE REQUEST ---
    req = AccessRequest(
        request_id="test-audit-1",
        principal_id="90673208-3b...", 
        principal_type="USER",
        permission_set_arn="arn:aws:sso:::permissionSet/ssoins-123/ps-123",
        permission_set_name="", 
        account_id="123456789012",
        instance_arn="arn:aws:sso:::instance/ssoins-123",
        rule_id="unknown",
        requested_at=time.time(),
        expires_at=time.time() + 3600, 
    )

    # --- EXECUTION ---
    print(f"Testing Request: {req.principal_id} -> Account {req.account_id}")
    result = workflow.handle_request(req)

    # --- REPORTING (HUMAN) ---
    print_verdict(req, result)
    
    # --- REPORTING (MACHINE AUDIT) ---
    # 2. Correct function call syntax (no colons)
    logfile = log_audit_event(req, result)
    print(f"\n[Audit Artifact Created]: {logfile}")

    # --- EXIT CODES (Req 4: Fail-Closed) ---
    # 3. Use res.effect to decide exit code
    if result.effect == "ALLOW":
        sys.exit(0)
    elif result.effect == "DENY":
        sys.exit(2)
    else:
        sys.exit(3) # Error