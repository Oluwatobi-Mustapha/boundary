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
        # We pretend AWS said this ARN = "ReadOnlyAccess"
        return "ReadOnlyAccess"

    def build_account_context(self, account_id) -> AWSAccountContext:
        # We pretend this account is in the Staging OU
        return AWSAccountContext(
            ou_path_ids=["ou-rge5-12345"],
            tags={"Environment": "Staging"}
        )

if __name__ == "__main__":
    # 1. Setup
    print("Initializing Engine...")
    engine = PolicyEngine("config/access_rules.yaml")
    adapter = MockAdapter()
    workflow = AccessWorkflow(engine, adapter)

    # 2. Create a Fake Request
    # We use the GROUP ID for 'developers' from YAML
    req = AccessRequest(
        request_id="test-123",
        principal_id="90673208-3b...", # Matches 'developers' in YAML
        principal_type="USER",
        permission_set_arn="arn:aws:sso:::permissionSet/ssoins-123/ps-123", # Fake ARN
        permission_set_name="", # Will be filled by workflow
        account_id="123456789012",
        instance_arn="arn:aws:sso:::instance/ssoins-123",
        rule_id="unknown",
        requested_at=time.time(),
        expires_at=time.time() + 3600, # Requesting 1 hour of access
    )

    # 3. Run!
    print(f"Testing Request: {req.principal_id} -> Account {req.account_id}")
    result = workflow.handle_request(req)

    # 4. Report (The Pretty Way)
    print_verdict(req, result)

