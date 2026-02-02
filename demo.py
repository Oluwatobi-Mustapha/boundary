from src.models.request import AccessRequest
from src.models.aws_context import AWSAccountContext
from src.core.engine import PolicyEngine
from src.core.workflow import AccessWorkflow

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

