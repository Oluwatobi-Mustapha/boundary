from src.core.engine import EvaluationResult
from src.models.request import AccessRequest
from src.core.engine import PolicyEngine
from src.adapters.aws_orgs import AWSOrganizationsAdapter

class AccessWorkflow:
    def __init__(self, engine: PolicyEngine, adapter: AWSOrganizationsAdapter):
        self.engine = engine
        self.adapter = adapter

    def handle_request(self, request: AccessRequest) -> EvaluationResult:
        """Orchestrates the fact-gathering and policy evaluation."""
        # Task: Resolve the Permission Set Name here
        request.permission_set_name = self.adapter.get_permission_set_name(
            instance_arn=request.instance_arn, 
            ps_arn=request.permission_set_arn
        )