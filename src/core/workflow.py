from src.core.engine import EvaluationResult
from src.models.request import AccessRequest
from src.core.engine import PolicyEngine
from src.adapters.aws_orgs import AWSOrganizationsAdapter, AWSResourceNotFoundError

class AccessWorkflow:
    def __init__(self, engine: PolicyEngine, adapter: AWSOrganizationsAdapter):
        self.engine = engine
        self.adapter = adapter

    def handle_request(self, request: AccessRequest) -> EvaluationResult:
        """Orchestrates the fact-gathering and policy evaluation."""
        try:
            # 1. Resolve Name
            request.permission_set_name = self.adapter.get_permission_set_name(
                instance_arn=request.instance_arn, 
                ps_arn=request.permission_set_arn
            )
            
            # 2. Gather Facts
            context = self.adapter.build_account_context(request.account_id)
            
            # 3. Get Verdict
            return self.engine.evaluate(request, context)

        except AWSResourceNotFoundError as e:
            # The Fail Closed Safety Net
            return EvaluationResult(
                effect="DENY",
                reason=f"Infrastructure Error: {str(e)}"
            )

   