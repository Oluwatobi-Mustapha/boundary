from src.core.engine import EvaluationResult
from src.models.request import AccessRequest
from src.core.engine import PolicyEngine
from src.adapters.aws_orgs import AWSOrganizationsAdapter

class AccessWorkflow:
    def __init__(self, engine: PolicyEngine, adapter: AWSOrganizationsAdapter):
        self.engine = engine
        self.adapter = adapter