import yaml
from src.models.request import AccessRequest
from dataclasses import dataclass
from typing import Optional

@dataclass
class EvaluationResult:
    effect: str
    reason: str
    rule_id: Optional[str] = None
    approval_required: bool = False
    approval_channel: Optional[str] = None
    approver_group: Optional[str] = None

class PolicyEngine:
    def __init__(self, config_path: str):
        """
        Initializes the engine by loading the YAML configuration.
        """
        with open(config_path, 'r') as file:
            # We store the entire YAML as a dictionary in self.config
            self.config = yaml.safe_load(file)

    def evaluate(self, access_request: AccessRequest) -> EvaluationResult:
        result = EvaluationResult(effect="DENY", reason="Denied by default policy.", rule_id=None)
        return result