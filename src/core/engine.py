import yaml
from src.models.request import AccessRequest
from dataclasses import dataclass
from typing import Optional

@dataclass
class EvaluationResult:
    effect: str
    reason: str

class PolicyEngine:
    def __init__(self, config_path: str):
        """
        Initializes the engine by loading the YAML configuration.
        """
        with open(config_path, 'r') as file:
            # We store the entire YAML as a dictionary in self.config
            self.config = yaml.safe_load(file)

    def evaluate(self, access_request):
        pass
