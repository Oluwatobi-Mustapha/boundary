import yaml
from src.models.request import AccessRequest 
from src.models.aws_context import AWSAccountContext
from dataclasses import dataclass
from typing import Optional

@dataclass
class EvaluationResult:
    """
    The final decision object returned by the Engine.
    It carries all the info needed to either grant access or tell the user 'No'.
    """
    effect: str                    # 'ALLOW' or 'DENY'
    reason: str                    # Friendly message explaining the decision
    rule_id: Optional[str] = None  # Which specific rule in the YAML matched
    approval_required: bool = False # Does a human need to click 'Approve'?
    approval_channel: Optional[str] = None # Slack channel for notifications
    approver_group: Optional[str] = None   # Which team is allowed to approve

class PolicyEngine:
    def __init__(self, config_path: str):
        """
        Setup: Load the rules from the YAML file into a Python dictionary.
        """
        with open(config_path, 'r') as file:
            # safe_load is used to prevent malicious code execution from the YAML
            self.config = yaml.safe_load(file)

    def _get_subject_name(self, principal_id: str) -> Optional[str]:
        """
        The 'Bridge': Translates an AWS Principal ID (e.g. 906732...) 
        into a human-readable name from our YAML (e.g. 'developers').
        """
        groups = self.config.get('subjects', {}).get('groups', {})
        for name, data in groups.items():
            if data.get('id') == principal_id:
                return name
        return None

    def evaluate(self, access_request: AccessRequest) -> EvaluationResult:
        """
        The Brain: Loops through all rules to see if the request is valid.
        """
        # RULE 0: Safety First (Default Deny)
        # We start by assuming the request is rejected.
        result = EvaluationResult(effect="DENY", reason="Denied by default policy.")
        
        # STEP 1: Identify the User
        # Translate the ID from the request into a group name from our rules.
        subject_name = self._get_subject_name(access_request.principal_id)
        if not subject_name:
            # If the user isn't in our YAML at all, we stop immediately.
            return EvaluationResult(effect="DENY", reason="User not in authorized groups.")
        
        # STEP 2: Loop through every rule in the YAML
        rules = self.config.get("rules", [])
        for rule in rules:
            
            # CHECK A: Does this rule apply to this user's group?
            if subject_name not in rule.get("subjects", []):
                continue # If not, skip to the next rule
                
            # CHECK B: Is the user asking for the right Permission Set?
            # NOTE: There is a gap here. YAML uses names, Request uses ARNs.
            rule_perm = rule.get("permission_set")
            if rule_perm != "*" and access_request.permission_set_arn != rule_perm:
                continue

            # TODO CHECK C: Target Account / OU
            # This is the 'Hard Part' we are tackling next.
            # We need to verify if the requested account belongs to the OU/Tags in the rule.
            
            # If we reach this point, the rule matches the user and the permissions!
            # We would then set result.effect = "ALLOW" and return.
            pass

        return result