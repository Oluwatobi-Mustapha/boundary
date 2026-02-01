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
    # NEW: duration capping metadata
    was_capped: bool = False
    effective_duration_hours: Optional[float] = None
    effective_expires_at: Optional[float] = None

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
    
    def _match_target(self, rule_target: dict, context: AWSAccountContext) -> bool:
        selector = rule_target.get("selector")
        if not selector:
            return False
        if selector == "ou_id":
            rule_ou_ids = rule_target.get("ids", [])
            return any(ou_id in context.ou_path_ids for ou_id in rule_ou_ids)
        
        if selector == "tag":
            rule_tags_key = rule_target.get("key")
            rule_tags_allowed_values = rule_target.get("values", [])
            if not rule_tags_key:
                return False
            if not rule_tags_allowed_values:
                return False
            actual_value = context.tags.get(rule_tags_key)
            return actual_value in rule_tags_allowed_values
        return False # This ensures unknown selectors never match

    def evaluate(self, access_request: AccessRequest, context: AWSAccountContext) -> EvaluationResult:
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

            # CHECK C: Target Account / OU

            if not self._match_target(rule.get("target", {}), context): 
                continue
            rule_effect = rule.get("effect", "").lower()
            if rule_effect == "deny":
                return EvaluationResult(
                    effect = "DENY",
                    rule_id = rule.get("id"),
                    reason = rule.get("description", "Denied by matching rule."),
                )
            approval_cfg = rule.get("approval", {})
            req_approval = approval_cfg.get("required", False)
            approval_channel = approval_cfg.get("channel")
            approver_groups = approval_cfg.get("approver_groups", [])
            approver_group = approver_groups[0] if approver_groups else None
            constraints_cfg = rule.get("constraints", {})
            global_max_hours = self.config.get("settings", {}).get("max_request_duration_hours", 12)
            max_hours = constraints_cfg.get("max_duration_hours", global_max_hours)
            requested_hours = (access_request.expires_at - access_request.requested_at) / 3600
            effective_hours = min(requested_hours, max_hours)
            was_capped = requested_hours > max_hours
            effective_expires_at = access_request.requested_at + (effective_hours * 3600)
            ticket_required = constraints_cfg.get("ticket_required", False)
            if ticket_required and not access_request.ticket_id:
                return EvaluationResult(effect="DENY", reason="Ticket required for this request.", rule_id=rule.get("id"))
                

            # Build a helpful reason (and mention capping if it happened)
            desc = rule.get("description", "Matched policy rule.")
            if was_capped:
                
                reason = f"{desc} Requested duration capped to {max_hours} hour(s) per policy."
            else:
                reason = desc
               
            # Approval vs direct allow
            if req_approval:
                return EvaluationResult(
                    effect="ALLOW",
                    reason=reason,
                    rule_id=rule.get("id"),
                    approval_required=True,
                    approval_channel=approval_channel,
                    approver_group=approver_group,
                    was_capped=was_capped,
                    effective_duration_hours=effective_hours,
                    effective_expires_at=effective_expires_at,
                )
            return EvaluationResult(
                effect="ALLOW",
                reason=reason,
                rule_id=rule.get("id"),
                was_capped=was_capped,
                effective_duration_hours=effective_hours,
                effective_expires_at=effective_expires_at,
            )
        