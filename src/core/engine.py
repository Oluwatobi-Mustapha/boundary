import yaml
import hashlib
from src.models.request import AccessRequest 
from src.models.aws_context import AWSAccountContext
from dataclasses import dataclass
from typing import Optional


@dataclass
class EvaluationResult:
    """
    The standardized 'Decision' object returned by the Engine.
    
    This acts as a contract between the Policy Logic and the UI (Slack/Web).
    It contains everything needed to grant access or inform the user of a denial.
    """
    effect: str                    # Final verdict: 'ALLOW' or 'DENY'
    reason: str                    # Human-friendly explanation for the user
    rule_id: Optional[str] = None  # ID of the specific YAML rule that triggered this
    approval_required: bool = False # If True, the workflow must pause for a human
    approval_channel: Optional[str] = None # Where to send the approval notification
    approver_group: Optional[str] = None   # Which IDP group is authorized to approve
    
    # Metadata for transparency (Audit Trail)
    was_capped: bool = False       # True if the user asked for more time than allowed
    effective_duration_hours: Optional[float] = None # The actual hours granted
    effective_expires_at: Optional[float] = None    # The final Unix timestamp for revocation

class PolicyEngine:
    """
    The 'Pure' Decision Engine. 
    It evaluates AccessRequests against YAML rules without talking to AWS directly.
    """
    def __init__(self, config_path: str):
        """Loads and parses the central security policy."""
        with open(config_path, 'r') as file:
            # safe_load prevents YAML-based injection attacks
            self.config = yaml.safe_load(file)

    def _get_subject_name(self, principal_id: str) -> Optional[str]:
        """Maps AWS GUIDs (IDP) to readable names (developers, security_admins)."""
        groups = self.config.get('subjects', {}).get('groups', {})
        for name, data in groups.items():
            if data.get('id') == principal_id:
                return name
        return None
    
    def _match_target(self, rule_target: dict, context: AWSAccountContext) -> bool:
        """
        Determines if an AWS account is 'in scope' for a specific rule.
        Supports both hierarchical (OU) and attribute-based (Tag) matching.
        """
        selector = rule_target.get("selector")
        if not selector:
            return False

        # Match by Organizational Unit (OU) ID
        if selector == "ou_id":
            rule_ou_ids = rule_target.get("ids", [])
            # any() returns True as soon as one match is found (Short-circuiting)
            return any(ou_id in context.ou_path_ids for ou_id in rule_ou_ids)
        
        # Match by AWS Resource Tags (Key-Value)
        if selector == "tag":
            rule_tags_key = rule_target.get("key")
            rule_tags_allowed_values = rule_target.get("values", [])
            if not rule_tags_key or not rule_tags_allowed_values:
                return False
            
            # Dictionary lookup is O(1) speed
            actual_value = context.tags.get(rule_tags_key)
            return actual_value in rule_tags_allowed_values

        return False

    def evaluate(self, access_request: AccessRequest, context: AWSAccountContext) -> EvaluationResult:
        """
        Main Decision Loop. Checks every rule until a match is found.
        """
        # SECURITY PRINCIPLE: Default Deny (Fail-Safe)
        result = EvaluationResult(effect="DENY", reason="Denied by default policy.")
        
        # 1. Subject Resolution: Who is asking?
        subject_name = self._get_subject_name(access_request.principal_id)
        if not subject_name:
            return EvaluationResult(effect="DENY", reason="User not in authorized groups.")
        
        # 2. Rule Evaluation
        rules = self.config.get("rules", [])
        for rule in rules:
            
            # Gate 1: Check if the user's group is listed in the rule
            if subject_name not in rule.get("subjects", []):
                continue
                
            # Gate 2: Permission Set verification
            rule_perm = rule.get("permission_set")
            if rule_perm != "*" and access_request.permission_set_name != rule_perm:
                continue

            # Gate 3: Target Validation (Does this account belong to the OU/Tag?)
            if not self._match_target(rule.get("target", {}), context): 
                continue

            # --- MATCH FOUND! ---
            
            # Explicit Deny wins over any allows (Standard IAM logic)
            rule_effect = rule.get("effect", "").lower()
            if rule_effect == "deny":
                return EvaluationResult(
                    effect="DENY",
                    rule_id=rule.get("id"),
                    reason=rule.get("description", "Denied by matching rule."),
                )

            # 3. Constraint & Duration Logic
            constraints_cfg = rule.get("constraints", {})
            global_max = self.config.get("settings", {}).get("max_request_duration_hours", 12)
            rule_max = constraints_cfg.get("max_duration_hours", global_max)
            
            # Convert timestamps to hours for comparison
            # Validate requested duration timestamps (fail closed)
            if access_request.expires_at <= access_request.requested_at:
                return EvaluationResult(
                    effect="DENY",
                    reason="Invalid request duration (expires_at must be after requested_at).",
                    rule_id=rule.get("id"),
                )
            requested_hours = (access_request.expires_at - access_request.requested_at) / 3600
            
            # AUTOMATIC CAPPING: Safety mechanism to prevent excessive access time
            was_capped = requested_hours > rule_max
            effective_hours = min(requested_hours, rule_max)
            effective_expires = access_request.requested_at + (effective_hours * 3600)

            # 4. Mandatory Documentation
            if constraints_cfg.get("ticket_required", False) and not access_request.ticket_id:
                return EvaluationResult(
                    effect="DENY", 
                    reason="Ticket required for this request.", 
                    rule_id=rule.get("id")
                )

            # 5. Approval Workflow Setup
            approval_cfg = rule.get("approval", {})
            req_approval = approval_cfg.get("required", False)
            
            desc = rule.get("description", "Matched policy rule.")
            reason = f"{desc} Duration capped to {rule_max}h." if was_capped else desc

            return EvaluationResult(
                effect="ALLOW",
                reason=reason,
                rule_id=rule.get("id"),
                approval_required=req_approval,
                approval_channel=approval_cfg.get("channel"),
                approver_group=approval_cfg.get("approver_groups", [None])[0],
                was_capped=was_capped,
                effective_duration_hours=effective_hours,
                effective_expires_at=effective_expires
            )
    
        return result