import yaml
import hashlib
import datetime
import os
import re
from src.models.request import AccessRequest 
from src.models.aws_context import AWSAccountContext
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

# 1. Define the Engine Version (Semantic Versioning)
VERSION = "0.1.0"

@dataclass
class EvaluationResult:
    """
    The standardized 'Decision' object returned by the Engine.
    Now Audit-Grade with evidence and integrity metadata.
    """
    effect: str                    # Final verdict: 'ALLOW' or 'DENY'
    reason: str                    # Human-friendly explanation for the user
    
    # --- Integrity Metadata ---
    policy_hash: str = "" 
    engine_version: str = ""  # Which version of code made this decision?
    # capturing UTC time in ISO format automatically when created
    evaluated_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    
    # --- Evidence Context ---
    # Stores specific OUs or Tags that led to the match.
    # Using default_factory=dict is required for mutable types in dataclasses
    context_evidence: Dict[str, Any] = field(default_factory=dict)
    rules_processed: int = 0 # Traceability (How many rules did we check?)
    
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
        """
        Loads and parses the central security policy.
        Calculates a SHA256 hash of the file for audit integrity.
        """
        # 1. Read the raw text
        with open(config_path, 'r') as file:
            raw_content = file.read()
            
        # 2. Expand Environment Variables (The Sanitization Layer)
        # We swap ${VAR} for the real value before parsing YAML
        content_with_secrets = self._expand_env_vars(raw_content)

        # 3. Calculate the Hash (Fingerprint) of the REAL content (post-expansion)
        # This ensures the audit log reflects the actual IDs used, not the placeholders.
        self.policy_hash = hashlib.sha256(content_with_secrets.encode('utf-8')).hexdigest()
        
        # 4. Parse the YAML
        self.config = yaml.safe_load(content_with_secrets)

    def _expand_env_vars(self, raw_yaml: str) -> str:
        """
        Replaces ${VAR_NAME} with the value from os.environ.
        Raises an error if the variable is missing to prevent security gaps.
        """
        pattern = re.compile(r'\$\{([A-Z0-9_]+)\}')
        
        def replace(match):
            var_name = match.group(1)
            val = os.environ.get(var_name)
            if not val:
                # Fail Fast: Do not run with missing config
                raise ValueError(f"CRITICAL: Policy config references ${{ {var_name} }}, but environment variable is missing.")
            
            # Validate format based on variable type
            if "OU_ID" in var_name:
                if not re.match(r'^(r-[a-z0-9]{4,32}|ou-[a-z0-9]{4,32}-[a-z0-9]{8,32})$', val):
                    raise ValueError(f"Invalid OU/Root ID format for {var_name}: {val}. Expected 'ou-xxxx-xxxxxxxx' or 'r-xxxx'")
            elif var_name.endswith("_ID") and not val.strip():
                raise ValueError(f"Empty value for {var_name}")
            
            return val
            
        return pattern.sub(replace, raw_yaml)

    def _get_subject_name(self, principal_id: str) -> Optional[str]:
        """Maps AWS GUIDs (IDP) to readable names (developers, security_admins)."""
        groups = self.config.get('subjects', {}).get('groups', {})
        for name, data in groups.items():
            if data.get('id') == principal_id:
                return name
        return None
    
    def _match_target(self, rule_target: dict, context: AWSAccountContext) -> bool:
        """Determines if the target AWS account matches rule criteria (OU or Tags)."""
        selector = rule_target.get("selector")
        if not selector:
            return False

        if selector == "ou_id":
            rule_ou_ids = rule_target.get("ids", [])
            return any(ou_id in context.ou_path_ids for ou_id in rule_ou_ids)
        
        if selector == "tag":
            rule_tags_key = rule_target.get("key")
            rule_tags_allowed_values = rule_target.get("values", [])
            if not rule_tags_key or not rule_tags_allowed_values:
                return False
            
            actual_value = context.tags.get(rule_tags_key)
            return actual_value in rule_tags_allowed_values

        return False

    def evaluate(self, access_request: AccessRequest, context: AWSAccountContext) -> EvaluationResult:
        """
        Main Decision Loop. Checks rules in order until a match or explicit deny is found.
        """
        # PRINCIPLE: Default Deny (Fail-Safe)
        # We initialize with the current policy hash so even Denials are audited
        result = EvaluationResult(
            effect="DENY",
            reason="Denied by default policy.",
            policy_hash=self.policy_hash,
            engine_version=VERSION
        )
        
        subject_name = self._get_subject_name(access_request.principal_id)
        if not subject_name:
            return EvaluationResult(
                effect="DENY", 
                reason="User not in authorized groups.",
                policy_hash=self.policy_hash
            )
        
        rules = self.config.get("rules", [])
        rules_checked_count = 0 # Counter

        for rule in rules:
            rules_checked_count += 1
            # Match Subject
            if subject_name not in rule.get("subjects", []):
                continue
                
            # Match Permission
            rule_perm = rule.get("permission_set")
            if rule_perm != "*" and access_request.permission_set_name != rule_perm:
                continue

            # Match Target
            if not self._match_target(rule.get("target", {}), context): 
                continue

            # --- MATCH CONFIRMED ---

            # Capture Evidence (Req 2)
            # We record exactly what matched so the auditor knows "Why".
            evidence = {
                "matched_selector": rule.get("target", {}).get("selector"),
                "account_ou_path": context.ou_path_ids,
                "account_tags": context.tags,
                "principal_group": subject_name
            }

            rule_effect = rule.get("effect", "").lower()
            if rule_effect == "deny":
                return EvaluationResult(
                    effect="DENY",
                    rule_id=rule.get("id"),
                    reason=rule.get("description", "Denied by matching rule."),
                    policy_hash=self.policy_hash,
                    context_evidence=evidence,
                    engine_version=VERSION,
                    rules_processed=rules_checked_count
                )

            constraints_cfg = rule.get("constraints", {})
            global_max = self.config.get("settings", {}).get("max_request_duration_hours", 12)
            rule_max = constraints_cfg.get("max_duration_hours", global_max)
            
            if access_request.expires_at <= access_request.requested_at:
                return EvaluationResult(
                    effect="DENY",
                    reason="Invalid request duration.",
                    rule_id=rule.get("id"),
                    policy_hash=self.policy_hash,
                    context_evidence=evidence
                )

            requested_hours = (access_request.expires_at - access_request.requested_at) / 3600
            was_capped = requested_hours > rule_max
            effective_hours = min(requested_hours, rule_max)
            effective_expires = access_request.requested_at + (effective_hours * 3600)

            if constraints_cfg.get("ticket_required", False) and not access_request.ticket_id:
                return EvaluationResult(
                    effect="DENY", 
                    reason="Ticket required for this request.", 
                    rule_id=rule.get("id"),
                    policy_hash=self.policy_hash,
                    context_evidence=evidence
                )

            approval_cfg = rule.get("approval", {})
            
           # --- RETURN ALLOW ---
            approval = rule.get("approval", {})
            desc = rule.get("description", "Matched policy.")
            reason = f"{desc} Duration capped to {rule_max}h." if was_capped else desc


            return EvaluationResult(
                effect="ALLOW",
                reason=reason,
                rule_id=rule.get("id"),
                approval_required=approval.get("required", False),
                approval_channel=approval.get("channel"),
                approver_group=approval.get("approver_groups", [None])[0],
                was_capped=was_capped,
                effective_duration_hours=effective_hours,
                effective_expires_at=effective_expires,
                policy_hash=self.policy_hash,
                engine_version=VERSION, 
                context_evidence=evidence,
                rules_processed=rules_checked_count
            )
    
        return result