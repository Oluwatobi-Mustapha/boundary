import boto3
from typing import List, Dict, Optional
from src.models.aws_context import AWSAccountContext

class AWSResourceNotFoundError(Exception):
    """
    Raised when the AWS Organizations hierarchy is broken or unreachable.
    In a security context, we prefer to crash than to make decisions on partial data.
    """
    pass

class AWSOrganizationsAdapter:
    """
    The 'Hands' of the system.
    This adapter translates raw AWS API responses into the clean models 
    required by our Policy Engine.
    """
    def __init__(self, orgs_client=None, sso_client=None): 
        # Dependency Injection allows us to pass 'Mock' clients during testing
        self.orgs = orgs_client or boto3.client("organizations")
        self.sso = sso_client or boto3.client("sso-admin")

    def get_ou_path(self, account_id: str) -> List[str]:
        """
        Recursively builds the OU path from the Account up to the Organization Root.
        
        Returns: A list of IDs, e.g., ['r-rootid', 'ou-parent', 'ou-immediate']
        This order allows the Engine to match rules at any level of the hierarchy.
        """
        ou_path_ids: List[str] = []
        current_id = account_id
        
        while True:
            # list_parents only returns the immediate level above. 
            # We must loop to reconstruct the full 'branch' of the tree.
            resp = self.orgs.list_parents(ChildId=current_id)
            parents = resp.get("Parents", [])
            
            if not parents:
                # Security Gate: If we haven't reached ROOT and find no parents,
                # the account is 'orphaned' or the API is failing. We must raise.
                raise AWSResourceNotFoundError(f"Hierarchy broken: No parents found for {current_id}")

            parent = parents[0]
            p_id = parent.get("Id")
            p_type = parent.get("Type")

            # We insert at 0 so the Root always ends up at the start of the list
            ou_path_ids.insert(0, p_id)

            # Exit condition: Once we hit the 'ROOT', the path is complete.
            if p_type == "ROOT":
                break
            
            current_id = p_id
            
        return ou_path_ids
    
    def get_account_tags(self, account_id: str) -> Dict[str, str]:
        """
        Fetches AWS tags and transforms them into a high-speed lookup dictionary.
        
        Input: [{'Key': 'Env', 'Value': 'Prod'}]
        Output: {'Env': 'Prod'}
        """
        try:
            # Note: ResourceId accepts the 12-digit Account ID for this call
            resp = self.orgs.list_tags_for_resource(ResourceId=account_id)
            tags = resp.get("Tags", [])
            return {tag["Key"]: tag["Value"] for tag in tags}
        except Exception:
            # If tags cannot be retrieved, we return an empty dict.
            # This triggers a 'Default Deny' for any rules relying on tag selectors.
            return {}

    def get_permission_set_name(self, instance_arn: str, ps_arn: str) -> str:
        """
        Placeholder for SSO Permission Set Name resolution.
        """
        # User requested to leave this for manual refinement
        resp = self.sso.describe_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=ps_arn
        )
        return resp.get("PermissionSet", {}).get("Name", "")

    def build_account_context(self, account_id: str) -> AWSAccountContext:
        """
        Orchestrator: Gathers OUs and Tags to create a full 'Fact' model.
        This is the single entry point the rest of the application uses.
        """
        ou_path_ids = self.get_ou_path(account_id)
        tags = self.get_account_tags(account_id)
        return AWSAccountContext(ou_path_ids=ou_path_ids, tags=tags)