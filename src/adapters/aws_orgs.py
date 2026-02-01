import boto3
from typing import List, Dict
from src.models.aws_context import AWSAccountContext
from botocore.exceptions import ClientError

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
        allowed_types = {"ROOT", "ORGANIZATIONAL_UNIT"}
        
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

            if not p_id or not p_type:
                raise AWSResourceNotFoundError(f"Hierarchy broken: parent missing Id/Type for {current_id}")
        
            if p_type not in allowed_types:
                raise AWSResourceNotFoundError(f"Hierarchy broken: unexpected parent type {p_type} for {current_id}")

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
        all_tags = []
        next_token = None
        try:
            while True:
                # Note: ResourceId accepts the 12-digit Account ID for this call
                if next_token: 
                    resp = self.orgs.list_tags_for_resource(ResourceId=account_id, NextToken=next_token)
                else:
                    resp = self.orgs.list_tags_for_resource(ResourceId=account_id)
                all_tags.extend(resp.get("Tags", []))
                next_token = resp.get("NextToken")
                if not next_token: 
                    break
            return {tag["Key"]: tag["Value"] for tag in all_tags}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == 'AccessDeniedException':
                return {}     
            raise 

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