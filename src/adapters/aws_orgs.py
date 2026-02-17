import boto3
import logging
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
    Handles both Reading (Context) and Writing (Provisioning).
    """
    def __init__(self, orgs_client=None, sso_client=None): 
        # Dependency Injection allows us to pass 'Mock' clients during testing
        self.orgs = orgs_client or boto3.client("organizations")
        self.sso = sso_client or boto3.client("sso-admin")
        self._ps_cache = {}
        # Initialize Logger
        self.logger = logging.getLogger("boundary.adapter")

    # --- READ METHODS ---

    def get_ou_path(self, account_id: str) -> List[str]:
        """
        Recursively builds the OU path from the Account up to the Organization Root.
        """
        ou_path_ids: List[str] = []
        current_id = account_id
        allowed_types = {"ROOT", "ORGANIZATIONAL_UNIT"}
        hit_root = False
        
        while True:
            resp = self.orgs.list_parents(ChildId=current_id)
            parents = resp.get("Parents", [])
            
            if not parents:
                raise AWSResourceNotFoundError(f"Hierarchy broken: No parents found for {current_id}")

            parent = parents[0]
            p_id = parent.get("Id")
            p_type = parent.get("Type")

            if not p_id or not p_type:
                raise AWSResourceNotFoundError(f"Hierarchy broken: parent missing Id/Type for {current_id}")
        
            if p_type not in allowed_types:
                raise AWSResourceNotFoundError(f"Hierarchy broken: unexpected parent type {p_type} for {current_id}")

            ou_path_ids.insert(0, p_id)

            if p_type == "ROOT":
                hit_root = True
                break      
            current_id = p_id

        if not hit_root:
            raise AWSResourceNotFoundError(f"Hierarchy broken: did not reach ROOT for account {account_id}") 
               
        return ou_path_ids
    
    def get_account_tags(self, account_id: str) -> Dict[str, str]:
        """
        Fetches AWS tags and transforms them into a high-speed lookup dictionary.
        """
        all_tags = []
        next_token = None
        try:
            while True:
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
        Resolves an SSO Permission Set ARN to its human-readable Name.
        Cached to avoid repeated DescribePermissionSet calls.
        """
        # Preserving your specific cache key logic
        cache_key = f"{instance_arn}:{ps_arn}"

        if cache_key in self._ps_cache:
             return self._ps_cache[cache_key]
         
        resp = self.sso.describe_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=ps_arn
        )
        name = resp.get("PermissionSet", {}).get("Name", "")

        self._ps_cache[cache_key] = name
        return name
           
    def build_account_context(self, account_id: str) -> AWSAccountContext:
        """
        Orchestrator: Gathers OUs and Tags to create a full 'Fact' model.
        """
        ou_path_ids = self.get_ou_path(account_id)
        tags = self.get_account_tags(account_id)
        return AWSAccountContext(ou_path_ids=ou_path_ids, tags=tags)

    # --- WRITE METHODS (NEW) ---

    def assign_user_to_account(self, principal_id: str, account_id: str, permission_set_arn: str, instance_arn: str):
        """
        PROVISIONING: Calls AWS to actually grant the access.
        """
        try:
            self.sso.create_account_assignment(
                InstanceArn=instance_arn,
                TargetId=account_id,
                TargetType='AWS_ACCOUNT',
                PermissionSetArn=permission_set_arn,
                PrincipalType='GROUP', 
                PrincipalId=principal_id
            )
            self.logger.info(f"AWS API: Granted access for {principal_id} on {account_id}")
        except ClientError as e:
            # If it already exists, that's fine (idempotency). Otherwise, raise.
            if e.response['Error']['Code'] == 'ConflictException':
                self.logger.warning("Assignment already exists. Continuing...")
                return
            raise Exception(f"Failed to provision access in AWS: {e}")

    def remove_user_from_account(self, principal_id: str, account_id: str, permission_set_arn: str, instance_arn: str):
        """
        REVOCATION: Calls AWS to remove the access.
        """
        try:
            self.sso.delete_account_assignment(
                InstanceArn=instance_arn,
                TargetId=account_id,
                TargetType='AWS_ACCOUNT',
                PermissionSetArn=permission_set_arn,
                PrincipalType='GROUP',
                PrincipalId=principal_id
            )
            self.logger.info(f"AWS API: Revoked access for {principal_id} on {account_id}")
        except ClientError as e:
            # If it's already gone, we don't crash.
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                self.logger.warning("Assignment already removed or not found. Continuing...")
                return
            raise Exception(f"Failed to revoke access in AWS: {e}")