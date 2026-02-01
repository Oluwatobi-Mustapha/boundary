import boto3
from typing import List, Dict, Optional
from src.models.aws_context import AWSAccountContext


class AWSOrganizationsAdapter:
    def __init__(self, orgs_client=None): 
        self.orgs = orgs_client or boto3.client("organizations")
    def get_ou_path(self, account_id: str) -> List[str]:
        



