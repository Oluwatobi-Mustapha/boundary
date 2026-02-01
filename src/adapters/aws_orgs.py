import boto3
from typing import List, Dict, Optional
from src.models.aws_context import AWSAccountContext


class AWSOrganizationsAdapter:
    def __init__(self, orgs_client=None): 
        self.orgs = orgs_client or boto3.client("organizations")

    def get_ou_path(self, account_id: str) -> List[str]:
        ou_path_ids: List[str] = []
        current_id = account_id
        while True:
            resp = self.orgs.list_parents(ChildId=current_id)
            parents = resp.get("Parents", [])
            if not parents:
                break
            parent = parents[0]
            parent_id = parent.get("Id")
            parent_type = parent.get("Type")
            if not parent_id or not parent_type:
                break
            ou_path_ids.insert(0, parent_id)
            if parent_type == "ROOT":
                break
            current_id = parent_id

           





