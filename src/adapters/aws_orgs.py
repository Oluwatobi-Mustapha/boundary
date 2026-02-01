import boto3
from dataclasses import dataclass
from typing import List, Dict, Optional
from src.models.aws_context import AWSAccountContext

@dataclass
class AWSOrganizationsAdapter:
    
