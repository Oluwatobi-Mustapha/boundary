from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class AWSAccountContext:

    """
    Holds the 'Facts' about an AWS Account retrieved from the Organizations API.
    By keeping this data here, the PolicyEngine doesn't have to talk to AWS.
    """
    
    # A list of OU IDs from the root down to the account's parent.
    # Example: ["r-1234", "ou-abcd-1111"]
    # This allows rules to match on any level of the hierarchy.
    ou_path_ids: List[str] = field(default_factory=list)

    # A flattened dictionary of tags for the account.
    # AWS returns: [{"Key": "Env", "Value": "Prod"}]
    # We store: {"Env": "Prod"}
    # This makes lookup O(1) speed: tags.get("Env")
    tags: Dict[str, str] = field(default_factory=dict)

    # We can also store the Account Name or Email if we want to show 
    # them in Slack messages later.
    account_name: str = ""
