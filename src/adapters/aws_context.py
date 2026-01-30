from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class AWSAccountContext:
    ou_path_ids: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
