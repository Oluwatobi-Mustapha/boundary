from dataclasses import dataclass, field
from typing import List

@dataclass
class AWSAccountContext:
    ou_path_ids: List[str] = field(default_factory=list)
