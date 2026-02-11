from typing import List, Optional
from revelio.vulnerabilities import (
    BaseVulnerability,
)
from revelio.attacks import BaseAttack
from dataclasses import dataclass


@dataclass
class RiskCategory:
    name: str
    vulnerabilities: List[BaseVulnerability]
    attacks: List[BaseAttack]
    description: Optional[str] = None
    _display_name: Optional[str] = None
