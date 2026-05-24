from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.recursive_hijacking import RecursiveHijackingType
from revelio.metrics.agentic.subversion_success.subversion_success import (
    SubversionSuccessMetric,
)
from .template import RecursiveHijackingTemplate

RecursiveHijackingLiteralType = Literal[
    "self_modifying_goals",
    "recursive_objective_chaining",
    "goal_propagation_attacks",
]


class RecursiveHijacking(RedTeamingVulnerability):
    name = "Recursive Hijacking"
    description = "Recursive subversion of the AI's objectives through self-modifying goals, objective chaining, or goal propagation attacks."
    ALLOWED_TYPES = [t.value for t in RecursiveHijackingType]
    _type_enum = RecursiveHijackingType
    _template = RecursiveHijackingTemplate
    _metric_cls = SubversionSuccessMetric
