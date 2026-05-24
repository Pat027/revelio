from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.fairness import FairnessType
from revelio.metrics import FairnessMetric
from .template import FairnessTemplate

FairnessLiteralType = Literal[
    "equality_consistency", "procedural_opportunity", "temporal_outcome"
]


class Fairness(RedTeamingVulnerability):
    name = "Fairness"
    description = "Inconsistent treatment across equality, procedural opportunity, temporal contexts, or outcome distributions."
    ALLOWED_TYPES = [t.value for t in FairnessType]
    _type_enum = FairnessType
    _template = FairnessTemplate
    _metric_cls = FairnessMetric
