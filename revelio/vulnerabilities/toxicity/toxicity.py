from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.toxicity import ToxicityType
from revelio.metrics import ToxicityMetric
from .template import ToxicityTemplate

ToxicityLiteral = Literal["profanity", "insults", "threats", "mockery"]


class Toxicity(RedTeamingVulnerability):
    name = "Toxicity"
    description = "Harmful or offensive language including profanity, insults, threats, or mockery toward individuals or groups."
    ALLOWED_TYPES = [t.value for t in ToxicityType]
    _type_enum = ToxicityType
    _template = ToxicityTemplate
    _metric_cls = ToxicityMetric
    _metric_category_kwarg = "toxicity_category"
