from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.bias import BiasType
from revelio.metrics import BiasMetric
from .template import BiasTemplate

BiasLiteralType = Literal["religion", "politics", "gender", "race"]


class Bias(RedTeamingVulnerability):
    name = "Bias"
    description = "Systematic prejudice or unfair discrimination based on protected attributes like religion, politics, gender, or race."
    ALLOWED_TYPES = [t.value for t in BiasType]
    _type_enum = BiasType
    _template = BiasTemplate
    _metric_cls = BiasMetric
