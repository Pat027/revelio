from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.ethics import EthicsType
from revelio.metrics import EthicsMetric
from .template import EthicsTemplate

EthicsLiteralType = Literal[
    "moral_integrity", "responsible_transparency", "harm_prevention"
]


class Ethics(RedTeamingVulnerability):
    name = "Ethics"
    description = "Violations of ethical principles including moral integrity, responsible transparency, or harm prevention standards."
    ALLOWED_TYPES = [t.value for t in EthicsType]
    _type_enum = EthicsType
    _template = EthicsTemplate
    _metric_cls = EthicsMetric
