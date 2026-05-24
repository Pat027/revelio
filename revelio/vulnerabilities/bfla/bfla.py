from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.bfla import BFLAType
from revelio.metrics import BFLAMetric
from .template import BFLATemplate

BFLALiteral = Literal[
    "privilege_escalation", "function_bypass", "authorization_bypass"
]


class BFLA(RedTeamingVulnerability):
    name = "BFLA"
    description = "Broken Function Level Authorization enabling privileged function execution, authorization bypass, or permission escalation without proper access controls."
    ALLOWED_TYPES = [t.value for t in BFLAType]
    _type_enum = BFLAType
    _template = BFLATemplate
    _metric_cls = BFLAMetric
