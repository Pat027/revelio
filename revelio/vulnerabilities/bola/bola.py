from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.bola import BOLAType
from revelio.metrics import BOLAMetric
from .template import BOLATemplate

BOLALiteral = Literal[
    "object_access_bypass",
    "cross_customer_access",
    "unauthorized_object_manipulation",
]


class BOLA(RedTeamingVulnerability):
    name = "BOLA"
    description = "Broken Object Level Authorization enabling cross-customer access, object access bypass, or unauthorized object manipulation without proper authorization."
    ALLOWED_TYPES = [t.value for t in BOLAType]
    _type_enum = BOLAType
    _template = BOLATemplate
    _metric_cls = BOLAMetric
    _metric_takes_purpose = False
