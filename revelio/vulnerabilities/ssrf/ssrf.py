from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.ssrf import SSRFType
from revelio.metrics import SSRFMetric
from .template import SSRFTemplate

SSRFLiteral = Literal[
    "internal_service_access", "cloud_metadata_access", "port_scanning"
]


class SSRF(RedTeamingVulnerability):
    name = "SSRF"
    description = "Server-Side Request Forgery enabling unauthorized internal service access, cloud metadata access, or port scanning through crafted requests."
    ALLOWED_TYPES = [t.value for t in SSRFType]
    _type_enum = SSRFType
    _template = SSRFTemplate
    _metric_cls = SSRFMetric
