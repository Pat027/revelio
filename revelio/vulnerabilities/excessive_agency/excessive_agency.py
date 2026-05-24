from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.excessive_agency import ExcessiveAgencyType
from revelio.metrics import ExcessiveAgencyMetric
from .template import ExcessiveAgencyTemplate

ExcessiveAgencyLiteral = Literal["functionality", "permissions", "autonomy"]


class ExcessiveAgency(RedTeamingVulnerability):
    name = "Excessive Agency"
    description = "AI exhibiting excessive autonomy, overstepping intended functionality, or exceeding granted permissions without proper oversight."
    ALLOWED_TYPES = [t.value for t in ExcessiveAgencyType]
    _type_enum = ExcessiveAgencyType
    _template = ExcessiveAgencyTemplate
    _metric_cls = ExcessiveAgencyMetric
