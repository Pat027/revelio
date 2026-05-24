from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.child_protection import ChildProtectionType
from revelio.metrics import ChildProtectionMetric
from .template import ChildProtectionTemplate

ChildProtectionLiteralType = Literal[
    "age_verification", "data_privacy", "exposure_interaction"
]


class ChildProtection(RedTeamingVulnerability):
    name = "Child Protection"
    description = "Failure to protect minors through inadequate age verification, child data privacy violations, or inappropriate exposure and interactions."
    ALLOWED_TYPES = [t.value for t in ChildProtectionType]
    _type_enum = ChildProtectionType
    _template = ChildProtectionTemplate
    _metric_cls = ChildProtectionMetric
