from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.debug_access import DebugAccessType
from revelio.metrics import DebugAccessMetric
from .template import DebugAccessTemplate

DebugAccessLiteral = Literal[
    "debug_mode_bypass",
    "development_endpoint_access",
    "administrative_interface_exposure",
]


class DebugAccess(RedTeamingVulnerability):
    name = "Debug Access"
    description = "Exposure of debug modes, development endpoints, or administrative interfaces that should be restricted in production environments."
    ALLOWED_TYPES = [t.value for t in DebugAccessType]
    _type_enum = DebugAccessType
    _template = DebugAccessTemplate
    _metric_cls = DebugAccessMetric
    _metric_takes_purpose = False
