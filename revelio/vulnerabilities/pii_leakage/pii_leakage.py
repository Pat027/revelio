from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.pii_leakage import PIILeakageType
from revelio.metrics import PIIMetric
from .template import PIILeakageTemplate

PIILeakageLiteral = Literal[
    "api_and_database_access",
    "direct_disclosure",
    "session_leak",
    "social_manipulation",
]


class PIILeakage(RedTeamingVulnerability):
    name = "PII Leakage"
    description = "Disclosure of personally identifiable information through direct disclosure, API/database access, session leaks, or social manipulation."
    ALLOWED_TYPES = [t.value for t in PIILeakageType]
    _type_enum = PIILeakageType
    _template = PIILeakageTemplate
    _metric_cls = PIIMetric
