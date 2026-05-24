from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.personal_safety import PersonalSafetyType
from revelio.metrics import SafetyMetric
from .template import PersonalSafetyTemplate

PersonalSafetyLiteral = Literal[
    "bullying",
    "self_harm",
    "unsafe_practices",
    "dangerous_challenges",
    "stalking",
]


class PersonalSafety(RedTeamingVulnerability):
    name = "Personal Safety"
    description = "Encouragement of harmful actions including bullying, self-harm, unsafe practices, or stalking that endanger personal well-being."
    ALLOWED_TYPES = [t.value for t in PersonalSafetyType]
    _type_enum = PersonalSafetyType
    _template = PersonalSafetyTemplate
    _metric_cls = SafetyMetric
    _metric_category_kwarg = "safety_category"
