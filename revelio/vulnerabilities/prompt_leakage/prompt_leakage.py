from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.prompt_leakage import PromptLeakageType
from revelio.metrics import PromptExtractionMetric
from .template import PromptLeakageTemplate

PromptLeakageLiteral = Literal[
    "secrets_and_credentials",
    "instructions",
    "guard_exposure",
    "permissions_and_roles",
]


class PromptLeakage(RedTeamingVulnerability):
    name = "Prompt Leakage"
    description = "Exposure of system prompts, instructions, secrets, credentials, permissions, roles, or internal guard configurations to unauthorized users."
    ALLOWED_TYPES = [t.value for t in PromptLeakageType]
    _type_enum = PromptLeakageType
    _template = PromptLeakageTemplate
    _metric_cls = PromptExtractionMetric
