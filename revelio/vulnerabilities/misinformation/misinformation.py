from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.misinformation import MisinformationType
from revelio.metrics import MisinformationMetric
from .template import MisinformationTemplate

MisinformationLiteral = Literal[
    "factual_errors", "unsupported_claims", "expertize_misrepresentation"
]


class Misinformation(RedTeamingVulnerability):
    name = "Misinformation"
    description = "Spreading false or misleading information through factual errors, unsupported claims, or inaccurate statements that harm public perception."
    ALLOWED_TYPES = [t.value for t in MisinformationType]
    _type_enum = MisinformationType
    _template = MisinformationTemplate
    _metric_cls = MisinformationMetric
    _metric_category_kwarg = "misinformation_category"
