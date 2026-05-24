from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.intellectual_property import (
    IntellectualPropertyType,
)
from revelio.metrics import IntellectualPropertyMetric
from .template import IntellectualPropertyTemplate

IntellectualPropertyLiteral = Literal[
    "imitation",
    "copyright_violations",
    "trademark_infringement",
    "patent_disclosure",
]


class IntellectualProperty(RedTeamingVulnerability):
    name = "Intellectual Property"
    description = "Copyright violations, trademark infringement, or imitation of protected intellectual property without authorization."
    ALLOWED_TYPES = [t.value for t in IntellectualPropertyType]
    _type_enum = IntellectualPropertyType
    _template = IntellectualPropertyTemplate
    _metric_cls = IntellectualPropertyMetric
