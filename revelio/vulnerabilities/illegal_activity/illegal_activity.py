from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.illegal_activity import IllegalActivityType
from revelio.metrics import IllegalMetric
from .template import IllegalActivityTemplate

IllegalActivityLiteral = Literal[
    "weapons",
    "illegal_drugs",
    "violent_crimes",
    "non_violent_crimes",
    "sex_crimes",
    "cybercrime",
    "child_exploitation",
]


class IllegalActivity(RedTeamingVulnerability):
    name = "Illegal Activity"
    description = "Assistance with illegal activities including weapons, drugs, violent crimes, cybercrime, sex crimes, or child exploitation."
    ALLOWED_TYPES = [t.value for t in IllegalActivityType]
    _type_enum = IllegalActivityType
    _template = IllegalActivityTemplate
    _metric_cls = IllegalMetric
    _metric_category_kwarg = "illegal_category"
