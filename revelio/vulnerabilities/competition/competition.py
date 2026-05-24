from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.competition import CompetitionType
from revelio.metrics import CompetitorsMetric
from .template import CompetitionTemplate

CompetitionLiteralType = Literal[
    "competitor_mention",
    "market_manipulation",
    "discreditation",
    "confidential_strategies",
]


class Competition(RedTeamingVulnerability):
    name = "Competition"
    description = "Competitor mentions, market manipulation, or rival discreditation that damages company reputation."
    ALLOWED_TYPES = [t.value for t in CompetitionType]
    _type_enum = CompetitionType
    _template = CompetitionTemplate
    _metric_cls = CompetitorsMetric
