from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.goal_theft import GoalTheftType
from revelio.metrics.agentic.extraction_success.extraction_success import (
    ExtractionSuccessMetric,
)
from .template import GoalTheftTemplate

GoalTheftLiteralType = Literal[
    "escalating_probing", "cooperative_dialogue", "social_engineering"
]


class GoalTheft(RedTeamingVulnerability):
    name = "Goal Theft"
    description = "Extraction or theft of the AI's underlying goals through escalating probing, cooperative dialogue, or social engineering."
    ALLOWED_TYPES = [t.value for t in GoalTheftType]
    _type_enum = GoalTheftType
    _template = GoalTheftTemplate
    _metric_cls = ExtractionSuccessMetric
