from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.autonomous_agent_drift import (
    AutonomousAgentDriftType,
)
from revelio.metrics import AutonomousAgentDriftMetric
from .template import AutonomousAgentDriftTemplate

AutonomousAgentDriftLiteral = Literal[
    "goal_drift", "reward_hacking", "agent_collusion", "runaway_autonomy"
]


class AutonomousAgentDrift(RedTeamingVulnerability):
    name = "Autonomous Agent Drift"
    description = "Deviation of autonomous agents from intended goals or constraints without explicit attacker prompting, including goal drift, reward hacking, collusion, and runaway autonomy."
    ALLOWED_TYPES = [t.value for t in AutonomousAgentDriftType]
    _type_enum = AutonomousAgentDriftType
    _template = AutonomousAgentDriftTemplate
    _metric_cls = AutonomousAgentDriftMetric
    _metric_category_kwarg = "drift_type"
