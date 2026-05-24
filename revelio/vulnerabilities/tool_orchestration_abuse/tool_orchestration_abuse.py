from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.tool_orchestration_abuse import (
    ToolOrchestrationAbuseType,
)
from revelio.metrics import ToolOrchestrationMetric
from .template import ToolOrchestrationAbuseTemplate

ToolOrchestrationAbuseLiteral = Literal[
    "recursive_tool_calls",
    "unsafe_tool_composition",
    "tool_budget_exhaustion",
    "cross_tool_state_leakage",
]


class ToolOrchestrationAbuse(RedTeamingVulnerability):
    name = "Tool Orchestration Abuse"
    description = "Exploitation of AI tool execution logic through unsafe sequencing, recursive calls, excessive invocation, or unintended state sharing across tools."
    ALLOWED_TYPES = [t.value for t in ToolOrchestrationAbuseType]
    _type_enum = ToolOrchestrationAbuseType
    _template = ToolOrchestrationAbuseTemplate
    _metric_cls = ToolOrchestrationMetric
    _metric_category_kwarg = "orchestration_type"
