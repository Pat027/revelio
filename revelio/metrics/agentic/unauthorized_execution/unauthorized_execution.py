from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agentic.unauthorized_execution.template import (
    UnauthorizedExecutionTemplate,
)


class UnauthorizedExecutionMetric(RedTeamingLLMMetric):
    _template = UnauthorizedExecutionTemplate
    _display_name = "Unauthorized Execution"
