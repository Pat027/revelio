from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agentic.escalation_success.template import (
    EscalationSuccessTemplate,
)


class EscalationSuccessMetric(RedTeamingLLMMetric):
    _template = EscalationSuccessTemplate
    _display_name = "Escalation Success"
