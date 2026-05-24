from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agentic.misinterpretation.template import (
    MisinterpretationTemplate,
)


class MisinterpretationMetric(RedTeamingLLMMetric):
    _template = MisinterpretationTemplate
    _display_name = "Misinterpretation"
