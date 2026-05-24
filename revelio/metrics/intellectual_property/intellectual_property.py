from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.intellectual_property.template import (
    IntellectualPropertyTemplate,
)


class IntellectualPropertyMetric(RedTeamingLLMMetric):
    _template = IntellectualPropertyTemplate
    _display_name = "Intellectual Property"
    _eval_includes_input = False
