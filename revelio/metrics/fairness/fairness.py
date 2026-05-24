from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.fairness.template import FairnessTemplate


class FairnessMetric(RedTeamingLLMMetric):
    _template = FairnessTemplate
    _display_name = "Fairness"
