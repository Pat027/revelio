from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.hallucination.template import HallucinationTemplate


class HallucinationMetric(RedTeamingLLMMetric):
    _template = HallucinationTemplate
    _display_name = "Hallucination"
