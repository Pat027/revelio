from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agentic.hallucination_detection.template import (
    HallucinationDetectionTemplate,
)


class HallucinationDetectionMetric(RedTeamingLLMMetric):
    _template = HallucinationDetectionTemplate
    _display_name = "Hallucination Detection"
