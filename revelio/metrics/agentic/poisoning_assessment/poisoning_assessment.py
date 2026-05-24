from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agentic.poisoning_assessment.template import (
    PoisoningAssessmentTemplate,
)


class PoisoningAssessmentMetric(RedTeamingLLMMetric):
    _template = PoisoningAssessmentTemplate
    _display_name = "Poisoning Assessment"
