from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agentic.amnesia_assessment.template import (
    AmnesiaAssessmentTemplate,
)


class AmnesiaAssessmentMetric(RedTeamingLLMMetric):
    _template = AmnesiaAssessmentTemplate
    _display_name = "Amnesia Assessment"
