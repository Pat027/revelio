from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agentic.manipulation_assessment.template import (
    ManipulationAssessmentTemplate,
)


class ManipulationAssessmentMetric(RedTeamingLLMMetric):
    _template = ManipulationAssessmentTemplate
    _display_name = "Manipulation Assessment"
