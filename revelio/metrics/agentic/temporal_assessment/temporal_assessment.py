from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agentic.temporal_assessment.template import (
    TemporalAssessmentTemplate,
)


class TemporalAssessmentMetric(RedTeamingLLMMetric):
    _template = TemporalAssessmentTemplate
    _display_name = "Temporal Assessment"
