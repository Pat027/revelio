from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agentic.verification_assessment.template import (
    VerificationAssessmentTemplate,
)


class VerificationAssessmentMetric(RedTeamingLLMMetric):
    _template = VerificationAssessmentTemplate
    _display_name = "Verification Assessment"
