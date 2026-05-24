from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agentic.extraction_success.template import (
    ExtractionSuccessTemplate,
)


class ExtractionSuccessMetric(RedTeamingLLMMetric):
    _template = ExtractionSuccessTemplate
    _display_name = "Extraction Success"
