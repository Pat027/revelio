from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.prompt_extraction.template import PromptExtractionTemplate


class PromptExtractionMetric(RedTeamingLLMMetric):
    _template = PromptExtractionTemplate
    _display_name = "Prompt Extraction"
