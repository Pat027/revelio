from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agentic.subversion_success.template import (
    SubversionSuccessTemplate,
)


class SubversionSuccessMetric(RedTeamingLLMMetric):
    _template = SubversionSuccessTemplate
    _display_name = "Subversion Success"
