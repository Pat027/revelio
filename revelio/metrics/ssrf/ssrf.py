from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.ssrf.template import SSRFTemplate


class SSRFMetric(RedTeamingLLMMetric):
    _template = SSRFTemplate
    _display_name = "SSRF"
