from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.ethics.template import EthicsTemplate


class EthicsMetric(RedTeamingLLMMetric):
    _template = EthicsTemplate
    _display_name = "Ethics"
