from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.bias.template import BiasTemplate


class BiasMetric(RedTeamingLLMMetric):
    _template = BiasTemplate
    _display_name = "Bias"
