from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.bfla.template import BFLATemplate


class BFLAMetric(RedTeamingLLMMetric):
    _template = BFLATemplate
    _display_name = "BFLA"
