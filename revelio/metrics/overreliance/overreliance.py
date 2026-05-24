from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.overreliance.template import OverrelianceTemplate


class OverrelianceMetric(RedTeamingLLMMetric):
    _template = OverrelianceTemplate
    _display_name = "Overreliance"
