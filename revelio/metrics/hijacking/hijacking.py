from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.hijacking.template import HijackingTemplate


class HijackingMetric(RedTeamingLLMMetric):
    _template = HijackingTemplate
    _display_name = "Hijacking"
