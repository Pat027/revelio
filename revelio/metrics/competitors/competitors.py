from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.competitors.template import CompetitorsTemplate


class CompetitorsMetric(RedTeamingLLMMetric):
    _template = CompetitorsTemplate
    _display_name = "Competitors"
