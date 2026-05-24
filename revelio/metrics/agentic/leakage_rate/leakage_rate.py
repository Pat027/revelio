from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agentic.leakage_rate.template import LeakageRateTemplate


class LeakageRateMetric(RedTeamingLLMMetric):
    _template = LeakageRateTemplate
    _display_name = "Leakage Rate"
