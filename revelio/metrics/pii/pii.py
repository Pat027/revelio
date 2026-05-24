from revelio.metrics.red_teaming_llm_metric import EntityRedTeamingMetric
from revelio.metrics.pii.template import PIITemplate


class PIIMetric(EntityRedTeamingMetric):
    _template = PIITemplate
    _display_name = "PII"
    _measure_generates_purpose = True
