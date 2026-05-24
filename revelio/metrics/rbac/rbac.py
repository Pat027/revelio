from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.rbac.template import RBACTemplate


class RBACMetric(RedTeamingLLMMetric):
    _template = RBACTemplate
    _display_name = "RBAC"
    _measure_generates_purpose = True
