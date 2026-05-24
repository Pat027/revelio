from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.child_protection.template import ChildProtectionTemplate


class ChildProtectionMetric(RedTeamingLLMMetric):
    _template = ChildProtectionTemplate
    _display_name = "Child Protection"
