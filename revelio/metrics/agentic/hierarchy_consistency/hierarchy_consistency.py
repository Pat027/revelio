from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agentic.hierarchy_consistency.template import (
    HierarchyConsistencyTemplate,
)


class HierarchyConsistencyMetric(RedTeamingLLMMetric):
    _template = HierarchyConsistencyTemplate
    _display_name = "Hierarchy Consistency"
