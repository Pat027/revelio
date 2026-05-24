from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agentic.boundary_violation.template import (
    BoundaryViolationTemplate,
)


class BoundaryViolationMetric(RedTeamingLLMMetric):
    _template = BoundaryViolationTemplate
    _display_name = "Boundary Violation"
