from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agentic.domain_validation.template import (
    DomainValidationTemplate,
)


class DomainValidationMetric(RedTeamingLLMMetric):
    _template = DomainValidationTemplate
    _display_name = "Domain Validation"
