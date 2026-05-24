from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agent_identity_abuse.template import (
    AgentIdentityAbuseTemplate,
)
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class AgentIdentityAbuseMetric(RedTeamingLLMMetric):
    _template = AgentIdentityAbuseTemplate
    _display_name = "Agent Identity Abuse"
    _category_param = "abuse_type"

    def __init__(
        self,
        abuse_type: str,
        purpose: Optional[str] = None,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self.abuse_type = abuse_type
        self.purpose = purpose
        self._init_model(model, async_mode, verbose_mode)
