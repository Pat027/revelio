from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.insecure_inter_agent_communication.template import (
    InsecureInterAgentCommunicationTemplate,
)
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class InsecureInterAgentCommunicationMetric(RedTeamingLLMMetric):
    _template = InsecureInterAgentCommunicationTemplate
    _display_name = "Insecure Inter-Agent Communication"
    _category_param = "communication_type"

    def __init__(
        self,
        communication_type: str,
        purpose: Optional[str] = None,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self.communication_type = communication_type
        self.purpose = purpose
        self._init_model(model, async_mode, verbose_mode)
