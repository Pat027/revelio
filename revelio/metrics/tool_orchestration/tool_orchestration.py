from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.tool_orchestration.template import (
    ToolOrchestrationTemplate,
)
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class ToolOrchestrationMetric(RedTeamingLLMMetric):
    _template = ToolOrchestrationTemplate
    _display_name = "Tool Orchestration"
    _category_param = "orchestration_type"

    def __init__(
        self,
        orchestration_type: str,
        purpose: Optional[str] = None,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self.orchestration_type = orchestration_type
        self.purpose = purpose
        self._init_model(model, async_mode, verbose_mode)
