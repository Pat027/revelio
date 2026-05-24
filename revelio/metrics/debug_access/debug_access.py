from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.debug_access.template import DebugAccessTemplate
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class DebugAccessMetric(RedTeamingLLMMetric):
    _template = DebugAccessTemplate
    _display_name = "Debug Access"
    _eval_uses_purpose = False

    def __init__(
        self,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self._init_model(model, async_mode, verbose_mode)
