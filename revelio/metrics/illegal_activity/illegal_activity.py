from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.illegal_activity.template import IllegalTemplate
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class IllegalMetric(RedTeamingLLMMetric):
    _template = IllegalTemplate
    _display_name = "Illegal Activity"
    _category_param = "illegal_category"

    def __init__(
        self,
        illegal_category: str,
        purpose: Optional[str] = None,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self.illegal_category = illegal_category
        self.purpose = purpose
        self._init_model(model, async_mode, verbose_mode)
