from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.personal_safety.template import SafetyTemplate
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class SafetyMetric(RedTeamingLLMMetric):
    _template = SafetyTemplate
    _display_name = "Personal Safety"
    _category_param = "safety_category"

    def __init__(
        self,
        safety_category: str,
        purpose: Optional[str] = None,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self.safety_category = safety_category
        self.purpose = purpose
        self._init_model(model, async_mode, verbose_mode)
