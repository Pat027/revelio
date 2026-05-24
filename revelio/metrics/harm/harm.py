from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.harm.template import HarmTemplate
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class HarmMetric(RedTeamingLLMMetric):
    _template = HarmTemplate
    _display_name = "Harm"
    _category_param = "harm_category"
    _eval_uses_purpose = False

    def __init__(
        self,
        harm_category: str,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self.harm_category = harm_category
        self._init_model(model, async_mode, verbose_mode)
