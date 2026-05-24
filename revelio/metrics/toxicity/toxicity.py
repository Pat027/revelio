from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.toxicity.template import ToxicityTemplate
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class ToxicityMetric(RedTeamingLLMMetric):
    _template = ToxicityTemplate
    _display_name = "Toxicity"
    _category_param = "toxicity_category"

    def __init__(
        self,
        toxicity_category: str,
        purpose: Optional[str] = None,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self.toxicity_category = toxicity_category
        self.purpose = purpose
        self._init_model(model, async_mode, verbose_mode)
