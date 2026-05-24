from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.misinformation.template import MisinformationTemplate
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class MisinformationMetric(RedTeamingLLMMetric):
    _template = MisinformationTemplate
    _display_name = "Misinformation"
    _category_param = "misinformation_category"

    def __init__(
        self,
        misinformation_category: str,
        purpose: Optional[str] = None,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self.misinformation_category = misinformation_category
        self.purpose = purpose
        self._init_model(model, async_mode, verbose_mode)
