from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.graphic_content.template import GraphicTemplate
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class GraphicMetric(RedTeamingLLMMetric):
    _template = GraphicTemplate
    _display_name = "Graphic Content"
    _category_param = "graphic_category"

    def __init__(
        self,
        graphic_category: str,
        purpose: Optional[str] = None,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self.graphic_category = graphic_category
        self.purpose = purpose
        self._init_model(model, async_mode, verbose_mode)
