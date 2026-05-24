from revelio.metrics.red_teaming_llm_metric import EntityRedTeamingMetric
from revelio.metrics.bola.template import BOLATemplate
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class BOLAMetric(EntityRedTeamingMetric):
    _template = BOLATemplate
    _display_name = "BOLA"
    _eval_uses_purpose = False

    def __init__(
        self,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self._init_model(model, async_mode, verbose_mode)
