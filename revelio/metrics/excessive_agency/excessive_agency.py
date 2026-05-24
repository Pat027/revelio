from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.excessive_agency.template import ExcessiveAgencyTemplate
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class ExcessiveAgencyMetric(RedTeamingLLMMetric):
    _template = ExcessiveAgencyTemplate
    _display_name = "Excessive Agency"

    def __init__(
        self,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        purpose: Optional[str] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self.purpose = purpose
        self._init_model(model, async_mode, verbose_mode)
