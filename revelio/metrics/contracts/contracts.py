from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.contracts.template import ContractsTemplate
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class ContractsMetric(RedTeamingLLMMetric):
    _template = ContractsTemplate
    _display_name = "Contracts"
    _eval_uses_purpose = False

    def __init__(
        self,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self._init_model(model, async_mode, verbose_mode)
