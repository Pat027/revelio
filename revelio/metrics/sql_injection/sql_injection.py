from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.sql_injection.template import SQLInjectionTemplate
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class SQLInjectionMetric(RedTeamingLLMMetric):
    _template = SQLInjectionTemplate
    _display_name = "SQL Injection"
    _eval_uses_purpose = False

    def __init__(
        self,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self._init_model(model, async_mode, verbose_mode)
