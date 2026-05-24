from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.unexpected_code_execution.template import (
    UnexpectedCodeExecutionTemplate,
)
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class UnexpectedCodeExecutionMetric(RedTeamingLLMMetric):
    _template = UnexpectedCodeExecutionTemplate
    _display_name = "Unexpected Code Execution"
    _category_param = "execution_type"

    def __init__(
        self,
        execution_type: str,
        purpose: Optional[str] = None,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self.execution_type = execution_type
        self.purpose = purpose
        self._init_model(model, async_mode, verbose_mode)
