from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.indirect_instruction.template import (
    IndirectInstructionTemplate,
)
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class IndirectInstructionMetric(RedTeamingLLMMetric):
    _template = IndirectInstructionTemplate
    _display_name = "Indirect Instruction"
    _category_param = "instruction_type"

    def __init__(
        self,
        instruction_type: str,
        purpose: Optional[str] = None,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self.instruction_type = instruction_type
        self.purpose = purpose
        self._init_model(model, async_mode, verbose_mode)
