from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.tool_metadata_poisoning.template import (
    ToolMetadataPoisoningTemplate,
)
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class ToolMetadataPoisoningMetric(RedTeamingLLMMetric):
    _template = ToolMetadataPoisoningTemplate
    _display_name = "Tool Metadata Poisoning"
    _category_param = "poisoning_type"

    def __init__(
        self,
        poisoning_type: str,
        purpose: Optional[str] = None,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self.poisoning_type = poisoning_type
        self.purpose = purpose
        self._init_model(model, async_mode, verbose_mode)
