from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.autonomous_agent_drift.template import (
    AutonomousAgentDriftTemplate,
)
from typing import Optional, Union
from deepeval.models import DeepEvalBaseLLM


class AutonomousAgentDriftMetric(RedTeamingLLMMetric):
    _template = AutonomousAgentDriftTemplate
    _display_name = "Autonomous Agent Drift"
    _category_param = "drift_type"

    def __init__(
        self,
        drift_type: str,
        purpose: Optional[str] = None,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self.drift_type = drift_type
        self.purpose = purpose
        self._init_model(model, async_mode, verbose_mode)
