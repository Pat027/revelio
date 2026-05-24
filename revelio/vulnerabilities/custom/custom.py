from enum import Enum
from typing import List, Optional, Union

from deepeval.models import DeepEvalBaseLLM

from revelio.metrics import BaseRedTeamingMetric, HarmMetric
from revelio.vulnerabilities.base_vulnerability import BaseVulnerability
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from .template import CustomVulnerabilityTemplate


class CustomVulnerability(RedTeamingVulnerability):
    """User-defined vulnerability with its own types and evaluation criteria.

    Unlike the built-in vulnerabilities it has no fixed ``_type_enum`` — the
    type enum is built dynamically from the ``types`` argument — and it scores
    with a single ``HarmMetric`` configured by ``criteria``.
    """

    _template = CustomVulnerabilityTemplate

    def __init__(
        self,
        name: str,
        criteria: str,
        types: Optional[List[str]] = None,
        custom_prompt: Optional[str] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
        simulator_model: Optional[
            Union[str, DeepEvalBaseLLM]
        ] = "gpt-3.5-turbo-0125",
        evaluation_model: Optional[Union[str, DeepEvalBaseLLM]] = "gpt-4o",
    ):
        self.name = name
        if types:
            self.types = Enum(
                "CustomVulnerabilityType", {t.upper(): t for t in types}
            )
        self.custom_prompt = custom_prompt
        self.criteria = criteria.strip()
        self.simulator_model = simulator_model
        self.evaluation_model = evaluation_model
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        self.purpose = None
        self.metric = None
        # bypass RedTeamingVulnerability.__init__ (no static _type_enum)
        BaseVulnerability.__init__(self, self.types)

    def get_custom_prompt(self) -> Optional[str]:
        return self.custom_prompt

    def get_criteria(self) -> str:
        return self.criteria

    def _baseline_template_args(self, vuln_type, attacks_per_type):
        return (
            self.name,
            vuln_type,
            attacks_per_type,
            self.custom_prompt,
            self.purpose,
        )

    def _get_metric(self, type) -> BaseRedTeamingMetric:
        if self.metric is None:
            self.metric = HarmMetric(
                harm_category=self.criteria,
                model=self.evaluation_model,
                async_mode=self.async_mode,
                verbose_mode=self.verbose_mode,
            )
        return self.metric
