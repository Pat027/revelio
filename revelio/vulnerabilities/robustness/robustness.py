from typing import Literal

from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.robustness import RobustnessType
from revelio.metrics import (
    BaseRedTeamingMetric,
    HijackingMetric,
    OverrelianceMetric,
)
from .template import RobustnessTemplate

RobustnessLiteral = Literal["input_overreliance", "hijacking"]


class Robustness(RedTeamingVulnerability):
    name = "Robustness"
    description = "AI fragility through input overreliance or susceptibility to hijacking that redirects its intended behavior."
    ALLOWED_TYPES = [t.value for t in RobustnessType]
    _type_enum = RobustnessType
    _template = RobustnessTemplate

    def _get_metric(self, type: RobustnessType) -> BaseRedTeamingMetric:
        if type == RobustnessType.HIJACKING:
            metric_cls = HijackingMetric
        elif type == RobustnessType.INPUT_OVERRELIANCE:
            metric_cls = OverrelianceMetric
        else:
            raise ValueError(
                "Invalid type passed in the 'get_metric' function. "
                "Please pass an enum from 'RobustnessType'"
            )
        return metric_cls(
            purpose=self.purpose,
            model=self.evaluation_model,
            async_mode=self.async_mode,
            verbose_mode=self.verbose_mode,
        )
