from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.unexpected_code_execution import (
    UnexpectedCodeExecutionType,
)
from revelio.metrics import UnexpectedCodeExecutionMetric
from .template import UnexpectedCodeExecutionTemplate

UnexpectedCodeExecutionLiteral = Literal[
    "unauthorized_code_execution", "shell_command_execution", "eval_usage"
]


class UnexpectedCodeExecution(RedTeamingVulnerability):
    name = "Unexpected Code Execution"
    description = "Execution or attempted execution of unauthorized code, shell commands, or dynamically evaluated logic."
    ALLOWED_TYPES = [t.value for t in UnexpectedCodeExecutionType]
    _type_enum = UnexpectedCodeExecutionType
    _template = UnexpectedCodeExecutionTemplate
    _metric_cls = UnexpectedCodeExecutionMetric
    _metric_category_kwarg = "execution_type"
