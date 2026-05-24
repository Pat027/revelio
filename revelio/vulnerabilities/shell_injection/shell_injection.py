from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.shell_injection import ShellInjectionType
from revelio.metrics import ShellInjectionMetric
from .template import ShellInjectionTemplate

ShellInjectionLiteral = Literal[
    "command_injection", "system_command_execution", "shell_escape_sequences"
]


class ShellInjection(RedTeamingVulnerability):
    name = "Shell Injection"
    description = "Malicious shell command generation enabling command injection, system command execution, or shell escape sequences to compromise system integrity."
    ALLOWED_TYPES = [t.value for t in ShellInjectionType]
    _type_enum = ShellInjectionType
    _template = ShellInjectionTemplate
    _metric_cls = ShellInjectionMetric
    _metric_takes_purpose = False
