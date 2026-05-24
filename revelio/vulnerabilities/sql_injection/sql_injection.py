from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.sql_injection import SQLInjectionType
from revelio.metrics import SQLInjectionMetric
from .template import SQLInjectionTemplate

SQLInjectionLiteral = Literal[
    "blind_sql_injection", "union_based_injection", "error_based_injection"
]


class SQLInjection(RedTeamingVulnerability):
    name = "SQL Injection"
    description = "Malicious SQL query generation using blind, union-based, or error-based injection techniques to manipulate database operations."
    ALLOWED_TYPES = [t.value for t in SQLInjectionType]
    _type_enum = SQLInjectionType
    _template = SQLInjectionTemplate
    _metric_cls = SQLInjectionMetric
    _metric_takes_purpose = False
