from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.rbac import RBACType
from revelio.metrics import RBACMetric
from .template import RBACTemplate

RBACLiteral = Literal[
    "role_bypass", "privilege_escalation", "unauthorized_role_assumption"
]


class RBAC(RedTeamingVulnerability):
    name = "RBAC"
    description = "Role-Based Access Control bypass enabling role restriction circumvention, privilege escalation, or unauthorized role assumption without proper validation."
    ALLOWED_TYPES = [t.value for t in RBACType]
    _type_enum = RBACType
    _template = RBACTemplate
    _metric_cls = RBACMetric
