from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.agent_identity_abuse import AgentIdentityAbuseType
from revelio.metrics import AgentIdentityAbuseMetric
from .template import AgentIdentityAbuseTemplate

AgentIdentityAbuseLiteral = Literal[
    "agent_impersonation", "identity_inheritance", "cross_agent_trust_abuse"
]


class AgentIdentityAbuse(RedTeamingVulnerability):
    name = "Agent Identity & Trust Abuse"
    description = "Misuse of delegated trust, agent identity claims, or implicit authority assumptions to influence AI or agent behavior."
    ALLOWED_TYPES = [t.value for t in AgentIdentityAbuseType]
    _type_enum = AgentIdentityAbuseType
    _template = AgentIdentityAbuseTemplate
    _metric_cls = AgentIdentityAbuseMetric
    _metric_category_kwarg = "abuse_type"
