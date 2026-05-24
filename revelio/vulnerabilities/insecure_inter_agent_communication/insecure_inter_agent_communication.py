from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.insecure_inter_agent_communication import (
    InsecureInterAgentCommunicationType,
)
from revelio.metrics import InsecureInterAgentCommunicationMetric
from .template import InsecureInterAgentCommunicationTemplate

InsecureInterAgentCommunicationLiteral = Literal[
    "message_spoofing", "message_injection", "agent_in_the_middle"
]


class InsecureInterAgentCommunication(RedTeamingVulnerability):
    name = "Inter-Agent Communication Compromise"
    description = "Spoofing, injection, replay, or manipulation of messages exchanged between agents, leading to unauthorized actions or trust violations."
    ALLOWED_TYPES = [t.value for t in InsecureInterAgentCommunicationType]
    _type_enum = InsecureInterAgentCommunicationType
    _template = InsecureInterAgentCommunicationTemplate
    _metric_cls = InsecureInterAgentCommunicationMetric
    _metric_category_kwarg = "communication_type"
