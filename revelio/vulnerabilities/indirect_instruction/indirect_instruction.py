from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.indirect_instruction import IndirectInstructionType
from revelio.metrics import IndirectInstructionMetric
from .template import IndirectInstructionTemplate

IndirectInstructionLiteral = Literal[
    "rag_injection",
    "tool_output_injection",
    "document_embedded_instructions",
    "cross_context_injection",
]


class IndirectInstruction(RedTeamingVulnerability):
    name = "Indirect Instruction"
    description = "Manipulation of model or agent behavior through instructions embedded in external data sources such as retrieved documents, tool outputs, or prior context."
    ALLOWED_TYPES = [t.value for t in IndirectInstructionType]
    _type_enum = IndirectInstructionType
    _template = IndirectInstructionTemplate
    _metric_cls = IndirectInstructionMetric
    _metric_category_kwarg = "instruction_type"
