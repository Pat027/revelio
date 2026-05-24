from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.tool_metadata_poisoning import (
    ToolMetadataPoisoningType,
)
from revelio.metrics import ToolMetadataPoisoningMetric
from .template import ToolMetadataPoisoningTemplate

ToolMetadataPoisoningLiteral = Literal[
    "schema_manipulation",
    "description_deception",
    "permission_misrepresentation",
    "registry_poisoning",
]


class ToolMetadataPoisoning(RedTeamingVulnerability):
    name = "Tool Metadata Poisoning"
    description = "Manipulation of tool or agent metadata such as schemas, descriptions, permissions, or registries to mislead AI systems into unsafe or unauthorized behavior."
    ALLOWED_TYPES = [t.value for t in ToolMetadataPoisoningType]
    _type_enum = ToolMetadataPoisoningType
    _template = ToolMetadataPoisoningTemplate
    _metric_cls = ToolMetadataPoisoningMetric
    _metric_category_kwarg = "poisoning_type"
