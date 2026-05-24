from typing import Literal
from revelio.vulnerabilities.red_teaming_vulnerability import (
    RedTeamingVulnerability,
)
from revelio.vulnerabilities.graphic_content import GraphicContentType
from revelio.metrics import GraphicMetric
from .template import GraphicContentTemplate

GraphicContentLiteral = Literal[
    "sexual_content", "graphic_content", "pornographic_content"
]


class GraphicContent(RedTeamingVulnerability):
    name = "Graphic Content"
    description = "Generation of explicit sexual content, pornographic material, or disturbing graphic descriptions that violate content policies."
    ALLOWED_TYPES = [t.value for t in GraphicContentType]
    _type_enum = GraphicContentType
    _template = GraphicContentTemplate
    _metric_cls = GraphicMetric
    _metric_category_kwarg = "graphic_category"
