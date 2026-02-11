from typing import Union

from revelio.metrics.intellectual_property.template import (
    IntellectualPropertyTemplate,
)
from revelio.vulnerabilities.bias.template import BiasTemplate
from revelio.vulnerabilities.competition.template import CompetitionTemplate
from revelio.vulnerabilities.graphic_content.template import (
    GraphicContentTemplate,
)
from revelio.vulnerabilities.illegal_activity.template import (
    IllegalActivityTemplate,
)
from revelio.vulnerabilities.intellectual_property import (
    IntellectualPropertyType,
)
from revelio.vulnerabilities.misinformation.template import (
    MisinformationTemplate,
)
from revelio.vulnerabilities.personal_safety.template import (
    PersonalSafetyTemplate,
)
from revelio.vulnerabilities.pii_leakage.template import PIILeakageTemplate
from revelio.vulnerabilities.prompt_leakage.template import (
    PromptLeakageTemplate,
)
from revelio.vulnerabilities.toxicity.template import ToxicityTemplate
from revelio.vulnerabilities.illegal_activity import IllegalActivityType
from revelio.vulnerabilities.personal_safety import PersonalSafetyType
from revelio.vulnerabilities.graphic_content import GraphicContentType
from revelio.vulnerabilities.misinformation import MisinformationType
from revelio.vulnerabilities.prompt_leakage import PromptLeakageType
from revelio.vulnerabilities.competition import CompetitionType
from revelio.vulnerabilities.pii_leakage import PIILeakageType
from revelio.vulnerabilities.toxicity import ToxicityType
from revelio.vulnerabilities.bias import BiasType
from revelio.vulnerabilities.rbac import RBACType
from revelio.vulnerabilities.bola.types import BOLAType
from revelio.vulnerabilities.bfla.types import BFLAType
from revelio.vulnerabilities.ssrf.types import SSRFType
from revelio.vulnerabilities.debug_access.types import DebugAccessType
from revelio.vulnerabilities.shell_injection.types import ShellInjectionType
from revelio.vulnerabilities.sql_injection.types import SQLInjectionType
from revelio.vulnerabilities.rbac.template import RBACTemplate
from revelio.vulnerabilities.bola.template import BOLATemplate
from revelio.vulnerabilities.bfla.template import BFLATemplate
from revelio.vulnerabilities.ssrf.template import SSRFTemplate
from revelio.vulnerabilities.debug_access.template import DebugAccessTemplate
from revelio.vulnerabilities.shell_injection.template import (
    ShellInjectionTemplate,
)
from revelio.vulnerabilities.sql_injection.template import SQLInjectionTemplate
from revelio.vulnerabilities.robustness import RobustnessType
from revelio.vulnerabilities.robustness.template import (
    RobustnessTemplate,
)
from revelio.vulnerabilities.excessive_agency import (
    ExcessiveAgencyType,
)
from revelio.vulnerabilities.excessive_agency.template import (
    ExcessiveAgencyTemplate,
)

# Import agentic vulnerability types
from revelio.vulnerabilities.goal_theft.types import GoalTheftType
from revelio.vulnerabilities.recursive_hijacking.types import (
    RecursiveHijackingType,
)
from revelio.vulnerabilities.goal_theft.template import (
    GoalTheftTemplate,
)
from revelio.vulnerabilities.recursive_hijacking.template import (
    RecursiveHijackingTemplate,
)

VulnerabilityType = Union[
    IllegalActivityType,
    PersonalSafetyType,
    GraphicContentType,
    MisinformationType,
    PromptLeakageType,
    PromptLeakageType,
    CompetitionType,
    PIILeakageType,
    ToxicityType,
    BiasType,
    IntellectualPropertyType,
    IntellectualPropertyType,
    IntellectualPropertyType,
    RBACType,
    BOLAType,
    BFLAType,
    SSRFType,
    DebugAccessType,
    ShellInjectionType,
    SQLInjectionType,
    # Restored vulnerability types
    RobustnessType,
    ExcessiveAgencyType,
    # Agentic vulnerability types
    GoalTheftType,
    RecursiveHijackingType,
]

TemplateType = Union[
    BiasTemplate,
    CompetitionTemplate,
    GraphicContentTemplate,
    IllegalActivityTemplate,
    IntellectualPropertyTemplate,
    MisinformationTemplate,
    PersonalSafetyTemplate,
    PIILeakageTemplate,
    PromptLeakageTemplate,
    ToxicityTemplate,
    RBACTemplate,
    BOLATemplate,
    BFLATemplate,
    SSRFTemplate,
    DebugAccessTemplate,
    ShellInjectionTemplate,
    SQLInjectionTemplate,
    RobustnessTemplate,
    ExcessiveAgencyTemplate,
    GoalTheftTemplate,
    RecursiveHijackingTemplate,
]
