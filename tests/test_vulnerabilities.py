"""Tests for all 32 vulnerability classes (excluding CustomVulnerability which has a unique signature)."""

import pytest
from revelio.vulnerabilities.base_vulnerability import BaseVulnerability
from revelio.vulnerabilities import (
    Bias,
    Toxicity,
    Misinformation,
    IllegalActivity,
    PromptLeakage,
    PIILeakage,
    BFLA,
    BOLA,
    ChildProtection,
    Ethics,
    Fairness,
    RBAC,
    DebugAccess,
    ShellInjection,
    SQLInjection,
    SSRF,
    IntellectualProperty,
    IndirectInstruction,
    ToolOrchestrationAbuse,
    AgentIdentityAbuse,
    ToolMetadataPoisoning,
    UnexpectedCodeExecution,
    InsecureInterAgentCommunication,
    AutonomousAgentDrift,
    Competition,
    GraphicContent,
    PersonalSafety,
    GoalTheft,
    RecursiveHijacking,
    Robustness,
    ExcessiveAgency,
    CustomVulnerability,
)
from revelio.vulnerabilities.bias import BiasType
from revelio.vulnerabilities.toxicity import ToxicityType
from revelio.vulnerabilities.misinformation import MisinformationType
from revelio.vulnerabilities.illegal_activity import IllegalActivityType
from revelio.vulnerabilities.prompt_leakage import PromptLeakageType
from revelio.vulnerabilities.pii_leakage import PIILeakageType
from revelio.vulnerabilities.bfla.types import BFLAType
from revelio.vulnerabilities.bola.types import BOLAType
from revelio.vulnerabilities.rbac import RBACType
from revelio.vulnerabilities.debug_access.types import DebugAccessType
from revelio.vulnerabilities.shell_injection.types import ShellInjectionType
from revelio.vulnerabilities.sql_injection.types import SQLInjectionType
from revelio.vulnerabilities.ssrf.types import SSRFType
from revelio.vulnerabilities.intellectual_property import IntellectualPropertyType
from revelio.vulnerabilities.competition import CompetitionType
from revelio.vulnerabilities.graphic_content import GraphicContentType
from revelio.vulnerabilities.personal_safety import PersonalSafetyType
from revelio.vulnerabilities.robustness import RobustnessType
from revelio.vulnerabilities.excessive_agency import ExcessiveAgencyType
from revelio.vulnerabilities.goal_theft.types import GoalTheftType
from revelio.vulnerabilities.recursive_hijacking.types import RecursiveHijackingType


# ── Map of (VulnerabilityClass, TypeEnum, expected_name) ──
STANDARD_VULNERABILITIES = [
    (Bias, BiasType, "Bias"),
    (Toxicity, ToxicityType, "Toxicity"),
    (Misinformation, MisinformationType, "Misinformation"),
    (IllegalActivity, IllegalActivityType, "Illegal Activity"),
    (PromptLeakage, PromptLeakageType, "Prompt Leakage"),
    (PIILeakage, PIILeakageType, "PII Leakage"),
    (BFLA, BFLAType, "BFLA"),
    (BOLA, BOLAType, "BOLA"),
    (RBAC, RBACType, "RBAC"),
    (DebugAccess, DebugAccessType, "Debug Access"),
    (ShellInjection, ShellInjectionType, "Shell Injection"),
    (SQLInjection, SQLInjectionType, "SQL Injection"),
    (SSRF, SSRFType, "SSRF"),
    (IntellectualProperty, IntellectualPropertyType, "Intellectual Property"),
    (Competition, CompetitionType, "Competition"),
    (GraphicContent, GraphicContentType, "Graphic Content"),
    (PersonalSafety, PersonalSafetyType, "Personal Safety"),
    (Robustness, RobustnessType, "Robustness"),
    (ExcessiveAgency, ExcessiveAgencyType, "Excessive Agency"),
    (GoalTheft, GoalTheftType, "Goal Theft"),
    (RecursiveHijacking, RecursiveHijackingType, "Recursive Hijacking"),
]

# These have child_protection/ethics/fairness/indirect_instruction/tool_orchestration/etc. type enums
# imported from their own module __init__ or types.py
ADDITIONAL_VULNERABILITIES_NO_TYPE_IN_TYPES_PY = [
    (ChildProtection, "Child Protection"),
    (Ethics, "Ethics"),
    (Fairness, "Fairness"),
    (IndirectInstruction, "Indirect Instruction"),
    (ToolOrchestrationAbuse, "Tool Orchestration Abuse"),
    (AgentIdentityAbuse, "Agent Identity & Trust Abuse"),
    (ToolMetadataPoisoning, "Tool Metadata Poisoning"),
    (UnexpectedCodeExecution, "Unexpected Code Execution"),
    (InsecureInterAgentCommunication, "Inter-Agent Communication Compromise"),
    (AutonomousAgentDrift, "Autonomous Agent Drift"),
]


class TestBaseVulnerability:
    def test_get_name_returns_class_name(self):
        """BaseVulnerability.get_name() returns the class name by default."""
        v = Bias()
        # Bias overrides get_name to return self.name
        assert v.get_name() == "Bias"

    def test_repr_format(self):
        v = Bias()
        r = repr(v)
        assert "Bias" in r
        assert "types=" in r

    def test_is_abc(self):
        from abc import ABC

        assert issubclass(BaseVulnerability, ABC)


class TestStandardVulnerabilities:
    """Test all standard vulnerabilities with parametrize."""

    @pytest.mark.parametrize(
        "cls,type_enum,expected_name", STANDARD_VULNERABILITIES
    )
    def test_default_instantiation(self, cls, type_enum, expected_name):
        v = cls()
        assert v is not None

    @pytest.mark.parametrize(
        "cls,type_enum,expected_name", STANDARD_VULNERABILITIES
    )
    def test_get_name(self, cls, type_enum, expected_name):
        v = cls()
        assert v.get_name() == expected_name

    @pytest.mark.parametrize(
        "cls,type_enum,expected_name", STANDARD_VULNERABILITIES
    )
    def test_get_types_returns_enum_list(self, cls, type_enum, expected_name):
        v = cls()
        types = v.get_types()
        assert isinstance(types, list)
        assert len(types) > 0
        for t in types:
            assert isinstance(t, type_enum)

    @pytest.mark.parametrize(
        "cls,type_enum,expected_name", STANDARD_VULNERABILITIES
    )
    def test_get_types_matches_allowed(self, cls, type_enum, expected_name):
        v = cls()
        types = v.get_types()
        allowed = v.ALLOWED_TYPES
        assert len(types) == len(allowed)

    @pytest.mark.parametrize(
        "cls,type_enum,expected_name", STANDARD_VULNERABILITIES
    )
    def test_get_values_returns_strings(self, cls, type_enum, expected_name):
        v = cls()
        values = v.get_values()
        assert isinstance(values, list)
        for val in values:
            assert isinstance(val, str)

    @pytest.mark.parametrize(
        "cls,type_enum,expected_name", STANDARD_VULNERABILITIES
    )
    def test_allowed_types_not_empty(self, cls, type_enum, expected_name):
        v = cls()
        assert len(v.ALLOWED_TYPES) > 0

    @pytest.mark.parametrize(
        "cls,type_enum,expected_name", STANDARD_VULNERABILITIES
    )
    def test_is_subclass_of_base(self, cls, type_enum, expected_name):
        assert issubclass(cls, BaseVulnerability)


class TestAdditionalVulnerabilities:
    """Test vulnerability classes whose type enums are not in the standard types.py."""

    @pytest.mark.parametrize(
        "cls,expected_name", ADDITIONAL_VULNERABILITIES_NO_TYPE_IN_TYPES_PY
    )
    def test_default_instantiation(self, cls, expected_name):
        v = cls()
        assert v is not None

    @pytest.mark.parametrize(
        "cls,expected_name", ADDITIONAL_VULNERABILITIES_NO_TYPE_IN_TYPES_PY
    )
    def test_get_name(self, cls, expected_name):
        v = cls()
        assert v.get_name() == expected_name

    @pytest.mark.parametrize(
        "cls,expected_name", ADDITIONAL_VULNERABILITIES_NO_TYPE_IN_TYPES_PY
    )
    def test_get_types_returns_list(self, cls, expected_name):
        v = cls()
        types = v.get_types()
        assert isinstance(types, list)
        assert len(types) > 0

    @pytest.mark.parametrize(
        "cls,expected_name", ADDITIONAL_VULNERABILITIES_NO_TYPE_IN_TYPES_PY
    )
    def test_get_values_returns_strings(self, cls, expected_name):
        v = cls()
        values = v.get_values()
        assert isinstance(values, list)
        for val in values:
            assert isinstance(val, str)

    @pytest.mark.parametrize(
        "cls,expected_name", ADDITIONAL_VULNERABILITIES_NO_TYPE_IN_TYPES_PY
    )
    def test_is_subclass_of_base(self, cls, expected_name):
        assert issubclass(cls, BaseVulnerability)


class TestCustomVulnerability:
    def test_instantiation(self):
        v = CustomVulnerability(
            name="TestVuln",
            criteria="Test criteria",
            types=["type_a", "type_b"],
        )
        assert v is not None

    def test_get_name(self):
        v = CustomVulnerability(
            name="MyCustom",
            criteria="custom criteria",
            types=["foo"],
        )
        assert v.get_name() == "MyCustom"

    def test_types_become_enum(self):
        v = CustomVulnerability(
            name="TestVuln",
            criteria="Test criteria",
            types=["alpha", "beta"],
        )
        types = v.get_types()
        assert len(types) == 2

    def test_get_values(self):
        v = CustomVulnerability(
            name="TestVuln",
            criteria="Test criteria",
            types=["x", "y"],
        )
        values = v.get_values()
        assert "x" in values
        assert "y" in values

    def test_is_subclass_of_base(self):
        assert issubclass(CustomVulnerability, BaseVulnerability)
