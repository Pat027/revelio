"""Smoke tests verifying every public module imports cleanly."""

import pytest


class TestCoreImports:
    def test_import_red_team(self):
        from revelio import red_team

        assert callable(red_team)

    def test_import_version(self):
        from revelio import __version__

        assert isinstance(__version__, str)
        assert len(__version__) > 0


class TestVulnerabilityImports:
    """Verify all 33 vulnerability exports import cleanly."""

    VULNERABILITY_CLASSES = [
        "BaseVulnerability",
        "Bias",
        "Toxicity",
        "Misinformation",
        "IllegalActivity",
        "PromptLeakage",
        "PIILeakage",
        "BFLA",
        "BOLA",
        "ChildProtection",
        "Ethics",
        "Fairness",
        "RBAC",
        "DebugAccess",
        "ShellInjection",
        "SQLInjection",
        "SSRF",
        "IntellectualProperty",
        "IndirectInstruction",
        "ToolOrchestrationAbuse",
        "AgentIdentityAbuse",
        "ToolMetadataPoisoning",
        "UnexpectedCodeExecution",
        "InsecureInterAgentCommunication",
        "AutonomousAgentDrift",
        "Competition",
        "GraphicContent",
        "PersonalSafety",
        "CustomVulnerability",
        "GoalTheft",
        "RecursiveHijacking",
        "Robustness",
        "ExcessiveAgency",
    ]

    @pytest.mark.parametrize("cls_name", VULNERABILITY_CLASSES)
    def test_vulnerability_import(self, cls_name):
        import revelio.vulnerabilities as mod

        cls = getattr(mod, cls_name)
        assert cls is not None


class TestSingleTurnAttackImports:
    """Verify all 21 single-turn attack exports import cleanly."""

    ATTACK_CLASSES = [
        "BaseSingleTurnAttack",
        "AdversarialPoetry",
        "Base64",
        "GrayBox",
        "Leetspeak",
        "MathProblem",
        "Multilingual",
        "PromptInjection",
        "PromptProbing",
        "Roleplay",
        "ROT13",
        "CharacterStream",
        "ContextFlooding",
        "EmbeddedInstructionJSON",
        "SyntheticContextInjection",
        "AuthorityEscalation",
        "EmotionalManipulation",
        "SystemOverride",
        "PermissionEscalation",
        "GoalRedirection",
        "LinguisticConfusion",
        "InputBypass",
        "ContextPoisoning",
    ]

    @pytest.mark.parametrize("cls_name", ATTACK_CLASSES)
    def test_single_turn_attack_import(self, cls_name):
        import revelio.attacks.single_turn as mod

        cls = getattr(mod, cls_name)
        assert cls is not None


class TestMultiTurnAttackImports:
    """Verify all 5 multi-turn attack exports import cleanly."""

    ATTACK_CLASSES = [
        "CrescendoJailbreaking",
        "LinearJailbreaking",
        "TreeJailbreaking",
        "SequentialJailbreak",
        "BadLikertJudge",
        "BaseMultiTurnAttack",
    ]

    @pytest.mark.parametrize("cls_name", ATTACK_CLASSES)
    def test_multi_turn_attack_import(self, cls_name):
        import revelio.attacks.multi_turn as mod

        cls = getattr(mod, cls_name)
        assert cls is not None


class TestFrameworkImports:
    """Verify all 7 framework exports import cleanly."""

    FRAMEWORK_CLASSES = [
        "AISafetyFramework",
        "OWASPTop10",
        "OWASP_ASI_2026",
        "NIST",
        "Aegis",
        "BeaverTails",
        "MITRE",
    ]

    @pytest.mark.parametrize("cls_name", FRAMEWORK_CLASSES)
    def test_framework_import(self, cls_name):
        import revelio.frameworks as mod

        cls = getattr(mod, cls_name)
        assert cls is not None


class TestOtherImports:
    def test_import_base_metric(self):
        from revelio.metrics import BaseRedTeamingMetric

        assert BaseRedTeamingMetric is not None

    def test_import_test_case(self):
        from revelio.test_case import RTTestCase

        assert RTTestCase is not None

    def test_import_rt_turn(self):
        from revelio.test_case.test_case import RTTurn

        assert RTTurn is not None

    def test_import_get_risk_category(self):
        from revelio.risks import getRiskCategory

        assert callable(getRiskCategory)

    def test_import_llm_risk_categories(self):
        from revelio.risks.risks import LLMRiskCategories

        assert LLMRiskCategories is not None

    def test_import_model_refusal_error(self):
        from revelio.errors import ModelRefusalError

        assert issubclass(ModelRefusalError, Exception)

    def test_import_exploitability(self):
        from revelio.attacks.base_attack import Exploitability

        assert Exploitability is not None
