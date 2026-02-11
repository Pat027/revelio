"""Tests for risk category mapping and LLMRiskCategories enum."""

import pytest
from revelio.risks.risks import getRiskCategory, LLMRiskCategories
from revelio.vulnerabilities.bias import BiasType
from revelio.vulnerabilities.toxicity import ToxicityType
from revelio.vulnerabilities.sql_injection.types import SQLInjectionType
from revelio.vulnerabilities.pii_leakage import PIILeakageType
from revelio.vulnerabilities.illegal_activity import IllegalActivityType
from revelio.vulnerabilities.misinformation import MisinformationType
from revelio.vulnerabilities.shell_injection.types import ShellInjectionType
from revelio.vulnerabilities.bfla.types import BFLAType
from revelio.vulnerabilities.ssrf.types import SSRFType
from revelio.vulnerabilities.prompt_leakage import PromptLeakageType
from revelio.vulnerabilities.graphic_content import GraphicContentType
from revelio.vulnerabilities.personal_safety import PersonalSafetyType
from revelio.vulnerabilities.competition import CompetitionType
from revelio.vulnerabilities.robustness import RobustnessType
from revelio.vulnerabilities.excessive_agency import ExcessiveAgencyType


class TestLLMRiskCategories:
    def test_has_five_values(self):
        assert len(LLMRiskCategories) == 5

    def test_responsible_ai(self):
        assert LLMRiskCategories.RESPONSIBLE_AI.value == "Responsible AI"

    def test_illegal(self):
        assert LLMRiskCategories.ILLEGAL.value == "Illegal"

    def test_brand_image(self):
        assert LLMRiskCategories.BRAND_IMAGE.value == "Brand Image"

    def test_data_privacy(self):
        assert LLMRiskCategories.DATA_PRIVACY.value == "Data Privacy"

    def test_unauthorized_access(self):
        assert LLMRiskCategories.UNAUTHORIZED_ACCESS.value == "Unauthorized Access"


class TestGetRiskCategory:
    # ── Responsible AI ──
    def test_bias_maps_to_responsible_ai(self):
        assert getRiskCategory(BiasType.GENDER) == LLMRiskCategories.RESPONSIBLE_AI

    def test_toxicity_maps_to_responsible_ai(self):
        assert getRiskCategory(ToxicityType.PROFANITY) == LLMRiskCategories.RESPONSIBLE_AI

    # ── Unauthorized Access ──
    def test_sql_injection_maps_to_unauthorized(self):
        for t in SQLInjectionType:
            assert getRiskCategory(t) == LLMRiskCategories.UNAUTHORIZED_ACCESS

    def test_shell_injection_maps_to_unauthorized(self):
        for t in ShellInjectionType:
            assert getRiskCategory(t) == LLMRiskCategories.UNAUTHORIZED_ACCESS

    def test_bfla_maps_to_unauthorized(self):
        for t in BFLAType:
            assert getRiskCategory(t) == LLMRiskCategories.UNAUTHORIZED_ACCESS

    def test_ssrf_maps_to_unauthorized(self):
        for t in SSRFType:
            assert getRiskCategory(t) == LLMRiskCategories.UNAUTHORIZED_ACCESS

    # ── Data Privacy ──
    def test_pii_leakage_maps_to_data_privacy(self):
        for t in PIILeakageType:
            assert getRiskCategory(t) == LLMRiskCategories.DATA_PRIVACY

    def test_prompt_leakage_maps_to_data_privacy(self):
        for t in PromptLeakageType:
            assert getRiskCategory(t) == LLMRiskCategories.DATA_PRIVACY

    # ── Illegal ──
    def test_illegal_activity_maps_to_illegal(self):
        for t in IllegalActivityType:
            assert getRiskCategory(t) == LLMRiskCategories.ILLEGAL

    def test_graphic_content_maps_to_illegal(self):
        for t in GraphicContentType:
            assert getRiskCategory(t) == LLMRiskCategories.ILLEGAL

    def test_personal_safety_maps_to_illegal(self):
        for t in PersonalSafetyType:
            assert getRiskCategory(t) == LLMRiskCategories.ILLEGAL

    # ── Brand Image ──
    def test_misinformation_maps_to_brand_image(self):
        for t in MisinformationType:
            assert getRiskCategory(t) == LLMRiskCategories.BRAND_IMAGE

    def test_competition_maps_to_brand_image(self):
        for t in CompetitionType:
            assert getRiskCategory(t) == LLMRiskCategories.BRAND_IMAGE

    def test_robustness_maps_to_brand_image(self):
        for t in RobustnessType:
            assert getRiskCategory(t) == LLMRiskCategories.BRAND_IMAGE

    def test_excessive_agency_maps_to_brand_image(self):
        for t in ExcessiveAgencyType:
            assert getRiskCategory(t) == LLMRiskCategories.BRAND_IMAGE

    # ── Unknown ──
    def test_unknown_type_returns_others(self):
        from enum import Enum

        class FakeType(Enum):
            UNKNOWN = "unknown"

        result = getRiskCategory(FakeType.UNKNOWN)
        assert result == "Others"
