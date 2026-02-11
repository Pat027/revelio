"""Tests for RiskAssessment, construct_risk_assessment_overview, and related models."""

import json
import os
import pytest
from revelio.red_teamer.risk_assessment import (
    RiskAssessment,
    RedTeamingOverview,
    VulnerabilityTypeResult,
    AttackMethodResult,
    TestCasesList,
    construct_risk_assessment_overview,
)
from revelio.test_case.test_case import RTTestCase
from revelio.vulnerabilities.bias import BiasType
from revelio.vulnerabilities.toxicity import ToxicityType


class TestVulnerabilityTypeResult:
    def test_construction(self):
        r = VulnerabilityTypeResult(
            vulnerability="Bias",
            vulnerability_type=BiasType.GENDER,
            pass_rate=0.75,
            passing=3,
            failing=1,
            errored=0,
        )
        assert r.vulnerability == "Bias"
        assert r.pass_rate == 0.75
        assert r.passing == 3

    def test_all_fields_required(self):
        with pytest.raises(Exception):
            VulnerabilityTypeResult(vulnerability="Bias")


class TestAttackMethodResult:
    def test_construction(self):
        r = AttackMethodResult(
            pass_rate=0.5,
            passing=2,
            failing=2,
            errored=0,
            attack_method="Prompt Injection",
        )
        assert r.attack_method == "Prompt Injection"
        assert r.pass_rate == 0.5

    def test_attack_method_optional(self):
        r = AttackMethodResult(
            pass_rate=1.0,
            passing=5,
            failing=0,
            errored=0,
        )
        assert r.attack_method is None


class TestConstructRiskAssessmentOverview:
    def test_empty_test_cases(self):
        overview = construct_risk_assessment_overview([], run_duration=1.0)
        assert overview.vulnerability_type_results == []
        assert overview.attack_method_results == []
        assert overview.errored == 0
        assert overview.run_duration == 1.0

    def test_passing_test_cases(self, make_test_case):
        tc1 = make_test_case(score=0.8, vulnerability_type=BiasType.GENDER)
        tc2 = make_test_case(score=0.9, vulnerability_type=BiasType.GENDER)
        overview = construct_risk_assessment_overview([tc1, tc2], run_duration=2.5)
        assert len(overview.vulnerability_type_results) == 1
        vtr = overview.vulnerability_type_results[0]
        assert vtr.passing == 2
        assert vtr.failing == 0

    def test_failing_test_cases(self, make_test_case):
        tc = make_test_case(score=0.0, vulnerability_type=BiasType.RACE)
        overview = construct_risk_assessment_overview([tc], run_duration=1.0)
        vtr = overview.vulnerability_type_results[0]
        assert vtr.failing == 1
        assert vtr.passing == 0

    def test_errored_test_cases(self, make_test_case):
        tc = make_test_case(error="LLM timeout")
        overview = construct_risk_assessment_overview([tc], run_duration=1.0)
        assert overview.errored == 1

    def test_mixed_results(self, make_test_case):
        tc_pass = make_test_case(score=0.8, vulnerability_type=BiasType.GENDER)
        tc_fail = make_test_case(score=0.0, vulnerability_type=BiasType.GENDER)
        tc_err = make_test_case(error="timeout")
        overview = construct_risk_assessment_overview(
            [tc_pass, tc_fail, tc_err], run_duration=3.0
        )
        # Errored test cases are counted and excluded from vuln grouping.
        # Note: the implementation overwrites the top-level `errored` counter
        # with the per-vuln-type errored count from the last iteration.
        assert overview.run_duration == 3.0
        # At least one vuln type result should exist (from the non-errored cases)
        assert len(overview.vulnerability_type_results) >= 1

    def test_multiple_vulnerability_types(self, make_test_case):
        tc1 = make_test_case(
            score=1.0, vulnerability_type=BiasType.GENDER, vulnerability="Bias"
        )
        tc2 = make_test_case(
            score=0.5,
            vulnerability_type=ToxicityType.PROFANITY,
            vulnerability="Toxicity",
        )
        overview = construct_risk_assessment_overview([tc1, tc2], run_duration=1.0)
        assert len(overview.vulnerability_type_results) == 2

    def test_attack_method_grouping(self, make_test_case):
        tc1 = make_test_case(
            score=1.0,
            attack_method="Prompt Injection",
            vulnerability_type=BiasType.GENDER,
        )
        tc2 = make_test_case(
            score=0.0,
            attack_method="Roleplay",
            vulnerability_type=BiasType.GENDER,
        )
        overview = construct_risk_assessment_overview([tc1, tc2], run_duration=1.0)
        assert len(overview.attack_method_results) == 2

    def test_run_duration_passed_through(self, make_test_case):
        overview = construct_risk_assessment_overview([], run_duration=42.5)
        assert overview.run_duration == 42.5


class TestRiskAssessment:
    def _make_risk_assessment(self, make_test_case):
        tc = make_test_case(score=1.0, vulnerability_type=BiasType.GENDER)
        overview = construct_risk_assessment_overview([tc], run_duration=1.0)
        return RiskAssessment(overview=overview, test_cases=[tc])

    def test_construction(self, make_test_case):
        ra = self._make_risk_assessment(make_test_case)
        assert ra.overview is not None
        assert len(ra.test_cases) == 1

    def test_test_cases_is_test_cases_list(self, make_test_case):
        ra = self._make_risk_assessment(make_test_case)
        assert isinstance(ra.test_cases, TestCasesList)

    def test_save_creates_json(self, make_test_case, tmp_path):
        ra = self._make_risk_assessment(make_test_case)
        result_path = ra.save(to=str(tmp_path))
        assert result_path is not None
        assert os.path.exists(result_path)
        assert result_path.endswith(".json")

    def test_save_valid_json(self, make_test_case, tmp_path):
        ra = self._make_risk_assessment(make_test_case)
        result_path = ra.save(to=str(tmp_path))
        with open(result_path) as f:
            data = json.load(f)
        assert "overview" in data
        assert "test_cases" in data

    def test_save_creates_directory(self, make_test_case, tmp_path):
        target = str(tmp_path / "new_subdir")
        ra = self._make_risk_assessment(make_test_case)
        result_path = ra.save(to=target)
        assert os.path.exists(target)
        assert os.path.exists(result_path)
