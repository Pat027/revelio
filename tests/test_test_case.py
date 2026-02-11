"""Tests for RTTestCase and RTTurn data structures."""

import pytest
from revelio.test_case.test_case import RTTestCase, RTTurn
from revelio.vulnerabilities.bias import BiasType


class TestRTTurn:
    def test_basic_construction(self):
        turn = RTTurn(role="user", content="hello")
        assert turn.role == "user"
        assert turn.content == "hello"

    def test_turn_level_attack_defaults_none(self):
        turn = RTTurn(role="assistant", content="hi")
        assert turn.turn_level_attack is None

    def test_turn_level_attack_set(self):
        turn = RTTurn(role="user", content="test")
        turn.turn_level_attack = "Base64"
        assert turn.turn_level_attack == "Base64"

    def test_repr_without_attack(self):
        turn = RTTurn(role="user", content="hello")
        r = repr(turn)
        assert "RTTurn(" in r
        assert "role=user" in r
        assert "content=hello" in r
        assert "turn_level_attack" not in r

    def test_repr_with_attack(self):
        turn = RTTurn(role="user", content="hello")
        turn.turn_level_attack = "ROT13"
        r = repr(turn)
        assert "turn_level_attack=ROT13" in r


class TestRTTestCase:
    def test_minimal_construction(self):
        tc = RTTestCase(
            vulnerability="Bias",
            vulnerability_type=BiasType.GENDER,
            input="test",
        )
        assert tc.vulnerability == "Bias"

    def test_full_construction(self):
        tc = RTTestCase(
            vulnerability="Bias",
            vulnerability_type=BiasType.GENDER,
            input="test input",
            actual_output="test output",
            attack_method="Prompt Injection",
            risk_category="Responsible AI",
            score=0.8,
            reason="some reason",
            error=None,
            metadata={"key": "value"},
        )
        assert tc.input == "test input"
        assert tc.actual_output == "test output"
        assert tc.attack_method == "Prompt Injection"
        assert tc.score == 0.8
        assert tc.metadata == {"key": "value"}

    def test_optional_fields_default_none(self):
        tc = RTTestCase(
            vulnerability="Bias",
            vulnerability_type=BiasType.GENDER,
        )
        assert tc.input is None
        assert tc.actual_output is None
        assert tc.turns is None
        assert tc.metadata is None
        assert tc.attack_method is None
        assert tc.risk_category is None
        assert tc.score is None
        assert tc.reason is None
        assert tc.error is None

    def test_repr_includes_vulnerability(self):
        tc = RTTestCase(
            vulnerability="Bias",
            vulnerability_type=BiasType.GENDER,
            input="hi",
        )
        r = repr(tc)
        assert "vulnerability=Bias" in r
        assert "vulnerability_type=gender" in r

    def test_repr_includes_set_fields_only(self):
        tc = RTTestCase(
            vulnerability="Bias",
            vulnerability_type=BiasType.GENDER,
            score=0.5,
        )
        r = repr(tc)
        assert "score=0.5" in r
        # Fields not set should not appear
        assert "attack_method" not in r
        assert "error" not in r

    def test_with_turns(self, make_turn):
        turns = [make_turn("user", "hi"), make_turn("assistant", "hello")]
        tc = RTTestCase(
            vulnerability="Bias",
            vulnerability_type=BiasType.GENDER,
            turns=turns,
        )
        assert len(tc.turns) == 2
        assert tc.turns[0].role == "user"
