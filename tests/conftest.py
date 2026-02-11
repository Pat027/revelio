"""Shared fixtures for revelio test suite."""

import pytest
from enum import Enum
from revelio.vulnerabilities.bias import BiasType
from revelio.test_case.test_case import RTTestCase, RTTurn


@pytest.fixture
def sample_vulnerability_type():
    """Return a BiasType enum value for reuse across tests."""
    return BiasType.GENDER


@pytest.fixture
def make_turn():
    """Factory fixture to create RTTurn instances."""

    def _make_turn(role="user", content="hello", turn_level_attack=None):
        turn = RTTurn(role=role, content=content)
        if turn_level_attack is not None:
            turn.turn_level_attack = turn_level_attack
        return turn

    return _make_turn


@pytest.fixture
def make_test_case(sample_vulnerability_type):
    """Factory fixture to create RTTestCase instances."""

    def _make_test_case(
        vulnerability="Bias",
        vulnerability_type=None,
        input="test input",
        actual_output="test output",
        score=None,
        error=None,
        attack_method=None,
        risk_category=None,
    ):
        vtype = vulnerability_type or sample_vulnerability_type
        return RTTestCase(
            vulnerability=vulnerability,
            vulnerability_type=vtype,
            input=input,
            actual_output=actual_output,
            score=score,
            error=error,
            attack_method=attack_method,
            risk_category=risk_category,
        )

    return _make_test_case
