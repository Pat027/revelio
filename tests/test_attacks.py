"""Tests for all 26 attack classes (21 single-turn + 5 multi-turn)."""

import pytest
from revelio.attacks.base_attack import BaseAttack, Exploitability
from revelio.attacks.single_turn import (
    BaseSingleTurnAttack,
    AdversarialPoetry,
    Base64,
    GrayBox,
    Leetspeak,
    MathProblem,
    Multilingual,
    PromptInjection,
    PromptProbing,
    Roleplay,
    ROT13,
    CharacterStream,
    ContextFlooding,
    EmbeddedInstructionJSON,
    SyntheticContextInjection,
    AuthorityEscalation,
    EmotionalManipulation,
    SystemOverride,
    PermissionEscalation,
    GoalRedirection,
    LinguisticConfusion,
    InputBypass,
    ContextPoisoning,
)
from revelio.attacks.multi_turn import (
    CrescendoJailbreaking,
    LinearJailbreaking,
    TreeJailbreaking,
    SequentialJailbreak,
    BadLikertJudge,
    BaseMultiTurnAttack,
)


# ── Single-turn attacks that can be instantiated with no args ──
SIMPLE_SINGLE_TURN = [
    (AdversarialPoetry, "Adversarial Poetry", Exploitability.HIGH),
    (Base64, "Base64", Exploitability.HIGH),
    (GrayBox, "Gray Box", Exploitability.LOW),
    (Leetspeak, "Leetspeak", Exploitability.HIGH),
    (MathProblem, "Math Problem", Exploitability.LOW),
    (Multilingual, "Multilingual", Exploitability.MEDIUM),
    (PromptInjection, "Prompt Injection", Exploitability.MEDIUM),
    (PromptProbing, "Prompt Probing", Exploitability.MEDIUM),
    (Roleplay, "Roleplay", Exploitability.MEDIUM),
    (ROT13, "ROT-13", Exploitability.HIGH),
    (CharacterStream, "CharacterStream", Exploitability.MEDIUM),
    (ContextFlooding, "ContextFlooding", Exploitability.MEDIUM),
    (EmbeddedInstructionJSON, "EmbeddedInstructionJSON", Exploitability.MEDIUM),
    (AuthorityEscalation, "Authority Escalation", Exploitability.HIGH),
    (EmotionalManipulation, "Emotional Manipulation", Exploitability.HIGH),
    (SystemOverride, "System Override", Exploitability.MEDIUM),
    (PermissionEscalation, "Permission Escalation", Exploitability.MEDIUM),
    (GoalRedirection, "Goal Redirection", Exploitability.MEDIUM),
    (LinguisticConfusion, "Linguistic Confusion", Exploitability.MEDIUM),
    (InputBypass, "Input Bypass", Exploitability.MEDIUM),
    (ContextPoisoning, "Context Poisoning", Exploitability.MEDIUM),
]

# SyntheticContextInjection requires target_information arg
SPECIAL_SINGLE_TURN = [
    (
        SyntheticContextInjection,
        "Synthetic Context Injection",
        Exploitability.HIGH,
        {"target_information": "test target"},
    ),
]

MULTI_TURN = [
    (CrescendoJailbreaking, "Crescendo Jailbreaking", Exploitability.LOW),
    (LinearJailbreaking, "Linear Jailbreaking", Exploitability.LOW),
    (TreeJailbreaking, "Tree Jailbreaking", Exploitability.LOW),
    (SequentialJailbreak, "Sequential Jailbreak", Exploitability.LOW),
    (BadLikertJudge, "Bad Likert Judge", Exploitability.LOW),
]


class TestExploitabilityEnum:
    def test_has_low(self):
        assert Exploitability.LOW.value == "low"

    def test_has_medium(self):
        assert Exploitability.MEDIUM.value == "medium"

    def test_has_high(self):
        assert Exploitability.HIGH.value == "high"

    def test_member_count(self):
        assert len(Exploitability) == 3


class TestBaseSingleTurnAttack:
    def test_is_subclass_of_base_attack(self):
        assert issubclass(BaseSingleTurnAttack, BaseAttack)


class TestBaseMultiTurnAttack:
    def test_is_subclass_of_base_attack(self):
        assert issubclass(BaseMultiTurnAttack, BaseAttack)


class TestSimpleSingleTurnAttacks:
    @pytest.mark.parametrize(
        "cls,expected_name,expected_exploit", SIMPLE_SINGLE_TURN
    )
    def test_instantiation(self, cls, expected_name, expected_exploit):
        attack = cls()
        assert attack is not None

    @pytest.mark.parametrize(
        "cls,expected_name,expected_exploit", SIMPLE_SINGLE_TURN
    )
    def test_get_name(self, cls, expected_name, expected_exploit):
        attack = cls()
        name = attack.get_name()
        assert name == expected_name
        assert len(name) > 0

    @pytest.mark.parametrize(
        "cls,expected_name,expected_exploit", SIMPLE_SINGLE_TURN
    )
    def test_has_weight(self, cls, expected_name, expected_exploit):
        attack = cls()
        assert hasattr(attack, "weight")
        assert isinstance(attack.weight, int)

    @pytest.mark.parametrize(
        "cls,expected_name,expected_exploit", SIMPLE_SINGLE_TURN
    )
    def test_exploitability(self, cls, expected_name, expected_exploit):
        attack = cls()
        assert attack.exploitability == expected_exploit

    @pytest.mark.parametrize(
        "cls,expected_name,expected_exploit", SIMPLE_SINGLE_TURN
    )
    def test_multi_turn_is_false(self, cls, expected_name, expected_exploit):
        attack = cls()
        assert attack.multi_turn is False

    @pytest.mark.parametrize(
        "cls,expected_name,expected_exploit", SIMPLE_SINGLE_TURN
    )
    def test_is_subclass(self, cls, expected_name, expected_exploit):
        assert issubclass(cls, BaseSingleTurnAttack)
        assert issubclass(cls, BaseAttack)


class TestSpecialSingleTurnAttacks:
    @pytest.mark.parametrize(
        "cls,expected_name,expected_exploit,kwargs", SPECIAL_SINGLE_TURN
    )
    def test_instantiation(self, cls, expected_name, expected_exploit, kwargs):
        attack = cls(**kwargs)
        assert attack is not None

    @pytest.mark.parametrize(
        "cls,expected_name,expected_exploit,kwargs", SPECIAL_SINGLE_TURN
    )
    def test_get_name(self, cls, expected_name, expected_exploit, kwargs):
        attack = cls(**kwargs)
        assert attack.get_name() == expected_name

    @pytest.mark.parametrize(
        "cls,expected_name,expected_exploit,kwargs", SPECIAL_SINGLE_TURN
    )
    def test_multi_turn_is_false(
        self, cls, expected_name, expected_exploit, kwargs
    ):
        attack = cls(**kwargs)
        assert attack.multi_turn is False

    @pytest.mark.parametrize(
        "cls,expected_name,expected_exploit,kwargs", SPECIAL_SINGLE_TURN
    )
    def test_exploitability(self, cls, expected_name, expected_exploit, kwargs):
        attack = cls(**kwargs)
        assert attack.exploitability == expected_exploit


class TestMultiTurnAttacks:
    @pytest.mark.parametrize(
        "cls,expected_name,expected_exploit", MULTI_TURN
    )
    def test_instantiation(self, cls, expected_name, expected_exploit):
        attack = cls()
        assert attack is not None

    @pytest.mark.parametrize(
        "cls,expected_name,expected_exploit", MULTI_TURN
    )
    def test_get_name(self, cls, expected_name, expected_exploit):
        attack = cls()
        assert attack.get_name() == expected_name

    @pytest.mark.parametrize(
        "cls,expected_name,expected_exploit", MULTI_TURN
    )
    def test_multi_turn_is_true(self, cls, expected_name, expected_exploit):
        attack = cls()
        assert attack.multi_turn is True

    @pytest.mark.parametrize(
        "cls,expected_name,expected_exploit", MULTI_TURN
    )
    def test_has_weight(self, cls, expected_name, expected_exploit):
        attack = cls()
        assert hasattr(attack, "weight")
        assert isinstance(attack.weight, int)

    @pytest.mark.parametrize(
        "cls,expected_name,expected_exploit", MULTI_TURN
    )
    def test_exploitability(self, cls, expected_name, expected_exploit):
        attack = cls()
        assert attack.exploitability == expected_exploit

    @pytest.mark.parametrize(
        "cls,expected_name,expected_exploit", MULTI_TURN
    )
    def test_is_subclass(self, cls, expected_name, expected_exploit):
        assert issubclass(cls, BaseMultiTurnAttack)
        assert issubclass(cls, BaseAttack)
