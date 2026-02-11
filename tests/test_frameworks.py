"""Tests for all 6 framework classes."""

import pytest
from revelio.frameworks import (
    AISafetyFramework,
    NIST,
    OWASPTop10,
    OWASP_ASI_2026,
    MITRE,
    Aegis,
    BeaverTails,
)
from revelio.vulnerabilities.base_vulnerability import BaseVulnerability
from revelio.attacks.base_attack import BaseAttack


# Frameworks that populate vulnerabilities/attacks at init time
STANDARD_FRAMEWORKS = [
    (NIST, "NIST AI Risk Management Framework (AI RMF)"),
    (OWASPTop10, None),
    (OWASP_ASI_2026, None),
    (MITRE, None),
]

# Dataset-driven frameworks: vulnerabilities/attacks start empty (populated by load_dataset())
DATASET_FRAMEWORKS = [
    (Aegis, "Aegis"),
    (BeaverTails, "BeaverTails"),
]

ALL_FRAMEWORKS = STANDARD_FRAMEWORKS + DATASET_FRAMEWORKS


class TestAllFrameworks:
    @pytest.mark.parametrize("cls,_", ALL_FRAMEWORKS)
    def test_default_instantiation(self, cls, _):
        fw = cls()
        assert fw is not None

    @pytest.mark.parametrize("cls,_", ALL_FRAMEWORKS)
    def test_name_is_nonempty_string(self, cls, _):
        fw = cls()
        assert isinstance(fw.name, str)
        assert len(fw.name) > 0


class TestStandardFrameworks:
    @pytest.mark.parametrize("cls,_", STANDARD_FRAMEWORKS)
    def test_vulnerabilities_is_list(self, cls, _):
        fw = cls()
        assert isinstance(fw.vulnerabilities, list)
        assert len(fw.vulnerabilities) > 0

    @pytest.mark.parametrize("cls,_", STANDARD_FRAMEWORKS)
    def test_vulnerabilities_are_base_vulnerability(self, cls, _):
        fw = cls()
        for v in fw.vulnerabilities:
            assert isinstance(v, BaseVulnerability)

    @pytest.mark.parametrize("cls,_", STANDARD_FRAMEWORKS)
    def test_attacks_is_list(self, cls, _):
        fw = cls()
        assert isinstance(fw.attacks, list)
        assert len(fw.attacks) > 0

    @pytest.mark.parametrize("cls,_", STANDARD_FRAMEWORKS)
    def test_attacks_are_base_attack(self, cls, _):
        fw = cls()
        for a in fw.attacks:
            assert isinstance(a, BaseAttack)


class TestDatasetFrameworks:
    """Aegis and BeaverTails are dataset-driven: vulns/attacks start empty."""

    @pytest.mark.parametrize("cls,expected_name", DATASET_FRAMEWORKS)
    def test_vulnerabilities_starts_empty(self, cls, expected_name):
        fw = cls()
        assert isinstance(fw.vulnerabilities, list)
        assert len(fw.vulnerabilities) == 0

    @pytest.mark.parametrize("cls,expected_name", DATASET_FRAMEWORKS)
    def test_attacks_starts_empty(self, cls, expected_name):
        fw = cls()
        assert isinstance(fw.attacks, list)
        assert len(fw.attacks) == 0

    @pytest.mark.parametrize("cls,expected_name", DATASET_FRAMEWORKS)
    def test_has_dataset_flag(self, cls, expected_name):
        fw = cls()
        assert fw._has_dataset is True

    @pytest.mark.parametrize("cls,expected_name", DATASET_FRAMEWORKS)
    def test_get_name(self, cls, expected_name):
        fw = cls()
        assert fw.get_name() == expected_name


class TestNISTSpecific:
    def test_default_categories(self):
        fw = NIST()
        assert fw.categories == [
            "measure_1",
            "measure_2",
            "measure_3",
            "measure_4",
        ]

    def test_custom_categories_subset(self):
        fw = NIST(categories=["measure_1", "measure_3"])
        assert fw.categories == ["measure_1", "measure_3"]
        assert len(fw.vulnerabilities) > 0
        assert len(fw.attacks) > 0

    def test_single_category(self):
        fw = NIST(categories=["measure_2"])
        assert len(fw.categories) == 1
        assert len(fw.vulnerabilities) > 0

    def test_risk_categories_populated(self):
        fw = NIST()
        assert isinstance(fw.risk_categories, list)
        assert len(fw.risk_categories) > 0

    def test_get_name(self):
        fw = NIST()
        assert fw.get_name() == "NIST AI Risk Management Framework (AI RMF)"

    def test_fewer_categories_means_fewer_vulns(self):
        fw_all = NIST()
        fw_one = NIST(categories=["measure_1"])
        assert len(fw_one.vulnerabilities) <= len(fw_all.vulnerabilities)
