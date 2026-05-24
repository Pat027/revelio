"""Regression guard for the vulnerability/metric consolidation refactor.

For every exported vulnerability, asserts that ``_get_metric()`` still returns
the same metric class with the same ``purpose`` / category attributes it
produced before the refactor. The expected values are frozen in
``tests/_metric_baseline.json`` (captured from the pre-refactor code).

``_get_metric`` constructs a metric, which calls ``initialize_model`` and
therefore requires ``OPENAI_API_KEY`` to merely *exist* (it is never used for a
real request here), so a dummy key is set for the module.
"""

import json
import os
import pathlib

import pytest

os.environ.setdefault("OPENAI_API_KEY", "sk-dummy-for-offline-tests")

import revelio.vulnerabilities as V

_BASELINE = json.loads(
    (pathlib.Path(__file__).parent / "_metric_baseline.json").read_text()
)


def _instantiate(name):
    cls = getattr(V, name)
    if name == "CustomVulnerability":
        return cls(name="MyVuln", criteria="some criteria", types=["t1", "t2"])
    return cls()


@pytest.mark.parametrize("name", sorted(_BASELINE))
def test_get_metric_matches_baseline(name):
    expected = _BASELINE[name]
    inst = _instantiate(name)

    assert inst.get_name() == expected["vuln_name"]
    assert sorted(inst.get_values()) == expected["types"]

    types = list(inst.types)
    inst.evaluation_model = "gpt-4o"
    metric = inst._get_metric(types[0])

    assert type(metric).__name__ == expected["metric_class"]
    assert hasattr(metric, "purpose") == expected["metric_has_purpose"]
    assert getattr(metric, "__name__", None) == expected["metric_name"]

    cat_attrs = {
        k: v
        for k, v in vars(metric).items()
        if k.endswith(("_category", "_type")) and isinstance(v, str)
    }
    assert cat_attrs == expected["metric_category_attrs"]
