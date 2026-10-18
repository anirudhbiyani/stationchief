import json
import pathlib
import re

import pytest

SIGMA = pathlib.Path(__file__).parent.parent / "sigma"
GOLDEN = pathlib.Path(__file__).parent / "golden"

# Top-level OCSF keys our events emit. A dotted token starting with one of these
# is a field reference; anything else in the file is prose.
OCSF_ROOTS = {
    "actor", "api", "application", "device", "enrichments", "file",
    "http_request", "metadata", "observables", "process", "url",
}
PATH = re.compile(r"\b([a-z_]+(?:\.[a-z_0-9]+)+)\b")


def golden_paths():
    """Every dotted path present in any golden event, list indices flattened."""
    paths = set()

    def walk(node, prefix):
        if isinstance(node, dict):
            for key, value in node.items():
                child = f"{prefix}.{key}" if prefix else key
                paths.add(child)
                walk(value, child)
        elif isinstance(node, list):
            for item in node:
                walk(item, prefix)

    for path in GOLDEN.rglob("*.ocsf.json"):
        walk(json.loads(path.read_text()), "")
    return paths


def rule_files():
    files = sorted(SIGMA.glob("*.yml"))
    assert files, "no sigma rules found"
    return files


@pytest.mark.parametrize("rule", rule_files(), ids=lambda p: p.name)
def test_rule_has_the_required_sections(rule):
    text = rule.read_text()
    for section in ("title:", "id:", "status:", "logsource:", "detection:", "level:"):
        assert section in text, f"{rule.name} is missing {section}"


@pytest.mark.parametrize("rule", rule_files(), ids=lambda p: p.name)
def test_every_field_reference_exists_in_our_output(rule):
    known = golden_paths()
    referenced = {
        match
        for match in PATH.findall(rule.read_text())
        if match.split(".")[0] in OCSF_ROOTS
    }
    assert referenced, f"{rule.name} references no OCSF field"
    unknown = sorted(referenced - known)
    assert not unknown, (
        f"{rule.name} references fields stationchief never emits: {unknown}"
    )


def _documents():
    for rule in rule_files():
        for doc in rule.read_text().split("\n---\n"):
            yield rule.name, doc


def _correlated_rules(doc):
    block = re.search(r"^  rules:\n((?:    - \S+\n)+)", doc, re.M)
    return re.findall(r"- (\S+)", block.group(1)) if block else []


def test_correlations_reference_defined_rules_and_temporal_ones_need_two():
    defined = set()
    for _, doc in _documents():
        if "correlation:" not in doc:
            defined.update(re.findall(r"^(?:id|name):\s*(\S+)", doc, re.M))
    correlations = [(name, doc) for name, doc in _documents() if "correlation:" in doc]
    assert correlations
    for name, doc in correlations:
        rules = _correlated_rules(doc)
        assert rules and set(rules) <= defined, f"{name} references undefined rules {rules}"
        kind = re.search(r"^  type:\s*(\S+)", doc, re.M).group(1)
        if kind in ("temporal", "temporal_ordered"):
            # A temporal correlation over one rule fires on any single event.
            assert len(set(rules)) >= 2, f"{name}: {kind} correlation over one rule"


def test_rule_ids_are_unique():
    ids = [
        re.search(r"^id:\s*(\S+)", rule.read_text(), re.M).group(1)
        for rule in rule_files()
    ]
    assert len(ids) == len(set(ids))
