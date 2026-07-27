#!/usr/bin/env python3
"""Lifecycle and mapping fixtures for normative requirement evidence."""

from __future__ import annotations

import copy
import sys
import tempfile
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import requirements_lib as lib  # noqa: E402
import requirements_test_support as support  # noqa: E402

assert_fails = support.assert_fails
bind = support.bind
checker = support.checker
inputs = support.inputs
requirement = support.requirement


def test_obsolete_authority_as_current_fails() -> None:
    policy, ledger, register = inputs()
    broken_policy = copy.deepcopy(policy)
    broken_ledger = copy.deepcopy(ledger)
    source = next(
        item for item in broken_ledger["rfcs"] if item["number"] == 8174
    )
    source["lifecycle"] = "legacy"
    bind(broken_policy, broken_ledger, register)
    assert_fails(
        "treats obsolete authority as current",
        checker.build_matrix,
        broken_policy,
        broken_ledger,
        register,
    )


def test_duplicate_id_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    broken["requirements"].append(copy.deepcopy(broken["requirements"][0]))
    assert_fails(
        "duplicate stable IDs",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_invalid_id_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    broken["requirements"][0]["id"] = "unstable"
    assert_fails(
        "invalid stable requirement ID",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_absent_owner_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    broken["requirements"][0]["owner"] = "9.9.9"
    assert_fails(
        "absent or unknown owner",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_unknown_decision_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    broken["requirements"][0]["decision_ids"] = ["missing.surface"]
    assert_fails(
        "references unknown decisions",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_missing_target_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    broken["requirements"][0]["targets"] = []
    assert_fails(
        "requires exactly one target",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_lifecycle_target_mismatch_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    broken["requirements"][0]["targets"][0]["kind"] = "planned-symbol"
    assert_fails(
        "target incompatible with lifecycle",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_missing_actual_symbol_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    broken["requirements"][0]["targets"][0][
        "target"
    ] = "scripts/check-requirements.py#not_a_symbol"
    assert_fails(
        "actual target anchor is missing",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_tested_lifecycle_requires_actual_test() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    item = requirement(broken, "BRY-REQ-STD-0002")
    item["tests"][0]["status"] = "planned"
    assert_fails(
        "lifecycle requires an actual test",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_missing_actual_test_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    item = requirement(broken, "BRY-REQ-STD-0002")
    item["tests"][0]["target"] = "scripts/not-present.py#missing"
    assert_fails(
        "actual target is missing",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_premature_evidence_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    item = requirement(broken, "BRY-REQ-STD-0003")
    item["evidence"] = ["requirements/policy.json#schema"]
    assert_fails(
        "premature evidence",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_evidenced_lifecycle_requires_evidence() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    broken["requirements"][0]["evidence"] = []
    assert_fails(
        "evidenced lifecycle lacks evidence",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_silently_weakened_should_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    item = requirement(broken, "BRY-REQ-STD-0002")
    item["decision"] = "deviate"
    item["deviation_rationale"] = "too short"
    assert_fails(
        "silently weakened SHOULD",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_must_cannot_deviate() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    item = requirement(broken, "BRY-REQ-STD-0004")
    item["decision"] = "deviate"
    item["deviation_rationale"] = (
        "A deliberately long fixture rationale that still cannot weaken MUST."
    )
    assert_fails(
        "cannot deviate from MUST",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_illegal_lifecycle_transition_fails() -> None:
    assert_fails(
        "illegal requirement lifecycle transition",
        checker.validate_transition,
        "planned",
        "evidenced",
    )


def test_all_declared_lifecycle_transitions_pass() -> None:
    for previous, current_values in lib.TRANSITIONS.items():
        for current in current_values:
            checker.validate_transition(previous, current)


def test_protocol_implementation_claim_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    item = requirement(broken, "BRY-REQ-TLS-0001")
    item["lifecycle"] = "implemented"
    item["targets"][0]["kind"] = "actual-symbol"
    item["targets"][0]["target"] = "scripts/check-requirements.py#build_matrix"
    assert_fails(
        "prematurely claims protocol implementation",
        checker.build_matrix,
        broken,
        ledger,
        register,
    )


def test_bidirectional_indexes_are_complete() -> None:
    matrix, indexes = checker.build_matrix()
    by_requirement = indexes["by_requirement"]
    reverse = indexes["requirements_by"]
    for item in matrix["requirements"]:
        requirement_id = item["id"]
        assert requirement_id in by_requirement
        for category, values in by_requirement[requirement_id].items():
            for value in values:
                assert requirement_id in reverse[category][value]


def test_duplicate_json_key_fails() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "duplicate.json"
        path.write_text('{"schema": 1, "schema": 2}', encoding="utf-8")
        assert_fails("duplicate JSON key", lib.read_json, path)


def main() -> int:
    count = support.run_tests(globals())
    print(f"{count} normative-requirement lifecycle tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
