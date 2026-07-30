#!/usr/bin/env python3
"""History and semantic-link fixtures for normative requirements."""

from __future__ import annotations

import copy
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import requirements_history as history  # noqa: E402
import requirements_test_support as support  # noqa: E402

assert_fails = support.assert_fails
checker = support.checker
inputs = support.inputs
requirement = support.requirement


def row(
    lifecycle: str = "planned",
    revision: int = 1,
    statement: str = "original",
) -> dict:
    return {
        "id": "BRY-REQ-TEST-0001",
        "lifecycle": lifecycle,
        "revision": revision,
        "scope": "protocol",
        "statement": statement,
    }


def baseline(*rows: dict) -> dict:
    return {"requirements": list(rows), "schema": 1}


def test_production_builder_enforces_git_history() -> None:
    matrix, _ = checker.build_matrix()
    assert len(matrix["requirements"]) == 46


def test_illegal_history_transition_fails() -> None:
    assert_fails(
        "illegal requirement lifecycle transition",
        history.validate,
        baseline(row()),
        [row(lifecycle="evidenced", revision=2)],
        checker.validate_transition,
    )


def test_changed_content_requires_revision_increment() -> None:
    assert_fails(
        "revision must be 2",
        history.validate,
        baseline(row()),
        [row(statement="changed")],
        checker.validate_transition,
    )


def test_changed_content_with_revision_increment_passes() -> None:
    history.validate(
        baseline(row()),
        [row(revision=2, statement="changed")],
        checker.validate_transition,
    )


def test_unchanged_content_rejects_revision_increment() -> None:
    assert_fails(
        "revision must be 1",
        history.validate,
        baseline(row()),
        [row(revision=2)],
        checker.validate_transition,
    )


def test_released_requirement_removal_fails() -> None:
    assert_fails(
        "released requirement IDs cannot disappear",
        history.validate,
        baseline(row()),
        [],
        checker.validate_transition,
    )


def test_new_requirement_must_begin_at_revision_one() -> None:
    assert_fails(
        "must begin at revision 1",
        history.validate,
        baseline(),
        [row(revision=2)],
        checker.validate_transition,
    )


def test_bootstrap_requires_revision_one() -> None:
    assert_fails(
        "bootstrap requirements must begin at revision 1",
        history.validate,
        None,
        [row(revision=2)],
        checker.validate_transition,
    )


def test_unrelated_iana_mapping_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    requirement(broken, "BRY-REQ-TLS-0001")["decision_ids"] = ["legacy.ssl2"]
    assert_fails(
        "does not include its exact IANA source surface",
        checker.build_matrix,
        broken,
        ledger,
        register,
        False,
    )


def test_unrelated_additional_iana_mapping_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    requirement(broken, "BRY-REQ-TLS-0001")["decision_ids"].append(
        "legacy.ssl2"
    )
    assert_fails(
        "links an unrelated surface",
        checker.build_matrix,
        broken,
        ledger,
        register,
        False,
    )


def test_iana_lifecycle_disposition_mismatch_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    item = requirement(broken, "BRY-REQ-TLS-0001")
    item["applicability"] = "delegate"
    item["decision"] = "delegate"
    item["lifecycle"] = "caller-owned"
    item["targets"] = [
        {"kind": "boundary", "target": "boundary:fixture"}
    ]
    assert_fails(
        "lifecycle conflicts with surface disposition",
        checker.build_matrix,
        broken,
        ledger,
        register,
        False,
    )


def test_iana_owner_mismatch_fails() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    requirement(broken, "BRY-REQ-TLS-0001")["owner"] = "0.68.0"
    assert_fails(
        "owner conflicts with linked surfaces",
        checker.build_matrix,
        broken,
        ledger,
        register,
        False,
    )


def test_reviewed_global_mapping_requires_rationale() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    requirement(broken, "BRY-REQ-STD-0001")["mapping_rationale"] = ""
    assert_fails(
        "global mapping requires reviewed rationale",
        checker.build_matrix,
        broken,
        ledger,
        register,
        False,
    )


def test_protocol_requirement_cannot_use_reviewed_global() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    item = requirement(broken, "BRY-REQ-LEG-0001")
    item["decision_ids"] = ["legacy.ssl2"]
    item["mapping_scope"] = "reviewed-global"
    item["mapping_rationale"] = (
        "This deliberately invalid rationale cannot let a protocol requirement "
        "escape exact-source validation."
    )
    assert_fails(
        "protocol requirements require exact-source mapping",
        checker.build_matrix,
        broken,
        ledger,
        register,
        False,
    )


def test_reviewed_global_mapping_requires_rfc_source() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    item = requirement(broken, "BRY-REQ-IANA-0001")
    item["source"] = {
        "kind": "iana",
        "surface_id": item["decision_ids"][0],
    }
    item["mapping_rationale"] = (
        "This deliberately invalid fixture attempts a global IANA mapping."
    )
    assert_fails(
        "global mapping requires an RFC source",
        checker.build_matrix,
        broken,
        ledger,
        register,
        False,
    )


def test_released_requirement_scope_cannot_change() -> None:
    changed = row(revision=2, statement="changed")
    changed["scope"] = "governance"
    assert_fails(
        "released scope cannot change",
        history.validate,
        baseline(row()),
        [changed],
        checker.validate_transition,
    )


def test_exact_rfc_mapping_rejects_unrelated_surface() -> None:
    policy, ledger, register = inputs()
    broken = copy.deepcopy(policy)
    requirement(broken, "BRY-REQ-LEG-0001")["decision_ids"] = ["legacy.ssl2"]
    assert_fails(
        "unrelated to its RFC source",
        checker.build_matrix,
        broken,
        ledger,
        register,
        False,
    )


def test_private_use_exact_mapping_is_caller_owned() -> None:
    policy, ledger, register = inputs()
    changed = copy.deepcopy(policy)
    item = requirement(changed, "BRY-REQ-IANA-0003")
    item["mapping_scope"] = "exact-source"
    item["mapping_rationale"] = None
    item["source"] = {
        "kind": "iana",
        "surface_id": item["decision_ids"][0],
    }
    checker.build_matrix(changed, ledger, register, previous=False)


def main() -> int:
    count = support.run_tests(globals())
    print(f"{count} requirement-history and semantic-link tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
