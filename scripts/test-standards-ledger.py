#!/usr/bin/env python3
"""Positive and broken-fixture tests for the standards source ledger."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import standards_lib as lib  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "check_standards_ledger",
    Path(__file__).with_name("check-standards-ledger.py"),
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load standards ledger checker")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def assert_fails(expected: str, function, *args) -> None:
    try:
        function(*args)
    except RuntimeError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r} in {error!r}") from error
        return
    raise AssertionError("expected validation failure")


def load_inputs() -> tuple[dict, dict, dict, dict, dict]:
    policy = lib.read_policy()
    rfcs = lib.read_source_file(lib.RFC_SOURCES, int)
    local = lib.read_source_file(lib.LOCAL_SOURCES)
    index = json.loads(lib.RFC_INDEX.read_text(encoding="utf-8"))
    errata = json.loads(lib.ERRATA.read_text(encoding="utf-8"))
    return policy, rfcs, local, index, errata


def test_current_repository() -> None:
    ledger = checker.build_ledger()
    assert len(ledger["rfcs"]) == 103
    assert len(ledger["local_authorities"]) == 8
    assert len(ledger["registries"]) == 8


def test_missing_rfc_domain_fails() -> None:
    policy, rfcs, local, _, _ = load_inputs()
    broken = copy.deepcopy(policy)
    broken["domain"][0]["rfcs"].remove(2119)
    assert_fails(
        "cover exactly every locked RFC",
        checker.validate_policy,
        broken,
        rfcs,
        local,
    )


def test_unknown_local_source_fails() -> None:
    policy, rfcs, local, _, _ = load_inputs()
    broken = copy.deepcopy(policy)
    broken["domain"][0]["local"].append("invented.pdf")
    assert_fails(
        "cover exactly every locked local source",
        checker.validate_policy,
        broken,
        rfcs,
        local,
    )


def test_duplicate_lifecycle_fails() -> None:
    policy, rfcs, local, _, _ = load_inputs()
    broken = copy.deepcopy(policy)
    broken["lifecycle"]["legacy"].append(5246)
    assert_fails(
        "multiple lifecycle",
        checker.validate_policy,
        broken,
        rfcs,
        local,
    )


def test_unknown_milestone_fails() -> None:
    policy, rfcs, local, _, _ = load_inputs()
    broken = copy.deepcopy(policy)
    broken["domain"][0]["milestones"].append("9.9.9")
    assert_fails(
        "unknown roadmap milestones",
        checker.validate_policy,
        broken,
        rfcs,
        local,
    )


def test_hybrid_blocker_cannot_be_relaxed() -> None:
    policy, rfcs, local, _, _ = load_inputs()
    broken = copy.deepcopy(policy)
    broken["blocker"][0]["drafts_forbidden"] = False
    assert_fails(
        "drafts_forbidden=True",
        checker.validate_policy,
        broken,
        rfcs,
        local,
    )


def test_unclosed_rfc_relationship_fails() -> None:
    policy, rfcs, _, index, _ = load_inputs()
    broken = copy.deepcopy(policy)
    broken["closure_exclusion"].pop()
    assert_fails(
        "closure differs",
        checker.validate_closure,
        broken,
        index,
        set(rfcs),
    )


def test_stale_rfc_exclusion_fails() -> None:
    policy, rfcs, _, index, _ = load_inputs()
    broken = copy.deepcopy(policy)
    broken["closure_exclusion"].append(
        {
            "source": 2104,
            "relation": "updated-by",
            "target": 9999,
            "reason": "fixture",
        }
    )
    assert_fails(
        "closure differs",
        checker.validate_closure,
        broken,
        index,
        set(rfcs),
    )


def test_obsoleted_current_source_fails() -> None:
    policy, rfcs, _, index, _ = load_inputs()
    broken = copy.deepcopy(index)
    broken["rfcs"]["2104"]["obsoleted_by"] = [9999]
    assert_fails(
        "current RFC 2104 is obsoleted",
        checker.validate_closure,
        policy,
        broken,
        set(rfcs),
    )


def test_incomplete_errata_coverage_fails() -> None:
    _, rfcs, _, _, errata = load_inputs()
    broken = copy.deepcopy(errata)
    broken["reviewed_rfcs"].pop()
    assert_fails(
        "cover exactly every locked RFC",
        checker.validate_errata,
        broken,
        set(rfcs),
        lib.read_policy(),
    )


def test_duplicate_erratum_fails() -> None:
    _, rfcs, _, _, errata = load_inputs()
    broken = copy.deepcopy(errata)
    broken["records"].append(copy.deepcopy(broken["records"][0]))
    assert_fails(
        "duplicate or unlocked erratum",
        checker.validate_errata,
        broken,
        set(rfcs),
        lib.read_policy(),
    )


def test_errata_decision_drift_fails() -> None:
    _, rfcs, _, _, errata = load_inputs()
    broken = copy.deepcopy(errata)
    broken["records"][0]["disposition"] = "ignore"
    assert_fails(
        "invalid reviewed decision",
        checker.validate_errata,
        broken,
        set(rfcs),
        lib.read_policy(),
    )


def test_unknown_errata_status_fails() -> None:
    assert_fails("unknown errata status", lib.errata_disposition, "Pending")


def test_wrong_iana_registry_fails() -> None:
    data = (
        b'<registry xmlns="http://www.iana.org/assignments" id="wrong">'
        b"<title>Wrong</title></registry>"
    )
    assert_fails(
        "snapshot identifies",
        lib.validate_iana_snapshot,
        data,
        "expected",
    )


def test_checksum_set_and_bytes_fail_closed() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "one").write_bytes(b"correct")
        digest = lib.sha256(b"correct")
        checker.check_hashes({"one": digest}, root, {"one"}, "fixture")
        assert_fails(
            "checksum set differs",
            checker.check_hashes,
            {"one": digest},
            root,
            {"one", "two"},
            "fixture",
        )
        (root / "one").write_bytes(b"changed")
        assert_fails(
            "checksum mismatch",
            checker.check_hashes,
            {"one": digest},
            root,
            {"one"},
            "fixture",
        )


def test_errata_parser_uses_authoritative_identity() -> None:
    fixture = b"""
    <h2>Verified (1)</h2><table><tr>
    <td>RFC1234 (<a href="/eid42/">42</a>)</td>
    <td>7</td><td>Technical</td><td>source</td><td>person</td>
    <td>TXT</td><td>2026-01-02</td></tr></table>
    """
    records = lib.parse_errata(fixture, 1234)
    assert records == [
        {
            "date_reported": "2026-01-02",
            "id": 42,
            "rfc": 1234,
            "section": "7",
            "status": "Verified",
            "type": "Technical",
            "url": "https://errata.rfc-editor.org/eid42/",
        }
    ]


def main() -> int:
    tests = [
        value
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        test()
    print(f"{len(tests)} standards-ledger tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
