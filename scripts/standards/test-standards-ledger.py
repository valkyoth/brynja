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


def assert_fails(expected: str, function, *args, **kwargs) -> None:
    try:
        function(*args, **kwargs)
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
    assert len(ledger["rfcs"]) == 104
    assert len(ledger["local_authorities"]) == 18
    assert len(ledger["registries"]) == 8
    assert any(item["number"] == 10024 for item in ledger["rfcs"])
    hybrid = next(
        item
        for item in ledger["blockers"]
        if item["id"] == "ecdhe-ml-kem-groups"
    )
    assert hybrid["status"] == "resolved"
    assert ledger["integrity"]["pin_provenance"]


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


def test_non_https_source_fails() -> None:
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "SOURCES"
        source.write_text("1 http://www.rfc-editor.org/rfc/rfc1.txt role\n")
        assert_fails("unapproved HTTPS", lib.read_source_file, source, int)
    assert_fails(
        "unapproved HTTPS",
        lib.fetch,
        "http://www.rfc-editor.org/rfc-index.xml",
        max_bytes=1,
    )


def test_unallowlisted_registry_url_fails() -> None:
    policy, rfcs, local, _, _ = load_inputs()
    broken = copy.deepcopy(policy)
    broken["registry"][0]["url"] = "https://example.com/registry.xml"
    assert_fails(
        "not allowlisted",
        checker.validate_policy,
        broken,
        rfcs,
        local,
    )


def test_missing_upstream_pin_fails() -> None:
    policy, rfcs, local, _, _ = load_inputs()
    broken = copy.deepcopy(policy)
    del broken["registry"][0]["expected_sha256"]
    assert_fails(
        "requires a pinned SHA-256",
        checker.validate_policy,
        broken,
        rfcs,
        local,
    )


def test_missing_pin_provenance_fails() -> None:
    policy, rfcs, local, _, _ = load_inputs()
    broken = copy.deepcopy(policy)
    broken["review"]["pin_provenance"] = ""
    assert_fails(
        "requires independent pin provenance",
        checker.validate_policy,
        broken,
        rfcs,
        local,
    )


def test_pin_mismatch_fails() -> None:
    assert_fails(
        "does not match pinned",
        lib.verify_sha256,
        b"upstream bytes",
        "0" * 64,
        "fixture",
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


def test_hybrid_resolution_cannot_admit_drafts() -> None:
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


def test_official_errata_drift_fails() -> None:
    _, rfcs, _, _, errata = load_inputs()
    broken = copy.deepcopy(errata)
    broken["records"][0]["section"] += "-changed"
    assert_fails(
        "does not match pinned",
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


def test_xml_dtd_and_oversize_fail_before_parse() -> None:
    entity = b"""<!DOCTYPE registry [
    <!ENTITY x "expansion">
    ]><registry xmlns="http://www.iana.org/assignments" id="expected">&x;</registry>
    """
    assert_fails(
        "DTD and entity declarations are forbidden",
        lib.validate_iana_snapshot,
        entity,
        "expected",
    )
    oversized = b"x" * (lib.MAX_RFC_INDEX_BYTES + 1)
    assert_fails(
        "XML exceeds",
        lib.project_rfc_index,
        oversized,
        set(),
    )


def test_fetch_response_cap_fails() -> None:
    class Response:
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        @staticmethod
        def geturl():
            return "https://www.rfc-editor.org/rfc-index.xml"

        @staticmethod
        def read(size):
            return b"x" * size

    original = lib.HTTPS_OPENER.open
    lib.HTTPS_OPENER.open = lambda *_args, **_kwargs: Response()
    try:
        assert_fails(
            "response exceeds 8 bytes",
            lib.fetch,
            "https://www.rfc-editor.org/rfc-index.xml",
            max_bytes=8,
        )
    finally:
        lib.HTTPS_OPENER.open = original


def test_redirect_downgrade_fails() -> None:
    handler = lib.HttpsOnlyRedirectHandler()
    assert_fails(
        "unapproved HTTPS",
        handler.redirect_request,
        None,
        None,
        302,
        "Found",
        {},
        "http://www.rfc-editor.org/rfc-index.xml",
    )


def test_lock_scripts_cannot_generate_pins() -> None:
    for name in ("lock-rfcs.sh", "lock-local-references.sh"):
        text = (lib.ROOT / "scripts" / "standards" / name).read_text(
            encoding="utf-8"
        )
        assert "sha256sum" not in text
        assert "never computes or replaces the trust pins" in text


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


def test_manifest_only_mode_allows_absent_local_bytes() -> None:
    with tempfile.TemporaryDirectory() as directory:
        checker.check_hashes(
            {"local.pdf": lib.sha256(b"reviewed")},
            Path(directory),
            {"local.pdf"},
            "local fixture",
            verify_files=False,
        )


def test_partial_local_cache_fails_when_verifying() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "one.pdf").write_bytes(b"one")
        manifest = {
            "one.pdf": lib.sha256(b"one"),
            "two.pdf": lib.sha256(b"two"),
        }
        assert_fails(
            "pinned file is missing: two.pdf",
            checker.check_hashes,
            manifest,
            root,
            set(manifest),
            "local fixture",
            verify_files=True,
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


def test_errata_parser_requires_one_authoritative_outcome() -> None:
    empty = b'<p class="alert alert-info">No matching errata found.</p>'
    assert lib.parse_errata(empty, 1234) == []
    for fixture in (
        b"<html><body>maintenance</body></html>",
        b"<html><body>Please log in</body></html>",
        b"<html><body>Request blocked by WAF</body></html>",
        empty + empty,
    ):
        assert_fails(
            "errata response",
            lib.parse_errata,
            fixture,
            1234,
        )
    assert_fails(
        "errata table row",
        lib.parse_errata,
        b"<h2>Reported (1)</h2><table><tr><td>incomplete</td></tr></table>",
        1234,
    )
    record = b"""
    <h2>Verified (1)</h2><table><tr>
    <td>RFC1234 (42)</td><td>7</td><td>Technical</td><td>source</td>
    <td>person</td><td>TXT</td><td>2026-01-02</td></tr></table>
    """
    assert_fails("contradictory", lib.parse_errata, record + empty, 1234)
    assert_fails("duplicate records", lib.parse_errata, record + record, 1234)


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
