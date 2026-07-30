#!/usr/bin/env python3
"""Positive and broken-fixture tests for protocol-surface decisions."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import standards_lib as standards  # noqa: E402
import surface_lib as lib  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "check_protocol_surfaces",
    Path(__file__).with_name("check-protocol-surfaces.py"),
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load protocol-surface checker")
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


def inputs() -> tuple[dict, dict, list[dict]]:
    policy = lib.read_json(lib.POLICY)
    ledger = lib.read_json(standards.LEDGER)
    projected = []
    collections = {entry["id"]: entry for entry in ledger["registries"]}
    for collection_id, collection in sorted(collections.items()):
        projected.append(
            lib.project_collection(
                collection,
                (
                    standards.IANA_DIRECTORY / f"{collection_id}.xml"
                ).read_bytes(),
            )
        )
    return policy, ledger, projected


def bind(policy: dict, ledger: dict) -> None:
    policy["source_ledger_sha256"] = standards.sha256(
        standards.json_bytes(ledger)
    )


def test_current_repository() -> None:
    register = checker.build_register()
    assert register["schema"] == 2
    assert len(register["surfaces"]) == 4409
    assert not any(
        surface["disposition"] == "implemented"
        for surface in register["surfaces"]
    )
    assert standards.json_bytes(register) == lib.REGISTER.read_bytes()
    assert lib.render_coverage(register) == lib.COVERAGE.read_bytes()


def test_transport_milestones_are_exact_and_unique() -> None:
    register = checker.build_register()
    transport = [
        surface
        for surface in register["surfaces"]
        if "requirement_id" in surface
    ]
    assert len(transport) == 63
    assert len({surface["owner"] for surface in transport}) == 63
    assert len({surface["requirement_id"] for surface in transport}) == 63
    assert {surface["domain"] for surface in transport} == {
        "dtls",
        "quic",
        "tls",
        "tls12",
        "tls13",
    }


def test_transport_policy_binding_drift_fails() -> None:
    policy, ledger, _projected = inputs()
    transport = checker.load_transport_policies()
    transport[0]["source_ledger_sha256"] = "0" * 64
    assert_fails(
        "transport policy is not bound",
        checker.build_register,
        policy,
        ledger,
        transport,
    )


def test_duplicate_transport_surface_fails() -> None:
    policy, ledger, _projected = inputs()
    transport = checker.load_transport_policies()
    transport[1]["surface"][0]["id"] = transport[0]["surface"][0]["id"]
    assert_fails(
        "duplicate or invalid transport surface ID",
        checker.build_register,
        policy,
        ledger,
        transport,
    )


def test_duplicate_transport_requirement_fails() -> None:
    policy, ledger, _projected = inputs()
    transport = checker.load_transport_policies()
    transport[1]["surface"][0]["requirement_id"] = (
        transport[0]["surface"][0]["requirement_id"]
    )
    assert_fails(
        "duplicate or invalid transport requirement ID",
        checker.build_register,
        policy,
        ledger,
        transport,
    )


def test_generation_is_deterministic() -> None:
    first = standards.json_bytes(checker.build_register())
    second = standards.json_bytes(checker.build_register())
    assert first == second


def test_every_surface_has_complete_decision() -> None:
    register = checker.build_register()
    required = {
        "code_target",
        "disposition",
        "domain",
        "id",
        "kind",
        "normative_sources",
        "owner",
        "rationale",
        "test_target",
    }
    for surface in register["surfaces"]:
        assert required <= set(surface)
        assert surface["disposition"] in lib.DISPOSITIONS
        assert surface["normative_sources"]


def test_mandatory_explicit_decisions() -> None:
    register = checker.build_register()
    dispositions = {
        surface["id"]: surface["disposition"]
        for surface in register["surfaces"]
    }
    expected = {
        "facility.heartbeat": "intentionally-rejected",
        "facility.status-request-v2": "intentionally-rejected",
        "facility.sslkeylogfile.production": "intentionally-rejected",
        "facility.sslkeylogfile.test-support": "future-work",
        "facility.tls13.post-handshake-authentication":
            "intentionally-rejected",
        "facility.external-psk.certificate-authentication":
            "intentionally-rejected",
        "algorithm.legacy-pkcs1-client-signature":
            "intentionally-rejected",
        "format.ml-kem-pkix-credentials": "intentionally-rejected",
        "protocol.hpke.non-base-modes": "intentionally-rejected",
        "format.x509.unsigned": "intentionally-rejected",
        "protocol.quic.version-specific-cryptography": "future-work",
        "facility.certificate-compression": "future-work",
        "facility.unknown-ignorable-extension": "safely-ignored",
    }
    for surface_id, disposition in expected.items():
        assert dispositions[surface_id] == disposition


def test_every_iana_record_is_projected() -> None:
    _, _, projected = inputs()
    expected = sum(
        1 + len(registry["records"])
        for collection in projected
        for registry in collection["registries"]
    )
    register = checker.build_register()
    actual = sum(
        surface["kind"] in {"iana-entry", "iana-registry"}
        for surface in register["surfaces"]
    )
    assert actual == expected == 4298


def test_source_ledger_binding_drift_fails() -> None:
    policy, ledger, projected = inputs()
    broken = copy.deepcopy(ledger)
    broken["rfcs"][0]["status"] = "MUTATED"
    assert_fails(
        "not bound to the current source ledger",
        checker.validate_policy,
        policy,
        broken,
        projected,
    )


def test_missing_collection_fails() -> None:
    policy, ledger, projected = inputs()
    broken = copy.deepcopy(policy)
    broken["collections"].pop()
    assert_fails(
        "cover exactly every IANA collection",
        checker.validate_policy,
        broken,
        ledger,
        projected,
    )


def test_duplicate_collection_fails() -> None:
    policy, ledger, projected = inputs()
    broken = copy.deepcopy(policy)
    broken["collections"].append(copy.deepcopy(broken["collections"][0]))
    assert_fails(
        "cover exactly every IANA collection",
        checker.validate_policy,
        broken,
        ledger,
        projected,
    )


def test_unknown_disposition_fails() -> None:
    policy, ledger, projected = inputs()
    broken = copy.deepcopy(policy)
    broken["decisions"][0]["decision"]["disposition"] = "maybe"
    assert_fails(
        "unknown disposition",
        checker.validate_policy,
        broken,
        ledger,
        projected,
    )


def test_implemented_claim_fails() -> None:
    policy, ledger, _ = inputs()
    broken = copy.deepcopy(policy)
    broken["decisions"][0]["decision"]["disposition"] = "implemented"
    assert_fails(
        "must not classify any surface as implemented",
        checker.build_register,
        broken,
        ledger,
    )


def test_unknown_owner_fails() -> None:
    policy, ledger, projected = inputs()
    broken = copy.deepcopy(policy)
    broken["decisions"][0]["decision"]["owner"] = "9.9.9"
    assert_fails(
        "unknown owner milestone",
        checker.validate_policy,
        broken,
        ledger,
        projected,
    )


def test_unknown_source_fails() -> None:
    policy, ledger, projected = inputs()
    broken = copy.deepcopy(policy)
    broken["decisions"][0]["decision"]["sources"] = ["rfc:1"]
    assert_fails(
        "unknown normative sources",
        checker.validate_policy,
        broken,
        ledger,
        projected,
    )


def test_missing_source_fails() -> None:
    policy, ledger, projected = inputs()
    broken = copy.deepcopy(policy)
    broken["decisions"][0]["decision"]["sources"] = []
    assert_fails(
        "requires normative sources",
        checker.validate_policy,
        broken,
        ledger,
        projected,
    )


def test_invalid_targets_fail() -> None:
    policy, ledger, projected = inputs()
    broken = copy.deepcopy(policy)
    broken["decisions"][0]["decision"]["code_target"] = "../escape.rs"
    assert_fails(
        "invalid repository target",
        checker.validate_policy,
        broken,
        ledger,
        projected,
    )


def test_empty_rationale_fails() -> None:
    policy, ledger, projected = inputs()
    broken = copy.deepcopy(policy)
    broken["decisions"][0]["decision"]["rationale"] = "short"
    assert_fails(
        "requires a review rationale",
        checker.validate_policy,
        broken,
        ledger,
        projected,
    )


def test_duplicate_semantic_id_fails() -> None:
    policy, ledger, projected = inputs()
    broken = copy.deepcopy(policy)
    broken["decisions"].append(copy.deepcopy(broken["decisions"][0]))
    assert_fails(
        "duplicate semantic decision IDs",
        checker.validate_policy,
        broken,
        ledger,
        projected,
    )


def test_unknown_registry_rule_fails() -> None:
    policy, ledger, projected = inputs()
    broken = copy.deepcopy(policy)
    broken["collections"][0]["registry_rules"][0]["ids"] = ["invented"]
    assert_fails(
        "rules reference unknown registries",
        checker.validate_policy,
        broken,
        ledger,
        projected,
    )


def test_overlapping_registry_rule_fails() -> None:
    policy, ledger, projected = inputs()
    broken = copy.deepcopy(policy)
    first = broken["collections"][0]["registry_rules"][0]["ids"][0]
    broken["collections"][0]["registry_rules"][1]["ids"].append(first)
    assert_fails(
        "duplicate registry rules",
        checker.validate_policy,
        broken,
        ledger,
        projected,
    )


def test_unmatched_override_fails() -> None:
    policy, ledger, projected = inputs()
    broken = copy.deepcopy(policy)
    broken["entry_overrides"][0]["selector"]["equals"] = "not-present"
    assert_fails(
        "must match exactly one record",
        checker.validate_policy,
        broken,
        ledger,
        projected,
    )


def test_duplicate_override_fails() -> None:
    policy, ledger, projected = inputs()
    broken = copy.deepcopy(policy)
    broken["entry_overrides"].append(
        copy.deepcopy(broken["entry_overrides"][0])
    )
    assert_fails(
        "duplicate entry override selector",
        checker.validate_policy,
        broken,
        ledger,
        projected,
    )


def test_policy_classification_drift_changes_register() -> None:
    policy, ledger, _ = inputs()
    original = standards.json_bytes(checker.build_register(policy, ledger))
    changed = copy.deepcopy(policy)
    changed["decisions"][0]["decision"]["disposition"] = "intentionally-rejected"
    updated = standards.json_bytes(checker.build_register(changed, ledger))
    assert original != updated


def test_snapshot_hash_drift_fails() -> None:
    policy, ledger, _ = inputs()
    broken = copy.deepcopy(ledger)
    broken["registries"][0]["sha256"] = "0" * 64
    bind(policy, broken)
    assert_fails(
        "differs from source ledger",
        checker.build_register,
        policy,
        broken,
    )


def test_duplicate_nested_registry_fails() -> None:
    collection = {
        "id": "fixture",
        "sha256": standards.sha256(b"fixture"),
        "url": "https://www.iana.org/assignments/quic/quic.xml",
    }
    xml = b"""<registry xmlns="http://www.iana.org/assignments" id="fixture">
    <registry id="same"><title>One</title></registry>
    <registry id="same"><title>Two</title></registry></registry>"""
    assert_fails(
        "missing or duplicate registry ID",
        lib.project_collection,
        collection,
        xml,
    )


def test_xml_entity_fails() -> None:
    collection = {
        "id": "fixture",
        "sha256": "0" * 64,
        "url": "https://www.iana.org/assignments/quic/quic.xml",
    }
    xml = b"""<!DOCTYPE registry [<!ENTITY x "boom">]>
    <registry xmlns="http://www.iana.org/assignments" id="fixture">
    <registry id="one"><title>&x;</title></registry></registry>"""
    assert_fails(
        "DTD and entity declarations are forbidden",
        lib.project_collection,
        collection,
        xml,
    )


def test_duplicate_json_key_fails() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "duplicate.json"
        path.write_text('{"schema": 1, "schema": 2}', encoding="utf-8")
        assert_fails("duplicate JSON key", lib.read_json, path)


def main() -> int:
    tests = [
        value
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        test()
    print(f"{len(tests)} protocol-surface tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
