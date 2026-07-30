#!/usr/bin/env python3
"""Positive and broken fixtures for normative RFC-section bindings."""

from __future__ import annotations

import copy
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import requirements_bundle as bundle  # noqa: E402
import requirements_lib as lib  # noqa: E402
import requirements_sections as sections  # noqa: E402
import requirements_test_support as support  # noqa: E402
import requirements_transport as transport  # noqa: E402
import standards_lib as standards  # noqa: E402
import surface_lib as surfaces  # noqa: E402

assert_fails = support.assert_fails


def fixture() -> tuple[list[dict], dict[str, dict], dict]:
    ledger = lib.read_json(standards.LEDGER)
    register = lib.read_json(surfaces.REGISTER)
    versions = support.checker.roadmap_versions()
    resolved, _coverage, _digest = transport.build(
        ledger, register, versions
    )
    requirements = []
    for requirement in resolved:
        sources = [
            {
                key: value
                for key, value in source.items()
                if key != "sections"
            }
            for source in requirement["sources"]
        ]
        requirements.append(
            {**requirement, "revision": 1, "sources": sources}
        )
    scope = bundle.read_toml(transport.SCOPE)
    authorities, _deferrals = bundle.authority_partition(
        transport.CONFIG, scope, ledger, versions
    )
    policy = sections.read_policy(transport.CONFIG.section_policy)
    return requirements, authorities, policy


def binding(policy: dict, source_id: str, requirement_id: str) -> dict:
    return next(
        item
        for item in policy["binding"]
        if item["source_id"] == source_id
        and item["requirement_id"] == requirement_id
    )


def test_every_normative_section_has_an_explicit_disposition() -> None:
    requirements, authorities, policy = fixture()
    resolved, coverage = sections.apply(
        requirements, authorities, policy
    )
    assert len(coverage) == 550
    assert all(
        item.get("requirement_ids") or item.get("disposition")
        for item in coverage.values()
    )
    records = [
        (source["id"], section)
        for requirement in resolved
        for source in requirement["sources"]
        for section in source.get("sections", [])
    ]
    inventory = sections.section_inventory(authorities)
    assert records
    assert all(
        set(record) == {"anchor", "section", "section_sha256"}
        and record["anchor"] in inventory[(source_id, record["section"])]
        and record["section_sha256"]
        == lib.section_hash(inventory[(source_id, record["section"])])
        for source_id, record in records
    )


def test_unmapped_normative_section_fails() -> None:
    requirements, authorities, policy = fixture()
    broken = copy.deepcopy(policy)
    binding(
        broken, "rfc:8422", "BRY-REQ-TLS12-0088"
    )["sections"].remove("2")
    assert_fails(
        "unmapped normative sections",
        sections.apply,
        requirements,
        authorities,
        broken,
    )


def test_non_normative_section_fails() -> None:
    requirements, authorities, policy = fixture()
    broken = copy.deepcopy(policy)
    binding(
        broken, "rfc:8422", "BRY-REQ-TLS12-0088"
    )["sections"].append("10")
    assert_fails(
        "binding references non-normative section",
        sections.apply,
        requirements,
        authorities,
        broken,
    )


def test_requirement_source_mismatch_fails() -> None:
    requirements, authorities, policy = fixture()
    broken = copy.deepcopy(policy)
    item = binding(broken, "rfc:8422", "BRY-REQ-TLS12-0088")
    item["requirement_id"] = "BRY-REQ-QUIC-0093"
    assert_fails(
        "invalid normative-section binding",
        sections.apply,
        requirements,
        authorities,
        broken,
    )


def test_duplicate_requirement_source_pair_fails() -> None:
    requirements, authorities, policy = fixture()
    broken = copy.deepcopy(policy)
    broken["binding"].append(copy.deepcopy(broken["binding"][0]))
    assert_fails(
        "duplicate requirement and source section binding",
        sections.apply,
        requirements,
        authorities,
        broken,
    )


def test_missing_revision_fails() -> None:
    requirements, authorities, policy = fixture()
    broken = copy.deepcopy(policy)
    broken["revisions"].pop("BRY-REQ-TLS12-0088")
    assert_fails(
        "revision set is incomplete",
        sections.apply,
        requirements,
        authorities,
        broken,
    )


def test_reviewed_exclusion_is_explicit() -> None:
    requirements, authorities, policy = fixture()
    reviewed = copy.deepcopy(policy)
    binding(
        reviewed, "rfc:8422", "BRY-REQ-TLS12-0088"
    )["sections"].remove("2")
    reviewed["exclusion"].append(
        {
            "disposition": "not-applicable",
            "rationale": (
                "RFC 8422 section 2 is excluded only in this synthetic "
                "fixture to prove that an exact reviewed disposition replaces "
                "a requirement binding without becoming an uncovered section."
            ),
            "section": "2",
            "source_id": "rfc:8422",
        }
    )
    _resolved, coverage = sections.apply(
        requirements, authorities, reviewed
    )
    assert coverage[("rfc:8422", "2")]["disposition"] == "not-applicable"


def main() -> int:
    count = support.run_tests(globals())
    print(f"{count} normative-section tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
