#!/usr/bin/env python3
"""v0.3.5 optional, legacy, operational, and residual closure."""

from __future__ import annotations

import tomllib
from collections import defaultdict

import requirements_domain_coverage as domain_coverage
import requirements_lib as lib
import requirements_mapping as mapping
import requirements_validation as validation
import standards_lib as standards


POLICY = lib.DIRECTORY / "residual-policy.toml"
GROUP_FIELDS = {"disposition", "domain", "id", "owner", "sources"}
REGISTRY_FIELDS = {"id", "source", "surface"}
DISPOSITION_LIFECYCLE = {
    "caller-owned": "caller-owned",
    "future-work": "planned",
    "intentionally-rejected": "rejected",
    "legacy-only": "legacy",
}


def read_policy() -> dict:
    try:
        with POLICY.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        lib.fail(f"{POLICY}: invalid residual policy: {error}")


def source_map(ledger: dict) -> dict[str, dict]:
    result = {
        f"rfc:{entry['number']}": {**entry, "kind": "rfc"}
        for entry in ledger["rfcs"]
    }
    result.update(
        {
            ("nist:" if entry["filename"].startswith("NIST.") else "itu:")
            + entry["filename"]: {**entry, "kind": "local"}
            for entry in ledger["local_authorities"]
        }
    )
    result.update(
        {
            f"iana:{entry['id']}": {
                **entry,
                "kind": "iana",
                "lifecycle": "current",
            }
            for entry in ledger["registries"]
        }
    )
    return result


def resolve_source(identifier: str, sources: dict[str, dict]) -> dict:
    entry = sources.get(identifier)
    if entry is None:
        lib.fail(f"residual policy references unknown authority: {identifier}")
    common = {
        "authority_role": entry.get("lifecycle", "current"),
        "domains": entry["domains"],
        "id": identifier,
        "kind": entry["kind"],
        "milestones": entry["milestones"],
        "sha256": entry["sha256"],
    }
    if entry["kind"] == "rfc":
        records = [
            {
                "anchor": _anchor(text),
                "section": section,
                "section_sha256": lib.section_hash(text),
            }
            for section, text in _normative_sections(entry).items()
        ]
        return {
            **common,
            "errata": entry["errata"],
            "sections": records,
            "status": entry["status"],
        }
    if entry["kind"] == "local":
        return {**common, "role": entry["role"]}
    return {**common, "collection": entry["id"]}


def _normative_sections(entry: dict) -> dict[str, str]:
    path = lib.ROOT / "rfc" / f"rfc{entry['number']}.txt"
    return {
        section: text
        for section, text in lib.rfc_sections(path).items()
        if domain_coverage.NORMATIVE.search(text)
    }


def _anchor(text: str) -> str:
    value = text[:160].strip()
    if len(value) < 20 or text.count(value) != 1:
        lib.fail("residual normative section lacks a unique extraction anchor")
    return value


def covered_surface_ids(
    foundation: list[dict],
    domain: dict,
    transport: dict,
) -> set[str]:
    covered = {
        item["id"]
        for artifact in (domain, transport)
        for item in artifact["surfaces"]
        if item["coverage"] == "requirement"
    }
    covered.update(
        decision
        for requirement in foundation
        for decision in requirement["decision_ids"]
    )
    return covered


def _target(lifecycle: str, surface: dict) -> dict:
    if lifecycle == "blocked":
        return {
            "kind": "blocker",
            "target": "standards/source-policy.toml#ecdhe-ml-kem-groups",
        }
    if lifecycle == "legacy":
        target = surface["code_target"]
        if not (lib.ROOT / target).is_file() or "brynja-legacy" not in target:
            target = "crates/brynja-legacy/src/lib.rs"
        return {"kind": "legacy-boundary", "target": target}
    if lifecycle in {"caller-owned", "rejected"}:
        label = surface["domain"].replace("_", "-")
        return {"kind": "boundary", "target": f"boundary:{label}.{surface['owner']}"}
    return {"kind": "planned-symbol", "target": surface["code_target"]}


def _invariants(domain: str, lifecycle: str) -> list[str]:
    values = ["resource-bound", "validation", "work-bound"]
    if domain in {"ech", "hpke", "hybrid", "tls", "tls12"}:
        values.append("version-separation")
    if domain in {"cryptography", "entropy", "hpke", "hybrid"}:
        values.extend(["key-lifecycle", "side-channel"])
    if lifecycle == "legacy":
        values.append("algorithm-admission")
    return values


def _tests(surface: dict) -> list[dict]:
    path, _separator, _anchor_value = surface["test_target"].partition("#")
    return [
        {
            "polarity": "positive",
            "status": "planned",
            "target": surface["test_target"],
        },
        {
            "polarity": "negative",
            "status": "planned",
            "target": f"{path}#reject_invalid_and_exhausted",
        },
    ]


def make_requirement(
    raw: dict,
    surface: dict,
    sources: dict[str, dict],
    *,
    lifecycle: str | None = None,
) -> dict:
    lifecycle = lifecycle or raw.get(
        "lifecycle", DISPOSITION_LIFECYCLE[surface["disposition"]]
    )
    applicability, decision = lib.LIFECYCLE_DECISIONS[lifecycle]
    requirement = {
        "applicability": applicability,
        "decision": decision,
        "decision_ids": [surface["id"]],
        "deviation_rationale": None,
        "domain": surface["domain"],
        "evidence": [],
        "evidence_gap": (
            "Executable vectors, fault campaigns, interoperability, and "
            f"independent audit evidence remain unresolved until {surface['owner']}."
        ),
        "id": raw["id"],
        "invariants": _invariants(surface["domain"], lifecycle),
        "lifecycle": lifecycle,
        "mapping_rationale": (
            "This residual group binds every previously uncovered surface in "
            "one exact domain, owner, and disposition class to reviewed locked "
            "authorities, a single implementation boundary, and paired tests."
        ),
        "mapping_scope": "reviewed-domain",
        "owner": surface["owner"],
        "profile": "optional-legacy-residual",
        "residual": (
            "No protocol implementation, interoperability, audit, source-rights, "
            "or production-readiness claim is made by this planning requirement."
        ),
        "revision": 1,
        "scope": "protocol",
        "sources": [resolve_source(item, sources) for item in raw["sources"]],
        "statement": surface["rationale"],
        "strength": "INVARIANT",
        "targets": [_target(lifecycle, surface)],
        "tests": _tests(surface),
        "work_bound": (
            "Inputs, parsing, retained bytes, retries, provider operations, "
            "state transitions, and outputs require explicit caller-owned ceilings."
        ),
    }
    validation.validate_targets(requirement)
    stripped = [
        {"status": item["status"], "target": item["target"]}
        for item in requirement["tests"]
    ]
    validation.validate_tests_and_evidence({**requirement, "tests": stripped})
    return requirement


def validate_policy(
    policy: dict,
    ledger: dict,
    register: dict,
    versions: set[str],
) -> None:
    if (
        set(policy)
        != {
            "milestone",
            "registry_requirement",
            "schema",
            "source_ledger_sha256",
            "surface_group",
            "surface_register_sha256",
        }
        or policy["schema"] != 1
        or policy["milestone"] != "0.3.5"
        or policy["source_ledger_sha256"]
        != standards.sha256(standards.json_bytes(ledger))
        or policy["surface_register_sha256"]
        != standards.sha256(standards.json_bytes(register))
    ):
        lib.fail("residual policy has invalid schema, milestone, or binding")
    groups = policy["surface_group"]
    for item in groups:
        if (
            set(item) != GROUP_FIELDS
            and set(item) != GROUP_FIELDS | {"lifecycle"}
        ) or (
            item["owner"] not in versions
            or item["disposition"] not in DISPOSITION_LIFECYCLE
            or not isinstance(item["sources"], list)
            or not item["sources"]
        ):
            lib.fail("residual policy has a malformed surface group")
    if any(set(item) != REGISTRY_FIELDS for item in policy["registry_requirement"]):
        lib.fail("residual policy has a malformed registry requirement")
    ids = [item["id"] for key in ("surface_group", "registry_requirement") for item in policy[key]]
    if len(ids) != len(set(ids)) or any(lib.ID_PATTERN.fullmatch(item) is None for item in ids):
        lib.fail("residual policy has duplicate or malformed stable IDs")


def build(
    ledger: dict,
    register: dict,
    versions: set[str],
    foundation: list[dict],
    domain: dict,
    transport: dict,
    existing_requirements: list[dict],
    policy: dict | None = None,
) -> tuple[list[dict], dict, str]:
    policy = policy or read_policy()
    validate_policy(policy, ledger, register, versions)
    surfaces = {item["id"]: item for item in register["surfaces"]}
    covered = covered_surface_ids(foundation, domain, transport)
    remaining = [item for item in register["surfaces"] if item["id"] not in covered]
    by_group: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for surface in remaining:
        by_group[(surface["domain"], surface["owner"], surface["disposition"])].append(surface)
    configured = {
        (item["domain"], item["owner"], item["disposition"]): item
        for item in policy["surface_group"]
    }
    if len(configured) != len(policy["surface_group"]) or set(configured) != set(by_group):
        lib.fail(
            "residual surface groups differ: "
            f"missing={sorted(set(by_group) - set(configured))}, "
            f"stale={sorted(set(configured) - set(by_group))}"
        )
    authorities = source_map(ledger)
    requirements = []
    assignments = []
    for key, raw in sorted(configured.items()):
        candidates = by_group[key]
        representative = next(
            (item for item in candidates if item["kind"] == "semantic"),
            candidates[0],
        )
        unknown = set(raw["sources"]) - set(authorities)
        if unknown:
            lib.fail(f"residual policy references unknown authority: {sorted(unknown)}")
        if not set(raw["sources"]).intersection(representative["normative_sources"]):
            lib.fail(f"{raw['id']} has no authority related to its representative")
        expected = raw.get("lifecycle", DISPOSITION_LIFECYCLE[key[2]])
        if key[2] not in mapping.EXPECTED_DISPOSITIONS[expected]:
            lib.fail(f"{raw['id']} lifecycle conflicts with its residual group")
        requirement = make_requirement(raw, representative, authorities)
        requirements.append(requirement)
        assignments.extend(
            {
                "coverage": "requirement",
                "disposition": item["disposition"],
                "domain": item["domain"],
                "id": item["id"],
                "owner": item["owner"],
                "requirement_id": requirement["id"],
            }
            for item in candidates
        )
    for raw in policy["registry_requirement"]:
        surface = surfaces.get(raw["surface"])
        if surface is None or raw["source"] not in surface["normative_sources"]:
            lib.fail(f"{raw['id']} has an invalid registry source surface")
        requirements.append(
            make_requirement(
                {**raw, "sources": [raw["source"]]},
                surface,
                authorities,
            )
        )
    ids = [item["id"] for item in requirements]
    if len(ids) != len(set(ids)):
        lib.fail("residual requirements have duplicate stable IDs")
    all_requirements = existing_requirements + requirements
    cited = set()
    for requirement in all_requirements:
        for source in requirement.get("sources") or [requirement.get("source")]:
            identifier = source.get("id")
            if identifier is None and source.get("kind") == "iana":
                identifier = f"iana:{source['collection']}"
            if identifier is not None:
                cited.add(identifier)
    missing = set(authorities) - cited
    if missing:
        lib.fail(f"source-to-requirement closure is incomplete: {sorted(missing)}")
    digest = standards.sha256(standards.json_bytes(policy))
    coverage = _coverage(requirements, assignments, digest)
    return requirements, coverage, digest


def _coverage(requirements: list[dict], assignments: list[dict], digest: str) -> dict:
    by_source: dict[str, list[str]] = defaultdict(list)
    source_records = {}
    for requirement in requirements:
        for source in requirement["sources"]:
            by_source[source["id"]].append(requirement["id"])
            source_records[source["id"]] = source
    authorities = []
    for identifier, source in sorted(source_records.items()):
        record = {
            key: value
            for key, value in source.items()
            if key not in {"sections"}
        }
        record["requirement_ids"] = sorted(set(by_source[identifier]))
        if "sections" in source:
            record["normative_sections"] = [
                {
                    **section,
                    "requirement_ids": record["requirement_ids"],
                }
                for section in source["sections"]
            ]
        authorities.append(record)
    return {
        "authorities": authorities,
        "authority_count": len(authorities),
        "mapped_normative_section_count": sum(
            len(item.get("normative_sections", [])) for item in authorities
        ),
        "normative_section_count": sum(
            len(item.get("normative_sections", [])) for item in authorities
        ),
        "policy_sha256": digest,
        "requirement_count": len(requirements),
        "schema": 1,
        "surface_count": len(assignments),
        "surfaces": sorted(assignments, key=lambda item: item["id"]),
    }
