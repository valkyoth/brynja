#!/usr/bin/env python3
"""v0.3.3 cryptography, encoding, and PKIX requirement coverage."""

from __future__ import annotations

import tomllib
from pathlib import Path

import requirements_domain_coverage as domain_coverage
import requirements_lib as lib
import requirements_mapping as mapping
import requirements_validation as validation
import standards_lib as standards


SCOPE = lib.DIRECTORY / "domain-scope.toml"
POLICY_DIRECTORY = lib.DIRECTORY / "domains"
COVERAGE = lib.DIRECTORY / "domain-coverage.json"
POLICY_FILES = (
    POLICY_DIRECTORY / "cryptography.toml",
    POLICY_DIRECTORY / "encoding.toml",
    POLICY_DIRECTORY / "pkix.toml",
    POLICY_DIRECTORY / "ocsp.toml",
    POLICY_DIRECTORY / "ct.toml",
)
SOURCE_DOMAINS = {
    "ct",
    "key-containers",
    "ocsp",
    "pkix",
    "public-key",
    "symmetric",
}
SURFACE_DOMAINS = {"cryptography", "ct", "ocsp", "pki", "pkix"}
AUTHORITY_ROLES = {"compatibility", "current", "evidence", "exclusion"}
INVARIANTS = {
    "algorithm-admission",
    "canonical-encoding",
    "constant-time",
    "failure-atomicity",
    "key-lifecycle",
    "resource-bound",
    "side-channel",
    "validation",
    "version-separation",
    "work-bound",
}
DOMAIN_FIELDS = {
    "applicability",
    "decision",
    "decision_ids",
    "deviation_rationale",
    "domain",
    "evidence",
    "evidence_gap",
    "id",
    "invariants",
    "lifecycle",
    "mapping_rationale",
    "mapping_scope",
    "owner",
    "profile",
    "residual",
    "revision",
    "scope",
    "sources",
    "statement",
    "strength",
    "targets",
    "tests",
    "work_bound",
}
RAW_FIELDS = {
    "decision_ids",
    "evidence_gap",
    "id",
    "invariants",
    "lifecycle",
    "mapping_rationale",
    "negative_test",
    "owner",
    "positive_test",
    "residual",
    "sources",
    "statement",
    "target",
    "work_bound",
}
def read_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def source_id(entry: dict) -> str:
    if "number" in entry:
        return f"rfc:{entry['number']}"
    prefix = "nist" if entry["filename"].startswith("NIST.") else "itu"
    return f"{prefix}:{entry['filename']}"


def load_policy() -> tuple[dict, list[dict], str]:
    scope = read_toml(SCOPE)
    documents = [read_toml(path) for path in POLICY_FILES]
    payload = {
        "documents": documents,
        "scope": scope,
    }
    digest = standards.sha256(standards.json_bytes(payload))
    requirements = []
    for path, document in zip(POLICY_FILES, documents, strict=True):
        if set(document) != {"domain", "requirement", "schema"}:
            lib.fail(f"{path}: invalid domain policy fields")
        if document["schema"] != 1:
            lib.fail(f"{path}: unsupported domain policy schema")
        for raw in document["requirement"]:
            if set(raw) != RAW_FIELDS:
                lib.fail(f"{path}: invalid compact requirement fields")
            lifecycle = raw["lifecycle"]
            decision = lib.LIFECYCLE_DECISIONS.get(lifecycle)
            if decision is None:
                lib.fail(f"{path}: unknown compact requirement lifecycle")
            target_kind = "boundary" if lifecycle == "rejected" else "planned-symbol"
            requirements.append(
                {
                    "applicability": decision[0],
                    "decision": decision[1],
                    "decision_ids": raw["decision_ids"],
                    "deviation_rationale": None,
                    "domain": document["domain"],
                    "evidence": [],
                    "evidence_gap": raw["evidence_gap"],
                    "id": raw["id"],
                    "invariants": raw["invariants"],
                    "lifecycle": lifecycle,
                    "mapping_rationale": raw["mapping_rationale"],
                    "mapping_scope": "reviewed-domain",
                    "owner": raw["owner"],
                    "profile": "crypto-encoding-pkix",
                    "residual": raw["residual"],
                    "revision": 1,
                    "scope": "protocol",
                    "sources": raw["sources"],
                    "statement": raw["statement"],
                    "strength": "INVARIANT",
                    "targets": [
                        {"kind": target_kind, "target": raw["target"]}
                    ],
                    "tests": [
                        {
                            "polarity": "positive",
                            "status": "planned",
                            "target": raw["positive_test"],
                        },
                        {
                            "polarity": "negative",
                            "status": "planned",
                            "target": raw["negative_test"],
                        },
                    ],
                    "work_bound": raw["work_bound"],
                }
            )
    return scope, requirements, digest


def validate_scope(scope: dict, ledger: dict, register: dict) -> None:
    required = {
        "milestone",
        "schema",
        "source_domains",
        "source_ledger_sha256",
        "surface_domains",
        "surface_exclusion",
        "surface_group",
        "surface_register_sha256",
    }
    if set(scope) != required or scope["schema"] != 1:
        lib.fail("domain scope has invalid schema or fields")
    if scope["milestone"] != "0.3.3":
        lib.fail("domain scope must remain owned by v0.3.3")
    if set(scope["source_domains"]) != SOURCE_DOMAINS:
        lib.fail("domain scope source domains are incomplete")
    if set(scope["surface_domains"]) != SURFACE_DOMAINS:
        lib.fail("domain scope surface domains are incomplete")
    ledger_hash = standards.sha256(standards.json_bytes(ledger))
    register_hash = standards.sha256(standards.json_bytes(register))
    if scope["source_ledger_sha256"] != ledger_hash:
        lib.fail("domain scope is not bound to the current source ledger")
    if scope["surface_register_sha256"] != register_hash:
        lib.fail("domain scope is not bound to the current surface register")


def expected_authorities(ledger: dict) -> dict[str, dict]:
    entries = [
        entry
        for entry in ledger["rfcs"]
        if SOURCE_DOMAINS.intersection(entry["domains"])
    ]
    entries.extend(
        entry
        for entry in ledger["local_authorities"]
        if SOURCE_DOMAINS.intersection(entry["domains"])
    )
    result = {source_id(entry): entry for entry in entries}
    if len(result) != len(entries):
        lib.fail("domain authority identifiers are not unique")
    return result


def resolve_sources(
    requirement: dict,
    authorities: dict[str, dict],
) -> list[dict]:
    raw_sources = requirement["sources"]
    if not isinstance(raw_sources, list) or not raw_sources:
        lib.fail(f"{requirement['id']} requires exact authority sources")
    resolved = []
    seen = set()
    for raw in raw_sources:
        if set(raw) != {"authority_role", "id"}:
            lib.fail(f"{requirement['id']} has malformed domain source")
        identifier = raw["id"]
        if identifier in seen:
            lib.fail(f"{requirement['id']} has duplicate authority sources")
        seen.add(identifier)
        entry = authorities.get(identifier)
        if entry is None:
            lib.fail(f"{requirement['id']} references out-of-scope authority")
        expected_role = entry.get("lifecycle", "current")
        if raw["authority_role"] != expected_role:
            lib.fail(f"{requirement['id']} misclassifies authority role")
        if expected_role not in AUTHORITY_ROLES:
            lib.fail(f"{requirement['id']} has unsupported authority role")
        if "number" in entry:
            resolved.append(
                {
                    "authority_role": expected_role,
                    "domains": entry["domains"],
                    "errata": entry["errata"],
                    "id": identifier,
                    "kind": "rfc",
                    "milestones": entry["milestones"],
                    "sha256": entry["sha256"],
                    "status": entry["status"],
                }
            )
        else:
            resolved.append(
                {
                    "authority_role": expected_role,
                    "domains": entry["domains"],
                    "id": identifier,
                    "kind": "local",
                    "milestones": entry["milestones"],
                    "role": entry["role"],
                    "sha256": entry["sha256"],
                }
            )
    return resolved


def validate_tests(requirement: dict) -> None:
    tests = requirement["tests"]
    if not isinstance(tests, list) or len(tests) < 2:
        lib.fail(f"{requirement['id']} requires positive and negative tests")
    polarities = set()
    stripped = []
    for test in tests:
        if set(test) != {"polarity", "status", "target"}:
            lib.fail(f"{requirement['id']} has malformed domain test")
        if test["polarity"] not in {"negative", "positive"}:
            lib.fail(f"{requirement['id']} has unknown test polarity")
        polarities.add(test["polarity"])
        stripped.append({"status": test["status"], "target": test["target"]})
    if polarities != {"negative", "positive"}:
        lib.fail(f"{requirement['id']} requires positive and negative tests")
    common = {**requirement, "tests": stripped}
    validation.validate_tests_and_evidence(common)


def validate_requirement(
    requirement: dict,
    versions: set[str],
    authorities: dict[str, dict],
    surface_map: dict[str, dict],
    allowed_surfaces: set[str],
) -> dict:
    requirement_id = requirement.get("id")
    if set(requirement) != DOMAIN_FIELDS:
        lib.fail(f"{requirement_id} has unexpected domain requirement fields")
    if requirement.get("profile") != "crypto-encoding-pkix":
        lib.fail(f"{requirement_id} has invalid domain profile")
    if requirement.get("scope") != "protocol":
        lib.fail(f"{requirement_id} domain requirement must use protocol scope")
    if not isinstance(requirement_id, str) or lib.ID_PATTERN.fullmatch(
        requirement_id
    ) is None:
        lib.fail(f"invalid stable requirement ID {requirement_id!r}")
    if requirement["revision"] != 1:
        lib.fail(f"{requirement_id} new domain requirement must begin at revision 1")
    if requirement["owner"] not in versions:
        lib.fail(f"{requirement_id} has absent or unknown owner")
    expected = lib.LIFECYCLE_DECISIONS.get(requirement["lifecycle"])
    actual = (requirement["applicability"], requirement["decision"])
    if expected is None or actual != expected:
        lib.fail(f"{requirement_id} lifecycle decision is inconsistent")
    if requirement["lifecycle"] not in {"planned", "rejected"}:
        lib.fail(f"{requirement_id} domain coverage cannot claim implementation")
    if requirement["strength"] != "INVARIANT":
        lib.fail(f"{requirement_id} domain bundle must use invariant strength")
    for field, minimum in (
        ("statement", 30),
        ("residual", 20),
        ("work_bound", 30),
        ("evidence_gap", 30),
    ):
        value = requirement[field]
        if not isinstance(value, str) or len(value.strip()) < minimum:
            lib.fail(f"{requirement_id} requires substantive {field}")
    invariants = requirement["invariants"]
    if (
        not isinstance(invariants, list)
        or len(invariants) != len(set(invariants))
        or set(invariants) - INVARIANTS
        or not {"resource-bound", "work-bound"}.intersection(invariants)
    ):
        lib.fail(f"{requirement_id} has incomplete assurance invariants")
    resolved = resolve_sources(requirement, authorities)
    roles = {source["authority_role"] for source in resolved}
    if roles == {"exclusion"} and requirement["lifecycle"] != "rejected":
        lib.fail(f"{requirement_id} exclusion authority must be rejected")
    if "exclusion" in roles and roles != {"exclusion"}:
        lib.fail(f"{requirement_id} mixes exclusion and admitted authorities")
    validation.validate_targets(requirement)
    validate_tests(requirement)
    mapping.validate_domain(
        requirement,
        resolved,
        surface_map,
        allowed_surfaces,
    )
    return {**requirement, "sources": resolved}


def build(
    ledger: dict,
    register: dict,
    versions: set[str],
) -> tuple[list[dict], dict, str]:
    scope, raw_requirements, policy_hash = load_policy()
    validate_scope(scope, ledger, register)
    authorities = expected_authorities(ledger)
    surface_map = {item["id"]: item for item in register["surfaces"]}
    allowed_surfaces = {
        item["id"]
        for item in register["surfaces"]
        if item["domain"] in SURFACE_DOMAINS
    }
    allowed_surfaces.update(
        item["id"]
        for item in register["surfaces"]
        if set(item["normative_sources"]).intersection(authorities)
    )
    allowed_surfaces.update(
        item["id"] for item in scope["surface_exclusion"]
    )
    requirements = [
        validate_requirement(
            requirement,
            versions,
            authorities,
            surface_map,
            allowed_surfaces,
        )
        for requirement in raw_requirements
    ]
    requirement_map = {item["id"]: item for item in requirements}
    if len(requirement_map) != len(requirements):
        lib.fail("domain requirement policy has duplicate stable IDs")
    cited = {
        source["id"]
        for requirement in requirements
        for source in requirement["sources"]
    }
    if cited != set(authorities):
        lib.fail(
            "domain authority coverage differs: "
            f"missing={sorted(set(authorities) - cited)}, "
            f"extra={sorted(cited - set(authorities))}"
        )
    authority_records = []
    for identifier, entry in sorted(authorities.items()):
        ids = sorted(
            requirement["id"]
            for requirement in requirements
            if identifier in {
                source["id"] for source in requirement["sources"]
            }
        )
        record = {
            "authority_role": entry.get("lifecycle", "current"),
            "domains": entry["domains"],
            "id": identifier,
            "milestones": entry["milestones"],
            "requirement_ids": ids,
            "sha256": entry["sha256"],
        }
        if "number" in entry:
            record["normative_sections"] = domain_coverage.normative_sections(
                entry
            )
            record["status"] = entry["status"]
        else:
            record["role"] = entry["role"]
        authority_records.append(record)
    surfaces = domain_coverage.surface_assignments(
        scope,
        register,
        requirement_map,
        SURFACE_DOMAINS,
    )
    coverage = {
        "authorities": authority_records,
        "authority_count": len(authority_records),
        "normative_section_count": sum(
            len(item.get("normative_sections", []))
            for item in authority_records
        ),
        "policy_sha256": policy_hash,
        "requirement_count": len(requirements),
        "schema": 1,
        "surface_count": len(surfaces),
        "surfaces": surfaces,
    }
    return requirements, coverage, policy_hash
