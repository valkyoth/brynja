#!/usr/bin/env python3
"""Shared validator for versioned normative-domain requirement bundles."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import NamedTuple

import requirements_bundle_coverage as bundle_coverage
import requirements_lib as lib
import requirements_mapping as mapping
import requirements_sections as sections
import requirements_validation as validation
import standards_lib as standards


class Config(NamedTuple):
    scope: Path
    policy_files: tuple[Path, ...]
    milestone: str
    profile: str
    source_domains: frozenset[str]
    surface_domains: frozenset[str]
    authority_roles: frozenset[str]
    lifecycles: frozenset[str]
    require_owner_coverage: bool = False
    section_policy: Path | None = None


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
SCOPE_REQUIRED = {
    "milestone",
    "schema",
    "source_domains",
    "source_ledger_sha256",
    "surface_domains",
    "surface_exclusion",
    "surface_group",
    "surface_register_sha256",
}
SCOPE_OPTIONAL = {
    "authority_exclusion",
    "owner_milestones",
    "surface_auto_requirements",
    "surface_defer_group",
    "surface_link_exception",
}


def read_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def source_id(entry: dict) -> str:
    if "number" in entry:
        return f"rfc:{entry['number']}"
    prefix = "nist" if entry["filename"].startswith("NIST.") else "itu"
    return f"{prefix}:{entry['filename']}"


def all_authorities(config: Config, ledger: dict) -> dict[str, dict]:
    entries = [
        entry
        for entry in ledger["rfcs"]
        if config.source_domains.intersection(entry["domains"])
    ]
    entries.extend(
        entry
        for entry in ledger["local_authorities"]
        if config.source_domains.intersection(entry["domains"])
    )
    result = {source_id(entry): entry for entry in entries}
    if len(result) != len(entries):
        lib.fail("domain authority identifiers are not unique")
    return result


def load_policy(config: Config) -> tuple[dict, list[dict], str]:
    scope = read_toml(config.scope)
    documents = [read_toml(path) for path in config.policy_files]
    section_document = (
        sections.read_policy(config.section_policy)
        if config.section_policy is not None
        else None
    )
    digest = standards.sha256(
        standards.json_bytes(
            {
                "documents": documents,
                "scope": scope,
                "section_policy": section_document,
            }
        )
    )
    requirements = []
    for path, document in zip(config.policy_files, documents, strict=True):
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
            target_kind = (
                "boundary"
                if lifecycle in {"caller-owned", "rejected"}
                else "planned-symbol"
            )
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
                    "profile": config.profile,
                    "residual": raw["residual"],
                    "revision": 1,
                    "scope": "protocol",
                    "sources": raw["sources"],
                    "statement": raw["statement"],
                    "strength": "INVARIANT",
                    "targets": [{"kind": target_kind, "target": raw["target"]}],
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


def validate_scope(
    config: Config,
    scope: dict,
    ledger: dict,
    register: dict,
) -> None:
    fields = set(scope)
    if (
        not SCOPE_REQUIRED <= fields
        or fields - SCOPE_REQUIRED - SCOPE_OPTIONAL
        or scope["schema"] != 1
    ):
        lib.fail("domain scope has invalid schema or fields")
    if scope["milestone"] != config.milestone:
        lib.fail(f"domain scope must remain owned by v{config.milestone}")
    if set(scope["source_domains"]) != config.source_domains:
        lib.fail("domain scope source domains are incomplete")
    if set(scope["surface_domains"]) != config.surface_domains:
        lib.fail("domain scope surface domains are incomplete")
    if config.require_owner_coverage != ("owner_milestones" in scope):
        lib.fail("domain scope owner-milestone coverage configuration differs")
    ledger_hash = standards.sha256(standards.json_bytes(ledger))
    register_hash = standards.sha256(standards.json_bytes(register))
    if scope["source_ledger_sha256"] != ledger_hash:
        lib.fail("domain scope is not bound to the current source ledger")
    if scope["surface_register_sha256"] != register_hash:
        lib.fail("domain scope is not bound to the current surface register")


def authority_partition(
    config: Config,
    scope: dict,
    ledger: dict,
    versions: set[str] | None = None,
) -> tuple[dict[str, dict], list[dict]]:
    authorities = all_authorities(config, ledger)
    exclusions = scope.get("authority_exclusion", [])
    seen = set()
    for item in exclusions:
        if set(item) != {"deferred_to", "id", "rationale"}:
            lib.fail("domain scope has malformed authority exclusion")
        if item["id"] in seen or item["id"] not in authorities:
            lib.fail("domain scope has duplicate or unknown authority exclusion")
        if not isinstance(item["rationale"], str) or len(item["rationale"]) < 40:
            lib.fail("domain authority exclusion requires reviewed rationale")
        if versions is not None and item["deferred_to"] not in versions:
            lib.fail("domain authority exclusion has unknown deferred milestone")
        seen.add(item["id"])
    included = {
        identifier: entry
        for identifier, entry in authorities.items()
        if identifier not in seen
    }
    return included, sorted(exclusions, key=lambda item: item["id"])


def resolve_sources(
    config: Config,
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
        if expected_role not in config.authority_roles:
            lib.fail(f"{requirement['id']} has unsupported authority role")
        resolved.append(
            {
                "authority_role": expected_role,
                "domains": entry["domains"],
                "id": identifier,
                "kind": "rfc" if "number" in entry else "local",
                "milestones": entry["milestones"],
                "sha256": entry["sha256"],
                **(
                    {"errata": entry["errata"], "status": entry["status"]}
                    if "number" in entry
                    else {"role": entry["role"]}
                ),
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
    validation.validate_tests_and_evidence(
        {**requirement, "tests": stripped}
    )


def validate_requirement(
    config: Config,
    requirement: dict,
    versions: set[str],
    authorities: dict[str, dict],
    surface_map: dict[str, dict],
    allowed_surfaces: set[str],
    link_exceptions: list[dict] | None = None,
) -> dict:
    requirement_id = requirement.get("id")
    if set(requirement) != DOMAIN_FIELDS:
        lib.fail(f"{requirement_id} has unexpected domain requirement fields")
    if requirement.get("profile") != config.profile:
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
    if requirement["lifecycle"] not in config.lifecycles:
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
    resolved = resolve_sources(config, requirement, authorities)
    roles = {source["authority_role"] for source in resolved}
    if roles == {"exclusion"} and requirement["lifecycle"] != "rejected":
        lib.fail(f"{requirement_id} exclusion authority must be rejected")
    if roles == {"caller-owned"} and requirement["lifecycle"] != "caller-owned":
        lib.fail(f"{requirement_id} caller-owned authority requires its boundary")
    if "exclusion" in roles and roles != {"exclusion"}:
        lib.fail(f"{requirement_id} mixes exclusion and admitted authorities")
    validation.validate_targets(requirement)
    validate_tests(requirement)
    mapping.validate_domain(
        requirement,
        resolved,
        surface_map,
        allowed_surfaces,
        link_exceptions,
    )
    return {**requirement, "sources": resolved}


def build(
    config: Config,
    ledger: dict,
    register: dict,
    versions: set[str],
    loaded: tuple[dict, list[dict], str] | None = None,
) -> tuple[list[dict], dict, str]:
    scope, raw_requirements, policy_hash = loaded or load_policy(config)
    validate_scope(config, scope, ledger, register)
    authorities, authority_deferrals = authority_partition(
        config, scope, ledger, versions
    )
    surface_map = {item["id"]: item for item in register["surfaces"]}
    allowed_surfaces = {
        item["id"]
        for item in register["surfaces"]
        if item["domain"] in config.surface_domains
        or set(item["normative_sources"]).intersection(authorities)
    }
    allowed_surfaces.update(
        item["id"] for item in scope["surface_exclusion"]
    )
    requirements = [
        validate_requirement(
            config,
            requirement,
            versions,
            authorities,
            surface_map,
            allowed_surfaces,
            scope.get("surface_link_exception"),
        )
        for requirement in raw_requirements
    ]
    mapping.validate_domain_exception_set(
        requirements,
        surface_map,
        scope.get("surface_link_exception", []),
    )
    requirement_map = {item["id"]: item for item in requirements}
    if len(requirement_map) != len(requirements):
        lib.fail("domain requirement policy has duplicate stable IDs")
    section_coverage = {}
    if config.section_policy is not None:
        section_policy = sections.read_policy(config.section_policy)
        sections.validate_policy(
            section_policy,
            config.section_policy,
            config.milestone,
            standards.sha256(standards.json_bytes(ledger)),
        )
        requirements, section_coverage = sections.apply(
            requirements, authorities, section_policy
        )
    requirement_map = {item["id"]: item for item in requirements}
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
    owner_milestones = set(scope.get("owner_milestones", []))
    semantic_owners = {
        item["owner"]
        for item in register["surfaces"]
        if item["domain"] in config.surface_domains
        and "requirement_id" in item
    }
    if config.require_owner_coverage and owner_milestones != semantic_owners:
        lib.fail("domain owner-milestone coverage is incomplete")
    if owner_milestones - {item["owner"] for item in requirements}:
        lib.fail("domain owner-milestone coverage is incomplete")
    if len(owner_milestones) != len(scope.get("owner_milestones", [])):
        lib.fail("domain scope has duplicate owner milestones")
    if owner_milestones - versions:
        lib.fail("domain scope has unknown owner milestones")
    coverage = bundle_coverage.build(
        config,
        scope,
        authorities,
        authority_deferrals,
        owner_milestones,
        register,
        requirements,
        requirement_map,
        section_coverage,
        versions,
        policy_hash,
    )
    return requirements, coverage, policy_hash
