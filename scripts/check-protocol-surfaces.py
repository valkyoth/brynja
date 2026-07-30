#!/usr/bin/env python3
"""Validate and deterministically generate Brynja's surface decisions."""

from __future__ import annotations

import argparse
from pathlib import Path

import standards_lib as standards
import surface_lib as lib
import surface_security


def roadmap_versions() -> set[str]:
    import re

    text = (lib.ROOT / "docs/VERSION_PLAN.md").read_text(encoding="utf-8")
    return set(re.findall(r"`(H?\d+\.\d+(?:\.\d+)?)`", text))


def validate_sources(
    sources: object,
    ledger: dict,
    label: str,
    *,
    allow_empty: bool = False,
) -> list[str]:
    if not isinstance(sources, list) or (not sources and not allow_empty):
        lib.fail(f"{label} requires normative sources")
    if len(sources) != len(set(sources)) or not all(
        isinstance(source, str) for source in sources
    ):
        lib.fail(f"{label} has duplicate or invalid normative sources")
    rfc_ids = {f"rfc:{entry['number']}" for entry in ledger["rfcs"]}
    local_ids = {
        f"nist:{entry['filename']}" for entry in ledger["local_authorities"]
    }
    registry_ids = {
        f"iana:{entry['id']}" for entry in ledger["registries"]
    }
    allowed = rfc_ids | local_ids | registry_ids
    unknown = set(sources) - allowed
    if unknown:
        lib.fail(f"{label} has unknown normative sources: {sorted(unknown)}")
    return sources


def validate_decision(
    decision: dict,
    ledger: dict,
    versions: set[str],
    label: str,
) -> dict:
    required = {
        "code_target",
        "disposition",
        "domain",
        "owner",
        "rationale",
        "sources",
        "test_target",
    }
    if not required <= set(decision) or set(decision) - required != (
        {"source_blocker"} if "source_blocker" in decision else set()
    ):
        lib.fail(f"{label} has unexpected decision fields")
    disposition = decision["disposition"]
    if disposition not in lib.DISPOSITIONS:
        lib.fail(f"{label} has unknown disposition {disposition!r}")
    owner = decision["owner"]
    if owner not in versions:
        lib.fail(f"{label} has unknown owner milestone {owner!r}")
    domain = decision["domain"]
    if not isinstance(domain, str) or lib.ID_PATTERN.fullmatch(domain) is None:
        lib.fail(f"{label} has invalid domain {domain!r}")
    rationale = decision["rationale"]
    if not isinstance(rationale, str) or len(rationale.strip()) < 20:
        lib.fail(f"{label} requires a review rationale")
    source_blocker = decision.get("source_blocker")
    if source_blocker is not None and (
        not isinstance(source_blocker, str)
        or lib.ID_PATTERN.fullmatch(source_blocker) is None
    ):
        lib.fail(f"{label} has invalid source blocker")
    result = {
        "code_target": lib.validate_target(
            decision["code_target"], f"{label} code"
        ),
        "disposition": disposition,
        "domain": domain,
        "normative_sources": validate_sources(
            decision["sources"],
            ledger,
            label,
            allow_empty=source_blocker is not None,
        ),
        "owner": owner,
        "rationale": rationale,
        "test_target": lib.validate_target(
            decision["test_target"], f"{label} test"
        ),
    }
    if source_blocker is not None:
        result["source_blocker"] = source_blocker
    return result


def registry_map(projected: list[dict]) -> dict[tuple[str, str], dict]:
    result = {}
    for collection in projected:
        for registry in collection["registries"]:
            result[(collection["id"], registry["id"])] = registry
    return result


def matches(record: dict, selector: dict) -> bool:
    if set(selector) != {"collection", "equals", "field", "registry"}:
        lib.fail("entry override has unexpected selector fields")
    return lib.record_field(record, selector["field"]) == selector["equals"]


def validate_policy(policy: dict, ledger: dict, projected: list[dict]) -> None:
    if set(policy) != {
        "collections",
        "decisions",
        "entry_overrides",
        "schema",
        "source_ledger_sha256",
    }:
        lib.fail("surface policy has unexpected top-level fields")
    if policy["schema"] != 1:
        lib.fail("surface policy schema must be exactly 1")
    actual_ledger_hash = standards.sha256(standards.json_bytes(ledger))
    if policy["source_ledger_sha256"] != actual_ledger_hash:
        lib.fail("surface policy is not bound to the current source ledger")

    expected_collections = {entry["id"] for entry in ledger["registries"]}
    collection_ids = [entry["id"] for entry in policy["collections"]]
    if set(collection_ids) != expected_collections or len(collection_ids) != len(
        set(collection_ids)
    ):
        lib.fail("surface policy must cover exactly every IANA collection")

    versions = roadmap_versions()
    registries = registry_map(projected)
    for collection in policy["collections"]:
        if set(collection) != {"default", "id", "registry_rules"}:
            lib.fail(
                f"collection {collection.get('id')} has unexpected fields"
            )
        validate_decision(
            collection["default"],
            ledger,
            versions,
            f"collection {collection['id']} default",
        )
        seen = set()
        available = {
            registry_id
            for collection_id, registry_id in registries
            if collection_id == collection["id"]
        }
        for rule in collection["registry_rules"]:
            if set(rule) != {"decision", "ids"}:
                lib.fail(
                    f"collection {collection['id']} has malformed registry rule"
                )
            ids = rule["ids"]
            if (
                not isinstance(ids, list)
                or not ids
                or len(ids) != len(set(ids))
                or set(ids) & seen
            ):
                lib.fail(
                    f"collection {collection['id']} has duplicate registry rules"
                )
            unknown = set(ids) - available
            if unknown:
                lib.fail(
                    f"collection {collection['id']} rules reference unknown "
                    f"registries: {sorted(unknown)}"
                )
            seen.update(ids)
            validate_decision(
                rule["decision"],
                ledger,
                versions,
                f"registry rule {collection['id']}/{ids[0]}",
            )

    decision_ids = [entry["id"] for entry in policy["decisions"]]
    if len(decision_ids) != len(set(decision_ids)):
        lib.fail("surface policy has duplicate semantic decision IDs")
    for entry in policy["decisions"]:
        if set(entry) != {"decision", "id"}:
            lib.fail("semantic decision has unexpected fields")
        if lib.ID_PATTERN.fullmatch(entry["id"]) is None:
            lib.fail(f"invalid semantic decision ID {entry['id']!r}")
        validate_decision(
            entry["decision"],
            ledger,
            versions,
            f"semantic decision {entry['id']}",
        )

    selectors = []
    for override in policy["entry_overrides"]:
        if set(override) != {"decision", "selector"}:
            lib.fail("entry override has unexpected fields")
        selector = override["selector"]
        selector_key = (
            selector.get("collection"),
            selector.get("registry"),
            selector.get("field"),
            selector.get("equals"),
        )
        if selector_key in selectors:
            lib.fail(f"duplicate entry override selector {selector_key!r}")
        selectors.append(selector_key)
        key = (selector.get("collection"), selector.get("registry"))
        registry = registries.get(key)
        if registry is None:
            lib.fail(f"entry override references unknown registry {key!r}")
        matched = [
            record for record in registry["records"] if matches(record, selector)
        ]
        if len(matched) != 1:
            lib.fail(
                f"entry override {key!r} must match exactly one record, "
                f"matched {len(matched)}"
            )
        validate_decision(
            override["decision"],
            ledger,
            versions,
            f"entry override {key!r}/{selector['equals']}",
        )


def load_transport_policies() -> list[dict]:
    return [lib.read_toml(path) for path in lib.TRANSPORT_POLICY_FILES]


def validate_transport_policies(
    policies: list[dict],
    ledger: dict,
    versions: set[str],
) -> list[dict]:
    if not policies:
        return []
    if len(policies) != len(lib.TRANSPORT_POLICY_FILES):
        lib.fail("transport policy file set is incomplete")
    ledger_hash = standards.sha256(standards.json_bytes(ledger))
    result = []
    seen = set()
    seen_requirements = set()
    for path, policy in zip(lib.TRANSPORT_POLICY_FILES, policies):
        if set(policy) != {
            "milestone",
            "schema",
            "source_ledger_sha256",
            "surface",
        } or not isinstance(policy["surface"], list) or not policy["surface"]:
            lib.fail(f"{path}: unexpected transport-policy fields")
        if policy["schema"] != 1 or policy["milestone"] != "0.3.4":
            lib.fail(f"{path}: transport-policy identity is invalid")
        if policy["source_ledger_sha256"] != ledger_hash:
            lib.fail(f"{path}: transport policy is not bound to the ledger")
        for entry in policy["surface"]:
            if set(entry) != {
                "code_target",
                "disposition",
                "domain",
                "id",
                "owner",
                "rationale",
                "requirement_id",
                "sources",
                "test_target",
            }:
                lib.fail(f"{path}: malformed transport surface")
            identifier = entry["id"]
            if (
                not isinstance(identifier, str)
                or lib.ID_PATTERN.fullmatch(identifier) is None
                or identifier in seen
            ):
                lib.fail(f"{path}: duplicate or invalid transport surface ID")
            seen.add(identifier)
            requirement_id = entry["requirement_id"]
            if (
                not isinstance(requirement_id, str)
                or not requirement_id.startswith("BRY-REQ-")
                or requirement_id in seen_requirements
            ):
                lib.fail(f"{path}: duplicate or invalid transport requirement ID")
            seen_requirements.add(requirement_id)
            decision = {
                key: value
                for key, value in entry.items()
                if key not in {"id", "requirement_id"}
            }
            result.append(
                {
                    "id": identifier,
                    "kind": "semantic",
                    "requirement_id": requirement_id,
                    **validate_decision(
                        decision,
                        ledger,
                        versions,
                        f"transport surface {identifier}",
                    ),
                }
            )
    return result


def rule_decision(collection: dict, registry_id: str) -> dict:
    matched = [
        rule["decision"]
        for rule in collection["registry_rules"]
        if registry_id in rule["ids"]
    ]
    if len(matched) > 1:
        lib.fail(f"registry {registry_id} has overlapping rules")
    return matched[0] if matched else collection["default"]


def build_register(
    policy: dict | None = None,
    ledger: dict | None = None,
    transport_policies: list[dict] | None = None,
) -> dict:
    custom_inputs = any(
        value is not None for value in (policy, ledger, transport_policies)
    )
    policy = policy or lib.read_json(lib.POLICY)
    ledger = ledger or lib.read_json(standards.LEDGER)
    if not isinstance(policy, dict) or not isinstance(ledger, dict):
        lib.fail("surface policy and source ledger must be JSON objects")

    projected = []
    ledger_collections = {entry["id"]: entry for entry in ledger["registries"]}
    for collection_id, collection in sorted(ledger_collections.items()):
        path = standards.IANA_DIRECTORY / f"{collection_id}.xml"
        data = path.read_bytes()
        if standards.sha256(data) != collection["sha256"]:
            lib.fail(f"IANA collection {collection_id} differs from source ledger")
        projected.append(lib.project_collection(collection, data))
    validate_policy(policy, ledger, projected)

    versions = roadmap_versions()
    if transport_policies is None:
        transport_policies = [] if custom_inputs else load_transport_policies()
    transport_surfaces = validate_transport_policies(
        transport_policies, ledger, versions
    )
    locked_rfc_sources = {f"rfc:{entry['number']}" for entry in ledger["rfcs"]}
    policy_collections = {entry["id"]: entry for entry in policy["collections"]}
    surfaces = list(transport_surfaces)
    for entry in policy["decisions"]:
        decision = validate_decision(
            entry["decision"],
            ledger,
            versions,
            f"semantic decision {entry['id']}",
        )
        surfaces.append({"id": entry["id"], "kind": "semantic", **decision})

    used_overrides = set()
    for collection in projected:
        collection_policy = policy_collections[collection["id"]]
        for registry in collection["registries"]:
            base = rule_decision(collection_policy, registry["id"])
            registry_decision = validate_decision(
                base,
                ledger,
                versions,
                f"registry {collection['id']}/{registry['id']}",
            )
            source = f"iana:{collection['id']}"
            registry_decision["normative_sources"] = sorted(
                set(registry_decision["normative_sources"]) | {source}
            )
            prefix = f"iana.{collection['id']}.{registry['id']}"
            surfaces.append(
                {
                    "id": prefix,
                    "kind": "iana-registry",
                    "registry": {
                        "collection": collection["id"],
                        "id": registry["id"],
                        "sha256": collection["sha256"],
                        "title": registry["title"],
                    },
                    **registry_decision,
                }
            )
            labels: dict[str, int] = {}
            for record in registry["records"]:
                decision_source = base
                for index, override in enumerate(policy["entry_overrides"]):
                    if (
                        override["selector"]["collection"] == collection["id"]
                        and override["selector"]["registry"] == registry["id"]
                        and matches(record, override["selector"])
                    ):
                        if index in used_overrides:
                            lib.fail(f"entry override {index} matched twice")
                        used_overrides.add(index)
                        decision_source = override["decision"]
                decision = validate_decision(
                    decision_source,
                    ledger,
                    versions,
                    f"record {prefix}/{lib.record_label(record)}",
                )
                decision["normative_sources"] = sorted(
                    set(decision["normative_sources"])
                    | {source}
                    | (set(lib.rfc_references(record)) & locked_rfc_sources)
                )
                label = lib.slug(lib.record_label(record))
                labels[label] = labels.get(label, 0) + 1
                surfaces.append(
                    {
                        "id": f"{prefix}.{label}.{labels[label]}",
                        "kind": "iana-entry",
                        "record": record,
                        "registry": {
                            "collection": collection["id"],
                            "id": registry["id"],
                        },
                        **decision,
                    }
                )
    if used_overrides != set(range(len(policy["entry_overrides"]))):
        lib.fail("one or more entry overrides did not match")
    ids = [surface["id"] for surface in surfaces]
    if len(ids) != len(set(ids)):
        lib.fail("generated protocol surface IDs are not unique")
    if any(surface["disposition"] == "implemented" for surface in surfaces):
        lib.fail(
            "planning milestones must not classify any surface as implemented"
        )
    if transport_surfaces:
        surface_security.validate(surfaces)
    return {
        "policy_sha256": lib.policy_hash(
            {
                "registry_policy": policy,
                "transport_policies": transport_policies,
            }
        ),
        "schema": 2,
        "source_ledger_sha256": policy["source_ledger_sha256"],
        "surfaces": sorted(surfaces, key=lambda surface: surface["id"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    register = build_register()
    register_bytes = standards.json_bytes(register)
    coverage_bytes = lib.render_coverage(register)
    if args.write:
        lib.REGISTER.write_bytes(register_bytes)
        lib.COVERAGE.write_bytes(coverage_bytes)
        print("wrote protocol surface register and coverage")
    elif (
        not lib.REGISTER.is_file()
        or lib.REGISTER.read_bytes() != register_bytes
        or not lib.COVERAGE.is_file()
        or lib.COVERAGE.read_bytes() != coverage_bytes
    ):
        lib.fail("protocol surface artifacts are stale; rerun with --write")
    else:
        print(
            f"{len(register['surfaces'])} protocol surfaces are explicit "
            "and reproducible"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
