#!/usr/bin/env python3
"""v0.3.4 TLS, DTLS, and QUIC normative requirement coverage."""

from __future__ import annotations

import requirements_bundle as bundle
import requirements_lib as lib
import standards_lib as standards
import surface_lib as surfaces


SCOPE = lib.DIRECTORY / "transport-scope.toml"
EXCEPTIONS = lib.DIRECTORY / "transport-exceptions.toml"
SOURCE_DOMAINS = {"dtls", "quic", "tls12", "tls13", "tls13-session"}
SURFACE_DOMAINS = {"dtls", "quic", "tls", "tls12", "tls13"}
AUTHORITY_ROLES = {
    "caller-owned",
    "compatibility",
    "current",
    "evidence",
    "exclusion",
}
CONFIG = bundle.Config(
    scope=SCOPE,
    policy_files=surfaces.TRANSPORT_POLICY_FILES + (EXCEPTIONS,),
    milestone="0.3.4",
    profile="tls-dtls-quic",
    source_domains=frozenset(SOURCE_DOMAINS),
    surface_domains=frozenset(SURFACE_DOMAINS),
    authority_roles=frozenset(AUTHORITY_ROLES),
    lifecycles=frozenset({"caller-owned", "planned", "rejected"}),
    require_owner_coverage=True,
)


def expanded_surface(entry: dict, roles: dict[str, str]) -> dict:
    identifier = entry["requirement_id"]
    domain = entry["domain"]
    invariants = ["resource-bound", "validation", "work-bound"]
    if domain in {"dtls", "quic", "tls12", "tls13"}:
        invariants.append("version-separation")
    if any(word in entry["id"] for word in ("key", "secret", "ticket", "psk")):
        invariants.append("key-lifecycle")
    test_path, _separator, _anchor = entry["test_target"].partition("#")
    return {
        "decision_ids": [entry["id"]],
        "evidence_gap": (
            f"Executable vectors, state-model, fault, fuzz, interoperability, "
            f"and audit evidence remain unresolved until {entry['owner']}."
        ),
        "id": identifier,
        "invariants": invariants,
        "lifecycle": "planned",
        "mapping_rationale": (
            "This dedicated semantic surface binds the reviewed transport "
            "authority set to exactly one implementation milestone, protocol "
            "domain, planned symbol, and positive and negative verification pair."
        ),
        "negative_test": f"{test_path}#reject_invalid_and_exhausted",
        "owner": entry["owner"],
        "positive_test": entry["test_target"],
        "residual": (
            "Implementation, executable verification, interoperability, and "
            "external review remain future work at the owning milestone."
        ),
        "sources": [
            {"authority_role": roles[source], "id": source}
            for source in entry["sources"]
        ],
        "statement": entry["rationale"],
        "target": entry["code_target"],
        "work_bound": (
            "Parsing, state transitions, provider operations, retained bytes, "
            "retries, and output must consume explicit caller-owned budgets."
        ),
    }


def load_policy(ledger: dict | None = None) -> tuple[dict, list[dict], str]:
    ledger = ledger or lib.read_json(standards.LEDGER)
    roles = {
        bundle.source_id(entry): entry.get("lifecycle", "current")
        for entry in ledger["rfcs"]
    }
    documents = [bundle.read_toml(path) for path in CONFIG.policy_files]
    policies = documents[:-1]
    exception_document = documents[-1]
    ledger_hash = standards.sha256(standards.json_bytes(ledger))
    surface_fields = {
        "code_target",
        "disposition",
        "domain",
        "id",
        "owner",
        "rationale",
        "requirement_id",
        "sources",
        "test_target",
    }
    for path, document in zip(
        surfaces.TRANSPORT_POLICY_FILES, policies, strict=True
    ):
        if (
            set(document)
            != {"milestone", "schema", "source_ledger_sha256", "surface"}
            or document["schema"] != 1
            or document["milestone"] != "0.3.4"
            or document["source_ledger_sha256"] != ledger_hash
            or not isinstance(document["surface"], list)
            or not document["surface"]
            or any(
                set(entry) != surface_fields
                or entry["disposition"] != "future-work"
                or not isinstance(entry["sources"], list)
                or not entry["sources"]
                or any(source not in roles for source in entry["sources"])
                for entry in document["surface"]
            )
        ):
            lib.fail(f"{path}: invalid transport surface policy")
    if (
        set(exception_document) != {"domain", "requirement", "schema"}
        or exception_document["schema"] != 1
        or not isinstance(exception_document["requirement"], list)
    ):
        lib.fail("transport exception policy has invalid fields")
    exception_fields = bundle.RAW_FIELDS | {"domain"}
    if any(
        set(requirement) != exception_fields
        for requirement in exception_document["requirement"]
    ):
        lib.fail("transport exception policy has invalid requirement fields")
    requirements = [
        expanded_surface(entry, roles)
        for document in policies
        for entry in document["surface"]
    ]
    requirements.extend(exception_document["requirement"])
    scope = bundle.read_toml(SCOPE)
    digest = standards.sha256(
        standards.json_bytes({"documents": documents, "scope": scope})
    )
    expanded = []
    for raw in requirements:
        lifecycle = raw["lifecycle"]
        applicability, decision = lib.LIFECYCLE_DECISIONS[lifecycle]
        target_kind = (
            "boundary"
            if lifecycle in {"caller-owned", "rejected"}
            else "planned-symbol"
        )
        expanded.append(
            {
                "applicability": applicability,
                "decision": decision,
                "decision_ids": raw["decision_ids"],
                "deviation_rationale": None,
                "domain": raw["domain"]
                if "domain" in raw
                else next(
                    entry["domain"]
                    for document in policies
                    for entry in document["surface"]
                    if entry["requirement_id"] == raw["id"]
                ),
                "evidence": [],
                "evidence_gap": raw["evidence_gap"],
                "id": raw["id"],
                "invariants": raw["invariants"],
                "lifecycle": lifecycle,
                "mapping_rationale": raw["mapping_rationale"],
                "mapping_scope": "reviewed-domain",
                "owner": raw["owner"],
                "profile": CONFIG.profile,
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
    return scope, expanded, digest


def build(
    ledger: dict,
    register: dict,
    versions: set[str],
) -> tuple[list[dict], dict, str]:
    return bundle.build(
        CONFIG,
        ledger,
        register,
        versions,
        loaded=load_policy(ledger),
    )
