#!/usr/bin/env python3
"""Semantic decision-link validation for normative requirements."""

from __future__ import annotations

import requirements_lib as lib


EXPECTED_DISPOSITIONS = {
    "blocked": {"future-work"},
    "caller-owned": {"caller-owned"},
    "evidenced": {"implemented"},
    "implemented": {"implemented"},
    "legacy": {"legacy-only"},
    "planned": {"future-work", "safely-ignored"},
    "rejected": {"intentionally-rejected"},
    "tested": {"implemented"},
}
DOMAIN_SURFACES = {
    "cryptography": {"cryptography"},
    "ct": {"ct"},
    "encoding": {"pkix"},
    "ocsp": {"ocsp", "pki", "pkix", "tls12"},
    "pkix": {"pkix"},
    "tls": {"tls", "tls12", "tls13"},
    "tls12": {"tls", "tls12"},
    "tls13": {"tls", "tls13"},
    "tls13-session": {"tls", "tls13"},
    "quic": {"quic"},
    "dtls": {"dtls", "tls"},
}


def validate(
    requirement: dict,
    source: dict,
    surface_map: dict[str, dict],
) -> None:
    requirement_id = requirement["id"]
    decision_ids = requirement["decision_ids"]
    if (
        not isinstance(decision_ids, list)
        or not decision_ids
        or len(decision_ids) != len(set(decision_ids))
    ):
        lib.fail(f"{requirement_id} has missing or duplicate decisions")
    unknown = set(decision_ids) - set(surface_map)
    if unknown:
        lib.fail(f"{requirement_id} references unknown decisions: {sorted(unknown)}")
    linked = [surface_map[item] for item in decision_ids]
    mapping_scope = requirement["mapping_scope"]
    rationale = requirement["mapping_rationale"]

    if mapping_scope == "reviewed-global":
        if requirement["scope"] != "governance":
            lib.fail(
                f"{requirement_id} protocol requirements require exact-source mapping"
            )
        if source["kind"] != "rfc":
            lib.fail(f"{requirement_id} global mapping requires an RFC source")
        if not isinstance(rationale, str) or len(rationale.strip()) < 40:
            lib.fail(f"{requirement_id} global mapping requires reviewed rationale")
        return
    if mapping_scope != "exact-source":
        lib.fail(f"{requirement_id} has unknown mapping scope")
    if rationale is not None:
        lib.fail(f"{requirement_id} exact-source mapping has unused rationale")

    if source["kind"] == "rfc":
        unrelated = [
            item["id"]
            for item in linked
            if source["id"] not in item["normative_sources"]
        ]
        if unrelated:
            lib.fail(
                f"{requirement_id} links surfaces unrelated to its RFC source: "
                f"{unrelated}"
            )
    else:
        exact_id = source["surface_id"]
        if exact_id not in decision_ids:
            lib.fail(
                f"{requirement_id} does not include its exact IANA source surface"
            )
        exact = surface_map[exact_id]
        exact_sources = set(exact["normative_sources"])
        for item in linked:
            if not exact_sources.intersection(item["normative_sources"]):
                lib.fail(
                    f"{requirement_id} links an unrelated surface {item['id']}"
                )
            if item["owner"] != exact["owner"]:
                lib.fail(
                    f"{requirement_id} links a surface with a different owner"
                )

    allowed = EXPECTED_DISPOSITIONS[requirement["lifecycle"]]
    mismatched = [
        item["id"] for item in linked if item["disposition"] not in allowed
    ]
    if mismatched:
        lib.fail(
            f"{requirement_id} lifecycle conflicts with surface disposition: "
            f"{mismatched}"
        )
    wrong_owner = [
        item["id"] for item in linked if item["owner"] != requirement["owner"]
    ]
    if wrong_owner:
        lib.fail(
            f"{requirement_id} owner conflicts with linked surfaces: {wrong_owner}"
        )


def validate_domain(
    requirement: dict,
    sources: list[dict],
    surface_map: dict[str, dict],
    allowed_surfaces: set[str],
) -> None:
    requirement_id = requirement["id"]
    decision_ids = requirement["decision_ids"]
    if (
        not isinstance(decision_ids, list)
        or not decision_ids
        or len(decision_ids) != len(set(decision_ids))
    ):
        lib.fail(f"{requirement_id} has missing or duplicate decisions")
    unknown = set(decision_ids) - set(surface_map)
    if unknown:
        lib.fail(f"{requirement_id} references unknown decisions: {sorted(unknown)}")
    outside = set(decision_ids) - allowed_surfaces
    if outside:
        lib.fail(
            f"{requirement_id} links decisions outside v0.3.3 scope: "
            f"{sorted(outside)}"
        )
    if requirement["mapping_scope"] != "reviewed-domain":
        lib.fail(f"{requirement_id} domain requirement must use reviewed-domain")
    rationale = requirement["mapping_rationale"]
    if not isinstance(rationale, str) or len(rationale.strip()) < 80:
        lib.fail(f"{requirement_id} domain mapping requires reviewed rationale")

    linked = [surface_map[item] for item in decision_ids]
    allowed_domains = DOMAIN_SURFACES.get(requirement["domain"])
    if allowed_domains is None:
        lib.fail(f"{requirement_id} has unknown coverage domain")
    wrong_domain = [
        item["id"] for item in linked if item["domain"] not in allowed_domains
    ]
    if wrong_domain:
        lib.fail(
            f"{requirement_id} links decisions outside its coverage domain: "
            f"{wrong_domain}"
        )
    allowed_dispositions = EXPECTED_DISPOSITIONS[requirement["lifecycle"]]
    mismatched = [
        item["id"]
        for item in linked
        if item["disposition"] not in allowed_dispositions
    ]
    if mismatched:
        lib.fail(
            f"{requirement_id} lifecycle conflicts with surface disposition: "
            f"{mismatched}"
        )
    authority_ids = {source["id"] for source in sources}
    if not any(
        authority_ids.intersection(item["normative_sources"])
        for item in linked
    ) and "cross-domain" not in rationale.lower():
        lib.fail(
            f"{requirement_id} unrelated domain mapping lacks cross-domain review"
        )
