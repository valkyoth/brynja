#!/usr/bin/env python3
"""Pure lifecycle-register construction and drift-review rules."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import standards_lib as standards


ROOT = standards.ROOT
POLICY = ROOT / "standards/authority-lifecycle-policy.toml"
REGISTER = ROOT / "standards/authority-lifecycle.json"
REVIEWS = ROOT / "standards/authority-reviews.json"
FRESHNESS = ROOT / "standards/authority-freshness.json"
LANDING_PINS = ROOT / "standards/snapshots/authority-landings.json"
MATRIX = ROOT / "requirements/matrix.json"
CLOSURE = ROOT / "requirements/closure.json"
ALLOWED_OBSERVATION_STATES = {
    "changed",
    "malformed",
    "oversized",
    "redirect-rejected",
    "rollback",
    "unavailable",
}
ALLOWED_REVIEW_DISPOSITIONS = {
    "no-effect",
    "implementation-update",
    "compatibility",
    "legacy-only",
    "disabled",
    "rejected",
}


class LifecycleError(RuntimeError):
    """Fail-closed lifecycle policy error."""


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def read_policy(path: Path = POLICY) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def source_links() -> dict[str, dict[str, list[str]]]:
    links: dict[str, dict[str, set[str]]] = {}
    matrix = load_json(MATRIX)["requirements"]
    for requirement in matrix:
        sources = (
            [requirement["source"]]
            if "source" in requirement
            else requirement.get("sources", [])
        )
        for source in sources:
            identifier = source.get("id")
            if identifier is None and source.get("kind") == "iana":
                identifier = f"iana:{source['collection']}"
            if identifier is None:
                continue
            item = links.setdefault(
                identifier,
                {"requirements": set(), "symbols": set(), "evidence": set()},
            )
            item["requirements"].add(requirement["id"])
            item["symbols"].update(
                target["target"] for target in requirement.get("targets", [])
            )
            item["evidence"].update(
                evidence
                if isinstance(evidence, str)
                else evidence.get("target", evidence.get("id", ""))
                for evidence in requirement.get("evidence", [])
            )
    return {
        key: {name: sorted(values - {""}) for name, values in value.items()}
        for key, value in links.items()
    }


def brynja_state(source: dict) -> str:
    role = source.get("authority_role", source.get("lifecycle", "current"))
    return {
        "caller-owned": "rejected",
        "compatibility": "compatibility",
        "evidence": "rejected",
        "exclusion": "rejected",
        "legacy": "legacy-only",
    }.get(role, "current")


def rfc_rows(ledger: dict, links: dict) -> list[dict]:
    rows = []
    for source in ledger["rfcs"]:
        identifier = f"rfc:{source['number']}"
        rows.append(
            base_row(
                identifier,
                "RFC Editor",
                source["title"],
                "final",
                f"https://www.rfc-editor.org/info/rfc{source['number']}",
                source["url"],
                source["sha256"],
                source,
                links,
                landing_channel="rfc-index-projection",
                replacements=source["relationships"]["obsoleted_by"],
                metadata={
                    "current_status": source["status"],
                    "errata": source["errata"],
                    "updated_by": source["relationships"]["updated_by"],
                },
            )
        )
    return rows


def base_row(
    identifier: str,
    publisher: str,
    edition: str,
    upstream_state: str,
    landing_url: str,
    content_url: str,
    content_sha256: str,
    source: dict,
    links: dict,
    *,
    landing_channel: str,
    replacements: list,
    metadata: dict,
) -> dict:
    associations = links.get(
        identifier,
        {"requirements": source.get("requirement_ids", []), "symbols": [], "evidence": []},
    )
    if upstream_state == "update-planned":
        impact = (
            "The pinned published edition remains authoritative; draft, planning, "
            "or future replacement text cannot alter Brynja until a human review "
            "updates exact requirements, symbols, evidence, and milestones."
        )
    elif upstream_state in {"superseded", "withdrawn"}:
        impact = (
            "The upstream retirement state cannot preserve this authority as modern "
            "or move code automatically; human compatibility, legacy-only, disabled, "
            "or rejected disposition is required before dependent implementation."
        )
    else:
        impact = (
            "Initial final-publication baseline; observed metadata or byte drift "
            "requires human impact review and cannot authorize implementation."
        )
    return {
        "affected_evidence": sorted(set(associations["evidence"])),
        "affected_milestones": sorted(set(source["milestones"])),
        "affected_requirements": sorted(set(associations["requirements"])),
        "affected_symbols": sorted(set(associations["symbols"])),
        "brynja_state": brynja_state(source),
        "content_sha256": content_sha256,
        "content_url": content_url,
        "edition": edition,
        "id": identifier,
        "landing_channel": landing_channel,
        "landing_url": landing_url,
        "last_successful_observation": read_policy()["monitor"]["baseline_observed_at"],
        "metadata": metadata,
        "planning_notices": [landing_url] if upstream_state == "update-planned" else [],
        "publisher": publisher,
        "replacements": replacements,
        "reviewed_disposition": "baseline",
        "reviewed_impact": impact,
        "upstream_state": upstream_state,
    }


def local_rows(ledger: dict, policy: dict, links: dict, pins: dict) -> list[dict]:
    metadata = {item["id"]: item for item in policy["local"]}
    rows = []
    for source in ledger["local_authorities"]:
        prefix = {"NIST": "nist", "ITU-T": "itu", "RISC-V International": "riscv"}
        item = next((value for value in metadata.values() if value["id"].endswith(source["filename"])), None)
        if item is None:
            raise LifecycleError(f"local lifecycle metadata missing: {source['filename']}")
        pin = pins["landings"].get(item["landing_url"])
        if pin is None:
            raise LifecycleError(f"landing pin missing: {item['landing_url']}")
        row = base_row(
            item["id"],
            item["publisher"],
            item["edition"],
            item["upstream_state"],
            item["landing_url"],
            source["url"],
            source["sha256"],
            source,
            links,
            landing_channel="bounded-page-sha256",
            replacements=[],
            metadata={
                "landing_projection": pin["projection"],
                "landing_sha256": pin["sha256"],
                "landing_size": pin["size"],
            },
        )
        if item["id"].split(":", 1)[0] != prefix[item["publisher"]]:
            raise LifecycleError(f"publisher prefix mismatch: {item['id']}")
        rows.append(row)
    if set(metadata) != {row["id"] for row in rows}:
        raise LifecycleError("local lifecycle metadata differs from locked local authorities")
    return rows


def iana_rows(ledger: dict, links: dict) -> list[dict]:
    rows = []
    for source in ledger["registries"]:
        identifier = f"iana:{source['id']}"
        landing = f"https://www.iana.org/assignments/{source['id']}/"
        rows.append(
            base_row(
                identifier,
                "IANA",
                source["title"],
                "final",
                landing,
                source["url"],
                source["sha256"],
                source,
                links,
                landing_channel="registry-xml-metadata",
                replacements=[],
                metadata={"created": source["created"], "updated": source["updated"]},
            )
        )
    return rows


def build_register(policy: dict | None = None) -> dict:
    policy = read_policy() if policy is None else policy
    ledger = load_json(standards.LEDGER)
    pins = load_json(LANDING_PINS)
    links = source_links()
    rows = rfc_rows(ledger, links)
    rows += local_rows(ledger, policy, links, pins)
    rows += iana_rows(ledger, links)
    rows.sort(key=lambda row: row["id"])
    return {
        "authorities": rows,
        "baseline_observed_at": policy["monitor"]["baseline_observed_at"],
        "policy_sha256": standards.sha256(POLICY.read_bytes()),
        "reviews_sha256": standards.sha256(REVIEWS.read_bytes()),
        "schema": 1,
        "source_ledger_sha256": standards.sha256(standards.LEDGER.read_bytes()),
    }


def validate_register(register: dict, policy: dict | None = None) -> None:
    policy = read_policy() if policy is None else policy
    if register.get("schema") != 1:
        raise LifecycleError("authority lifecycle register requires schema 1")
    rows = register.get("authorities", [])
    ids = [row.get("id") for row in rows]
    if ids != sorted(ids) or len(ids) != len(set(ids)) or len(ids) != 130:
        raise LifecycleError("authority lifecycle register requires 130 unique ordered authorities")
    upstream = set(policy["monitor"]["allowed_upstream_states"])
    brynja = set(policy["monitor"]["allowed_brynja_states"])
    dispositions = set(policy["monitor"]["allowed_dispositions"])
    for row in rows:
        standards.validate_https_url(row["landing_url"])
        standards.validate_https_url(row["content_url"])
        if standards.SHA256_PATTERN.fullmatch(row["content_sha256"]) is None:
            raise LifecycleError(f"invalid content hash: {row['id']}")
        if row["upstream_state"] not in upstream or row["brynja_state"] not in brynja:
            raise LifecycleError(f"invalid lifecycle state: {row['id']}")
        if row["reviewed_disposition"] not in dispositions:
            raise LifecycleError(f"invalid review disposition: {row['id']}")
        if row["last_successful_observation"] != policy["monitor"]["baseline_observed_at"]:
            raise LifecycleError(f"stale authority observation date: {row['id']}")
        if not row["reviewed_impact"].strip():
            raise LifecycleError(f"missing reviewed impact: {row['id']}")
        for field in (
            "affected_evidence",
            "affected_milestones",
            "affected_requirements",
            "affected_symbols",
            "planning_notices",
            "replacements",
        ):
            if row[field] != sorted(set(row[field])):
                raise LifecycleError(f"unordered or duplicate {field}: {row['id']}")


def compare_register(expected: dict, actual: dict) -> list[dict]:
    observations = []
    actual_rows = {row["id"]: row for row in actual["authorities"]}
    for expected_row in expected["authorities"]:
        observed = actual_rows.get(expected_row["id"])
        if observed is None:
            observations.append(observation(expected_row, "unavailable", "authority missing"))
            continue
        changed = sorted(key for key in expected_row if observed.get(key) != expected_row[key])
        if changed:
            state = "rollback" if observed.get("edition", "") < expected_row["edition"] else "changed"
            observations.append(observation(expected_row, state, ",".join(changed)))
    return observations


def observation(row: dict, state: str, detail: str) -> dict:
    if state not in ALLOWED_OBSERVATION_STATES:
        raise LifecycleError(f"invalid observation state: {state}")
    return {
        "affected_milestones": row["affected_milestones"],
        "affected_requirements": row["affected_requirements"],
        "authority": row["id"],
        "detail": detail[:512],
        "effective_brynja_state": row["brynja_state"],
        "requested_action": "human-review",
        "state": state,
    }


def retain_unresolved(prior: list[dict], observed: list[dict]) -> list[dict]:
    combined = {item["id"]: item for item in prior}
    for item in observed:
        identifier = standards.sha256(standards.json_bytes(item))[:24]
        combined.setdefault(identifier, {"id": identifier, **item})
    return [combined[key] for key in sorted(combined)]


def validate_reviews(reviews: dict) -> None:
    if set(reviews) != {"reviews", "schema", "unresolved_observations"} or reviews["schema"] != 1:
        raise LifecycleError("authority review register has invalid fields")
    unresolved_ids = set()
    for item in reviews["unresolved_observations"]:
        required = {
            "affected_milestones",
            "affected_requirements",
            "authority",
            "detail",
            "effective_brynja_state",
            "id",
            "requested_action",
            "state",
        }
        if set(item) != required or item["state"] not in ALLOWED_OBSERVATION_STATES:
            raise LifecycleError("unresolved authority observation has invalid fields")
        if item["id"] in unresolved_ids or item["requested_action"] != "human-review":
            raise LifecycleError("unresolved authority observation is duplicate or authorizing")
        unresolved_ids.add(item["id"])
    reviewed_ids = set()
    for item in reviews["reviews"]:
        required = {
            "authority",
            "corrective_milestone",
            "disposition",
            "observation_id",
            "pentest",
            "reviewed_impact",
        }
        if set(item) != required or item["disposition"] not in ALLOWED_REVIEW_DISPOSITIONS:
            raise LifecycleError("authority disposition review has invalid fields")
        if item["observation_id"] in reviewed_ids or not item["reviewed_impact"].strip():
            raise LifecycleError("authority disposition review is duplicate or unexplained")
        reviewed_ids.add(item["observation_id"])
        if item["disposition"] != "no-effect" and (
            not item["corrective_milestone"] or item["pentest"] != "exceptional-required"
        ):
            raise LifecycleError("security-behavior disposition lacks corrective milestone or pentest")
    if unresolved_ids & reviewed_ids:
        raise LifecycleError("reviewed observation remains unresolved")


def review_observation(observation_item: dict, disposition: str, *, corrective_milestone: str | None, pentest: str) -> dict:
    if disposition not in ALLOWED_REVIEW_DISPOSITIONS:
        raise LifecycleError("invalid authority drift disposition")
    if disposition in {"implementation-update", "compatibility", "legacy-only", "disabled", "rejected"}:
        if not corrective_milestone or pentest != "exceptional-required":
            raise LifecycleError("security-behavior disposition requires corrective milestone and exceptional pentest")
    return {
        "authority": observation_item["authority"],
        "corrective_milestone": corrective_milestone,
        "disposition": disposition,
        "observation_id": observation_item["id"],
        "pentest": pentest,
        "reviewed_impact": observation_item["detail"],
    }
