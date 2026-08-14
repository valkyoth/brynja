#!/usr/bin/env python3
"""Dependency-free helpers for Brynja's protocol-surface register."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import standards_lib as standards


ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "standards/surface-policy.json"
TRANSPORT_POLICY_DIRECTORY = ROOT / "standards/transport-surfaces"
TRANSPORT_POLICY_FILES = tuple(
    TRANSPORT_POLICY_DIRECTORY / name
    for name in ("tls.toml", "tls12.toml", "quic.toml", "dtls.toml")
)
REGISTER = ROOT / "standards/protocol-surfaces.json"
COVERAGE = ROOT / "standards/protocol-surface-coverage.md"
DISPOSITIONS = {
    "caller-owned",
    "future-work",
    "implemented",
    "intentionally-rejected",
    "legacy-only",
    "safely-ignored",
}
ID_PATTERN = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*")
TARGET_PATTERN = re.compile(r"(?:crates|scripts|tests)/[A-Za-z0-9_./#-]+")


def fail(message: str) -> None:
    raise RuntimeError(message)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> object:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
        )
    except json.JSONDecodeError as error:
        fail(f"{path}: invalid JSON: {error}")


def read_toml(path: Path) -> dict:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        fail(f"{path}: invalid TOML: {error}")


def normalized_text(element) -> str:
    return " ".join("".join(element.itertext()).split())


def project_record(record) -> dict:
    fields: dict[str, object] = {}
    references = []
    for child in record:
        name = child.tag.rsplit("}", 1)[-1]
        if name == "xref":
            reference = {
                key: value
                for key, value in sorted(child.attrib.items())
                if key in {"data", "type"}
            }
            if reference:
                references.append(reference)
            continue
        value: object = normalized_text(child)
        if child.attrib:
            value = {
                "attributes": dict(sorted(child.attrib.items())),
                "text": value,
            }
        previous = fields.get(name)
        if previous is None:
            fields[name] = value
        elif isinstance(previous, list):
            previous.append(value)
        else:
            fields[name] = [previous, value]
    return {
        "attributes": dict(sorted(record.attrib.items())),
        "fields": fields,
        "references": references,
    }


def project_collection(collection: dict, snapshot: bytes) -> dict:
    root = standards.safe_xml_root(
        snapshot,
        max_bytes=standards.MAX_IANA_BYTES,
        label=f"IANA {collection['id']}",
    )
    if root.get("id") != collection["id"]:
        fail(
            f"IANA collection {collection['id']} snapshot identifies "
            f"{root.get('id')!r}"
        )
    registries = []
    seen = set()
    for registry in root.findall(".//i:registry", standards.IANA_NS):
        registry_id = registry.get("id", "")
        if not registry_id or registry_id in seen:
            fail(
                f"IANA collection {collection['id']} has missing or duplicate "
                f"registry ID {registry_id!r}"
            )
        seen.add(registry_id)
        records = [
            project_record(record)
            for record in registry.findall("i:record", standards.IANA_NS)
        ]
        registries.append(
            {
                "id": registry_id,
                "records": records,
                "title": normalized_text(
                    registry.find("i:title", standards.IANA_NS)
                ),
            }
        )
    if not registries:
        fail(f"IANA collection {collection['id']} has no nested registries")
    return {
        "id": collection["id"],
        "registries": registries,
        "sha256": collection["sha256"],
        "url": collection["url"],
    }


def record_field(record: dict, field: str) -> str | None:
    value = record["fields"].get(field)
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        text = value.get("text")
        return text if isinstance(text, str) else None
    return None


def record_label(record: dict) -> str:
    for field in ("description", "name", "value"):
        value = record_field(record, field)
        if value:
            return value
    return "unnamed"


def slug(value: str) -> str:
    lowered = value.lower()
    result = re.sub(r"[^a-z0-9]+", "-", lowered).strip("-")
    return result or "unnamed"


def policy_hash(policy: object) -> str:
    return standards.sha256(standards.json_bytes(policy))


def validate_target(target: object, label: str) -> str:
    if (
        not isinstance(target, str)
        or TARGET_PATTERN.fullmatch(target) is None
        or ".." in target.split("/")
    ):
        fail(f"{label} has invalid repository target {target!r}")
    return target


def rfc_references(record: dict) -> list[str]:
    references = set()
    for reference in record["references"]:
        if reference.get("type") == "rfc":
            data = reference.get("data", "")
            if re.fullmatch(r"rfc[0-9]+", data):
                references.add(f"rfc:{int(data[3:])}")
    return sorted(references, key=lambda item: int(item.split(":")[1]))


def render_coverage(register: dict) -> bytes:
    counts: dict[str, int] = {}
    domains: dict[str, int] = {}
    kinds: dict[str, int] = {}
    for surface in register["surfaces"]:
        counts[surface["disposition"]] = counts.get(surface["disposition"], 0) + 1
        domains[surface["domain"]] = domains.get(surface["domain"], 0) + 1
        kinds[surface["kind"]] = kinds.get(surface["kind"], 0) + 1

    lines = [
        "# Protocol Surface Coverage",
        "",
        "Generated from `surface-policy.json`, `transport-surfaces/*.toml`,",
        "and the exact pinned standards evidence. Do not edit this file by hand.",
        "",
        f"- Schema: `{register['schema']}`",
        f"- Source-ledger SHA-256: `{register['source_ledger_sha256']}`",
        f"- Policy SHA-256: `{register['policy_sha256']}`",
        f"- Total classified surfaces: **{len(register['surfaces'])}**",
        "",
        "## Dispositions",
        "",
        "| Disposition | Count |",
        "| --- | ---: |",
    ]
    lines.extend(
        f"| `{key}` | {counts.get(key, 0)} |"
        for key in sorted(DISPOSITIONS)
    )
    lines.extend(
        [
            "",
            "`implemented` is an exact source-and-test-bound claim.",
            "`future-work` is not an implementation claim.",
            "",
            "## Surface Kinds",
            "",
            "| Kind | Count |",
            "| --- | ---: |",
        ]
    )
    lines.extend(f"| `{key}` | {kinds[key]} |" for key in sorted(kinds))
    lines.extend(
        [
            "",
            "## Domains",
            "",
            "| Domain | Count |",
            "| --- | ---: |",
        ]
    )
    lines.extend(f"| `{key}` | {domains[key]} |" for key in sorted(domains))
    lines.extend(
        [
            "",
            "Every row in the JSON register carries its normative source, owner,",
            "planned code target, planned test target, rationale, and disposition.",
            "The offline checker rejects omissions, duplicates, unknown values,",
            "stale source evidence, unmatched overrides, and byte drift.",
            "",
        ]
    )
    return "\n".join(lines).encode()
