#!/usr/bin/env python3
"""Dependency-free helpers for Brynja's normative requirement matrix."""

from __future__ import annotations

import re
from pathlib import Path

import standards_lib as standards
import surface_lib as surfaces


ROOT = Path(__file__).resolve().parent.parent
DIRECTORY = ROOT / "requirements"
POLICY = DIRECTORY / "policy.json"
SCHEMA = DIRECTORY / "schema.json"
MATRIX = DIRECTORY / "matrix.json"
INDEXES = DIRECTORY / "indexes.json"
COVERAGE = DIRECTORY / "coverage.md"
DOMAIN_COVERAGE = DIRECTORY / "domain-coverage.json"
TRANSPORT_COVERAGE = DIRECTORY / "transport-coverage.json"
RESIDUAL_COVERAGE = DIRECTORY / "residual-coverage.json"
CLOSURE = DIRECTORY / "closure.json"
ID_PATTERN = re.compile(r"BRY-REQ-[A-Z0-9]+-[0-9]{4}")
SECTION_PATTERN = re.compile(r"^([0-9]+(?:\.[0-9]+)*)\.\s+(.+?)\s*$", re.MULTILINE)
REPOSITORY_TARGET = re.compile(r"(?:crates|requirements|scripts|standards|tests)/[A-Za-z0-9_./-]+(?:#[A-Za-z0-9_.:-]+)?")
STRENGTHS = {
    "INVARIANT",
    "MAY",
    "MUST",
    "MUST NOT",
    "REGISTRY",
    "SHOULD",
    "SHOULD NOT",
}
LIFECYCLES = {
    "blocked",
    "caller-owned",
    "evidenced",
    "implemented",
    "legacy",
    "planned",
    "rejected",
    "tested",
}
TRANSITIONS = {
    "blocked": ["planned"],
    "caller-owned": ["planned"],
    "evidenced": ["tested"],
    "implemented": ["tested"],
    "legacy": ["blocked", "planned"],
    "planned": [
        "blocked",
        "caller-owned",
        "implemented",
        "legacy",
        "rejected",
    ],
    "rejected": ["planned"],
    "tested": ["evidenced", "implemented"],
}
LIFECYCLE_DECISIONS = {
    "blocked": ("blocked", "defer"),
    "caller-owned": ("delegate", "delegate"),
    "evidenced": ("apply", "enforce"),
    "implemented": ("apply", "enforce"),
    "legacy": ("legacy", "isolate"),
    "planned": ("apply", "enforce"),
    "rejected": ("reject", "exclude"),
    "tested": ("apply", "enforce"),
}


def fail(message: str) -> None:
    raise RuntimeError(message)


def read_json(path: Path) -> object:
    return surfaces.read_json(path)


def normalize(value: str) -> str:
    return " ".join(value.split())


def rfc_sections(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    matches = list(SECTION_PATTERN.finditer(text))
    result = {}
    for index, match in enumerate(matches):
        section = match.group(1)
        if section in result:
            fail(f"{path}: duplicate RFC section {section}")
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        result[section] = normalize(text[match.start():end])
    return result


def section_hash(text: str) -> str:
    return standards.sha256(text.encode())


def split_target(target: str) -> tuple[Path, str | None]:
    path_text, separator, anchor = target.partition("#")
    return ROOT / path_text, anchor if separator else None


def validate_repository_target(target: object, label: str) -> str:
    if (
        not isinstance(target, str)
        or REPOSITORY_TARGET.fullmatch(target) is None
        or ".." in target.split("/")
    ):
        fail(f"{label} has invalid repository target {target!r}")
    return target


def require_actual_target(target: str, label: str) -> None:
    path, anchor = split_target(target)
    root = ROOT.resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        fail(f"{label} target escapes repository root: {target}")
    if not resolved.is_file():
        fail(f"{label} actual target is missing: {target}")
    if anchor and anchor not in resolved.read_text(encoding="utf-8"):
        fail(f"{label} actual target anchor is missing: {target}")


def schema_document() -> dict:
    return {
        "applicabilities": sorted(
            {value[0] for value in LIFECYCLE_DECISIONS.values()}
        ),
        "decisions": sorted(
            {value[1] for value in LIFECYCLE_DECISIONS.values()} | {"deviate"}
        ),
        "id_format": ID_PATTERN.pattern,
        "lifecycles": sorted(LIFECYCLES),
        "authority_roles": [
            "caller-owned",
            "compatibility",
            "current",
            "evidence",
            "exclusion",
        ],
        "domain_invariants": [
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
        ],
        "mapping_scopes": [
            "exact-source",
            "reviewed-domain",
            "reviewed-global",
        ],
        "profiles": [
            "crypto-encoding-pkix",
            "foundation",
            "optional-legacy-residual",
            "tls-dtls-quic",
        ],
        "section_binding_fields": [
            "anchor",
            "section",
            "section_sha256",
        ],
        "section_dispositions": [
            "caller-owned",
            "excluded",
            "not-applicable",
        ],
        "schema": 5,
        "strengths": sorted(STRENGTHS),
        "target_kinds": [
            "actual-symbol",
            "blocker",
            "boundary",
            "legacy-boundary",
            "planned-symbol",
        ],
        "test_polarities": ["negative", "positive"],
        "test_statuses": ["actual", "planned"],
        "transitions": TRANSITIONS,
    }


def reference_key(source: dict) -> str:
    if source["kind"] == "rfc":
        return f"{source['id']}#{source['section']}"
    return source["surface_id"]


def reference_keys(requirement: dict) -> list[str]:
    if "source" in requirement:
        return [reference_key(requirement["source"])]
    return [source["id"] for source in requirement["sources"]]


def build_indexes(requirements: list[dict]) -> dict:
    reverse: dict[str, dict[str, list[str]]] = {
        key: {}
        for key in (
            "authority_roles",
            "decisions",
            "domains",
            "evidence",
            "invariants",
            "owners",
            "sources",
            "targets",
            "tests",
        )
    }
    forward = {}
    for requirement in requirements:
        requirement_id = requirement["id"]
        values = {
            "authority_roles": sorted(
                {
                    source["authority_role"]
                    for source in requirement.get("sources", [])
                }
            ),
            "decisions": requirement["decision_ids"],
            "domains": [requirement["domain"]]
            if "domain" in requirement
            else [],
            "evidence": requirement["evidence"],
            "invariants": requirement.get("invariants", []),
            "owners": [requirement["owner"]],
            "sources": reference_keys(requirement),
            "targets": [
                f"{target['kind']}:{target['target']}"
                for target in requirement["targets"]
            ],
            "tests": [
                ":".join(
                    part
                    for part in (
                        test["status"],
                        test.get("polarity"),
                        test["target"],
                    )
                    if part is not None
                )
                for test in requirement["tests"]
            ],
        }
        forward[requirement_id] = values
        for category, entries in values.items():
            for entry in entries:
                reverse[category].setdefault(entry, []).append(requirement_id)
    for category in reverse.values():
        for ids in category.values():
            ids.sort()
    return {
        "by_requirement": dict(sorted(forward.items())),
        "requirements_by": {
            key: dict(sorted(value.items()))
            for key, value in sorted(reverse.items())
        },
        "schema": 2,
    }


def render_coverage(matrix: dict, indexes: dict) -> bytes:
    lifecycle_counts = {key: 0 for key in LIFECYCLES}
    strength_counts = {key: 0 for key in STRENGTHS}
    scope_counts: dict[str, int] = {}
    domain_counts: dict[str, int] = {}
    for requirement in matrix["requirements"]:
        lifecycle_counts[requirement["lifecycle"]] += 1
        strength_counts[requirement["strength"]] += 1
        scope = requirement["scope"]
        scope_counts[scope] = scope_counts.get(scope, 0) + 1
        if "domain" in requirement:
            domain = requirement["domain"]
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
    lines = [
        "# Normative Requirement Matrix Coverage",
        "",
        "Generated from reviewed policies and exact standards evidence.",
        "Do not edit this file by hand.",
        "",
        f"- Schema: `{matrix['schema']}`",
        f"- Policy SHA-256: `{matrix['policy_sha256']}`",
        f"- Source-ledger SHA-256: `{matrix['source_ledger_sha256']}`",
        f"- Surface-register SHA-256: `{matrix['surface_register_sha256']}`",
        f"- Requirements: **{len(matrix['requirements'])}**",
        "",
        "## Lifecycles",
        "",
        "| Lifecycle | Count |",
        "| --- | ---: |",
    ]
    lines.extend(
        f"| `{key}` | {lifecycle_counts[key]} |"
        for key in sorted(lifecycle_counts)
    )
    lines.extend(
        [
            "",
            "## Strengths",
            "",
            "| Strength | Count |",
            "| --- | ---: |",
        ]
    )
    lines.extend(
        f"| `{key}` | {strength_counts[key]} |"
        for key in sorted(strength_counts)
    )
    lines.extend(
        [
            "",
            "## Scopes",
            "",
            "| Scope | Count |",
            "| --- | ---: |",
        ]
    )
    lines.extend(
        f"| `{key}` | {scope_counts[key]} |" for key in sorted(scope_counts)
    )
    lines.extend(
        [
            "",
            "## Populated Domains",
            "",
            "| Domain | Count |",
            "| --- | ---: |",
        ]
    )
    lines.extend(
        f"| `{key}` | {domain_counts[key]} |" for key in sorted(domain_counts)
    )
    reverse = indexes["requirements_by"]
    lines.extend(
        [
            "",
            "## Bidirectional Indexes",
            "",
            "| Index | Keys |",
            "| --- | ---: |",
        ]
    )
    lines.extend(
        f"| `{key}` | {len(value)} |"
        for key, value in sorted(reverse.items())
    )
    lines.extend(
        [
            "",
            "Cryptography, encoding, and PKIX are populated in v0.3.3. TLS,",
            "DTLS, and QUIC-TLS are populated in v0.3.4. v0.3.5 completes",
            "optional, HPKE, ECH, ML-KEM, entropy, legacy, operational, and",
            "residual closure across every locked source and surface.",
            "",
        ]
    )
    return "\n".join(lines).encode()
