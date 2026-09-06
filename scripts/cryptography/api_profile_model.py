#!/usr/bin/env python3
"""Validate and render Brynja's cryptographic API and secret-state register."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import Path

import api_profile_contracts as contracts
import rust_source_contract as rust_contract
ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "security/cryptographic-api-profile-policy.toml"
SURFACES = ROOT / "standards/protocol-surfaces.json"
REGISTER = ROOT / "security/cryptographic-api-profile-register.json"
COVERAGE = ROOT / "docs/cryptographic-api-profile-register.md"
MILESTONE = "0.24.15"
PROFILE_KEYS = {
    "kind",
    "secret_template",
    "required",
    "forbidden",
    "caller_owned",
    "not_applicable",
    "optional_isolated",
    "internal_only",
    "operations",
    "consumers",
}
OPERATION_KEYS = {
    "output_classification", "partial_failure_policy", "verification",
}
BUCKETS = {
    "required": "required",
    "forbidden": "forbidden",
    "caller_owned": "caller-owned",
    "not_applicable": "not-applicable",
    "optional_isolated": "optional-isolated",
    "internal_only": "internal-only",
}
LIFECYCLE_EDGES = (
    "creation",
    "success",
    "error",
    "cancellation",
    "replacement",
    "rekey",
    "failed-construction",
    "recoverable-unwind",
    "drop",
)
RESIDUALS = (
    "mem-forget",
    "process-abort",
    "forced-termination",
    "power-loss",
    "register-copies",
    "cpu-caches",
    "compiler-created-copies",
    "crash-dumps",
    "suspend-images",
    "os-swap-and-paging",
    "dma-visible-copies",
    "physical-memory-remanence",
)
REJECTIONS = (
    "copy-secret-state",
    "clone-secret-state",
    "format-secret-state",
    "serialize-secret-state",
    "raw-secret-state-access",
    "snapshot-secret-state",
    "reset-secret-into-ordinary-state",
    "downstream-hardened-marker-implementation",
    "downstream-hardened-marker-forgery",
    "optional-only-core-cleanup",
    "partial-secret-output-without-clearing",
    "unreviewed-secret-accelerated-backend",
    "implicit-secret-output-declassification",
    "unsafe-convenience-api",
    "nonstandard-convenience-api",
)
HASH = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"(?:H?[0-9]+\.[0-9]+(?:\.[0-9]+)?)")


class ProfileError(RuntimeError):
    """The API-profile policy or generated register is invalid."""


def fail(message: str) -> None:
    raise ProfileError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def path_part(target: str) -> str:
    return target.split("#", 1)[0]


def read_policy(path: Path = POLICY) -> dict:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read API-profile policy: {error}")


def read_surfaces(path: Path = SURFACES) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read protocol surfaces: {error}")


def exact_keys(value: dict, expected: set[str], label: str) -> None:
    if set(value) != expected:
        fail(f"{label} fields drifted")

def roadmap_versions(root: Path) -> set[str]:
    text = (root / "docs/VERSION_PLAN.md").read_text(encoding="utf-8")
    return set(re.findall(r"`(H?[0-9]+\.[0-9]+(?:\.[0-9]+)?)`", text))


def validate_target(root: Path, target: str, label: str) -> None:
    path = root / path_part(target)
    if not path.is_file() or path.is_symlink():
        fail(f"{label} target is unavailable: {target}")
    if "#" in target:
        symbol = target.split("#", 1)[1].rsplit("::", 1)[-1]
        if re.search(rf"\b{re.escape(symbol)}\b", path.read_text(encoding="utf-8")) is None:
            fail(f"{label} symbol is unavailable: {target}")

def validate_profile(name: str, profile: dict, dimensions: set[str], policy: dict) -> None:
    exact_keys(profile, PROFILE_KEYS, f"profile {name}")
    if profile["secret_template"] != "none" and profile["secret_template"] not in policy["secret-template"]:
        fail(f"profile {name} has unknown secret template")
    assigned: dict[str, str] = {}
    for field, disposition in BUCKETS.items():
        values = profile[field]
        if not isinstance(values, list) or len(values) != len(set(values)):
            fail(f"profile {name} has malformed {field}")
        for dimension in values:
            if dimension in assigned:
                fail(f"profile {name} assigns {dimension} more than once")
            assigned[dimension] = disposition
    if set(assigned) != dimensions:
        fail(f"profile {name} does not classify every API dimension")
    secret_template = profile["secret_template"]
    if secret_template != "none" and assigned["ownership"] != "required":
        fail(f"profile {name} must require hardened ownership")
    if name in {"fixed-hash", "hash-xof-family", "keyed-construction"}:
        if assigned["byte-input"] != "required" or assigned["bit-input"] != "required":
            fail(f"profile {name} must cover byte and bit input")
    if name == "fixed-hash" and assigned["fixed-output"] != "required":
        fail("fixed hash profile must require fixed output")
    if name == "hash-xof-family" and (
        assigned["fixed-output"] != "required"
        or assigned["extendable-output"] != "required"
    ):
        fail("SHA-3/SHAKE profile must cover fixed and extendable output")
    expected_operations = contracts.OPERATION_CONTRACTS.get(name)
    operations = profile["operations"]
    if expected_operations is None or set(operations) != set(expected_operations):
        fail(f"profile {name} operation inventory drifted")
    secret_outputs = 0
    for operation, output in operations.items():
        exact_keys(output, OPERATION_KEYS, f"profile {name} operation {operation}")
        actual = (
            output["output_classification"], output["partial_failure_policy"],
            output["verification"],
        )
        if actual != expected_operations[operation]:
            fail(f"profile {name} operation {operation} information flow drifted")
        if output["output_classification"] not in policy["output"]["classifications"]:
            fail(f"profile {name} operation {operation} has unknown output classification")
        if output["partial_failure_policy"] not in policy["output"]["partial_failure_policies"]:
            fail(f"profile {name} operation {operation} has unknown partial-output policy")
        if output["verification"] not in policy["output"]["verification_policies"]:
            fail(f"profile {name} operation {operation} has unknown verification policy")
        if output["output_classification"] == "typed-secret-owned":
            secret_outputs += 1
            if output["partial_failure_policy"] != "clear-complete-secret-destination":
                fail(f"profile {name} operation {operation} leaves secret output uncleared")
    if secret_template != "none":
        template = policy["secret-template"][secret_template]
        if template["secret_output_classification"] != "typed-secret-owned" or not secret_outputs:
            fail(f"profile {name} differs from secret template {secret_template}")
    consumers = profile["consumers"]
    if not consumers or len(consumers) != len(set(consumers)) or not all(
        isinstance(item, str) and item.startswith("consumer:") for item in consumers
    ):
        fail(f"profile {name} requires exact consumer links")


def assignment_map(policy: dict, semantic_ids: set[str]) -> dict[str, str]:
    exact: dict[str, str] = {}
    prefixes: list[tuple[str, str]] = []
    profiles = set(policy["profile"])
    for index, assignment in enumerate(policy["assignment"]):
        allowed = {"profile", "ids", "prefixes"}
        if (
            not {"profile"} < set(assignment) <= allowed
            or assignment["profile"] not in profiles
        ):
            fail(f"assignment {index} is malformed")
        for capability in assignment.get("ids", []):
            if capability in exact:
                fail(f"capability {capability} has duplicate exact assignments")
            exact[capability] = assignment["profile"]
        for prefix in assignment.get("prefixes", []):
            prefixes.append((prefix, assignment["profile"]))
    unknown = set(exact) - semantic_ids
    if unknown:
        fail(f"assignments reference unknown capabilities: {sorted(unknown)}")
    result = {}
    for capability in semantic_ids:
        matches = {profile for prefix, profile in prefixes if capability.startswith(prefix)}
        if capability in exact:
            result[capability] = exact[capability]
        elif len(matches) == 1:
            result[capability] = matches.pop()
        elif not matches:
            fail(f"capability {capability} has no API profile")
        else:
            fail(f"capability {capability} has ambiguous prefix profiles")
    return result


def validate_cleanup(policy: dict, root: Path, *, adapter_available: bool = True) -> None:
    cleanup = policy["cleanup"]
    exact_keys(
        cleanup,
        {
            "mandatory_core_symbol", "mandatory_core_evidence",
            "optional_adapter_symbol", "optional_adapter_evidence",
            "adapter_required_for_core", "adapter_in_fips_graph",
            "adjacent_failure_policy", "recoverable_unwind_policy",
        },
        "cleanup policy",
    )
    validate_target(root, cleanup["mandatory_core_symbol"], "mandatory cleanup")
    validate_target(root, cleanup["mandatory_core_evidence"], "mandatory cleanup evidence")
    if cleanup["adapter_required_for_core"] or cleanup["adapter_in_fips_graph"]:
        fail("optional adapter cannot be mandatory or enter the FIPS graph")
    if adapter_available:
        validate_target(root, cleanup["optional_adapter_symbol"], "optional adapter")
        validate_target(root, cleanup["optional_adapter_evidence"], "adapter evidence")
    if cleanup["adjacent_failure_policy"] != "attempt-every-region-and-latch-terminal-failure":
        fail("adjacent cleanup failures do not preserve all-region cleanup")
    if cleanup["recoverable_unwind_policy"] != "non-panicking-drop-cleans-every-owned-region":
        fail("recoverable unwind cleanup policy drifted")


def validate_policy(policy: dict, surfaces: dict, root: Path = ROOT) -> dict[str, str]:
    expected_top = {
        "schema", "api", "cleanup", "lifecycle", "output", "residual",
        "rejection", "profile", "secret-template", "assignment",
        "completion-overrides", "secret-owner-overrides",
        "current-secret-owner", "registered-secret-owner", "reviewed-source",
    }
    exact_keys(policy, expected_top, "API-profile policy")
    schema = policy["schema"]
    if schema.get("version") != 1 or schema.get("milestone") != MILESTONE:
        fail("API-profile schema or milestone drifted")
    if HASH.fullmatch(schema.get("surface_register_sha256", "")) is None:
        fail("surface-register hash is malformed")
    if sha256(json_bytes(surfaces)) != schema["surface_register_sha256"]:
        fail("API-profile policy changed or protocol surfaces drifted; reopen review")
    dimensions = policy["api"]["dimensions"]
    dispositions = policy["api"]["dispositions"]
    if len(dimensions) != 22 or len(dimensions) != len(set(dimensions)):
        fail("API dimensions are incomplete or duplicated")
    if set(dispositions) != set(BUCKETS.values()):
        fail("API dispositions drifted")
    if tuple(policy["lifecycle"].get("edges", ())) != LIFECYCLE_EDGES:
        fail("secret lifecycle edges are incomplete")
    if tuple(policy["residual"].get("risks", ())) != RESIDUALS:
        fail("secret-state residual risks are incomplete")
    if tuple(policy["rejection"].get("values", ())) != REJECTIONS:
        fail("explicit unsafe or nonstandard rejections are incomplete")
    validate_cleanup(policy, root)
    semantic = {row["id"]: row for row in surfaces["surfaces"] if row["kind"] == "semantic"}
    if len(semantic) != 134:
        fail("semantic capability count drifted")
    for name, profile in policy["profile"].items():
        validate_profile(name, profile, set(dimensions), policy)
    assignments = assignment_map(policy, set(semantic))
    versions = roadmap_versions(root)
    for capability, overrides in policy["completion-overrides"].items():
        if capability not in semantic or not set(overrides) <= set(dimensions):
            fail(f"completion overrides are invalid for {capability}")
        if any(owner not in versions for owner in overrides.values()):
            fail(f"completion override owner is absent for {capability}")
    for capability, owner in policy["secret-owner-overrides"].items():
        if capability not in semantic or owner not in versions:
            fail(f"secret owner override is invalid for {capability}")
    validate_secret_policy(policy, root, semantic, assignments)
    return assignments


def validate_secret_policy(
    policy: dict, root: Path, semantic: dict | None = None,
    assignments: dict | None = None,
) -> None:
    for name, template in policy["secret-template"].items():
        exact_keys(template, {"fields", "temporaries", "secret_output_classification"}, f"secret template {name}")
        if not template["fields"] or not template["temporaries"]:
            fail(f"secret template {name} lacks fields or temporaries")
        if template["secret_output_classification"] != "typed-secret-owned":
            fail(f"secret template {name} has invalid output classification")
    owners = policy["current-secret-owner"]
    ids = [owner.get("id") for owner in owners]
    if set(ids) != set(contracts.CURRENT_OWNER_SYMBOLS) or len(ids) != len(set(ids)):
        fail("current secret-owner inventory is incomplete or duplicated")
    for owner in owners:
        exact_keys(owner, {"id", "symbol", "fields", "temporaries", "sanitization_symbol", "cleanup_callers", "evidence", "storage"}, f"secret owner {owner.get('id')}")
        if not owner["fields"] or not owner["temporaries"] or not owner["evidence"]:
            fail(f"secret owner {owner['id']} lacks fields, temporaries, or evidence")
        if owner["symbol"] != contracts.CURRENT_OWNER_SYMBOLS[owner["id"]]:
            fail(f"secret owner {owner['id']} canonical symbol drifted")
        field_names = {field.split(":", 1)[0] for field in owner["fields"]}
        try:
            rust_contract.validate_type(root, owner["symbol"], field_names)
            rust_contract.validate_cleanup_binding(
                root, owner["sanitization_symbol"], owner["cleanup_callers"],
                contracts.CURRENT_CLEANUP_CALLS[owner["id"]],
            )
        except rust_contract.RustContractError as error:
            fail(f"secret owner {owner['id']} Rust contract failed: {error}")
        for evidence in owner["evidence"]:
            validate_target(root, evidence, f"secret owner {owner['id']} evidence")
    registered = policy["registered-secret-owner"]
    capabilities = [owner.get("capability") for owner in registered]
    if len(capabilities) != len(set(capabilities)):
        fail("registered secret-owner capability coverage is duplicated")
    for owner in registered:
        exact_keys(owner, {"capability", "id", "symbol", "fields", "temporaries", "sanitization_symbol", "cleanup_callers", "evidence", "storage", "output_classification", "partial_failure_policy"}, f"registered secret owner {owner.get('id')}")
        if not owner["fields"] or not owner["temporaries"] or not owner["evidence"]:
            fail(f"registered secret owner {owner['id']} is incomplete")
        capability = owner["capability"]
        if semantic is not None and (
            capability not in semantic
            or semantic[capability]["disposition"] != "implemented"
            or policy["profile"][assignments[capability]]["secret_template"] == "none"
        ):
            fail(f"registered secret owner {owner['id']} lacks an implemented secret capability")
        if (
            owner["id"] != f"registered.{capability}"
            or owner["output_classification"] != "typed-secret-owned"
            or owner["partial_failure_policy"] != "clear-complete-secret-destination"
        ):
            fail(f"registered secret owner {owner['id']} information flow drifted")
        contract = contracts.REGISTERED_OWNER_CONTRACTS.get(owner["id"])
        if contract is None:
            fail(f"registered owner lacks compiler contract: {owner['id']}")
        if owner != {"id": owner["id"], **contract["record"]}:
            fail(f"registered owner differs from compiler contract: {owner['id']}")
        for evidence in owner["evidence"]:
            validate_target(root, evidence, f"registered secret owner {owner['id']} evidence")
    reviews = policy["reviewed-source"]
    paths = [review.get("path") for review in reviews]
    if set(paths) != contracts.REVIEWED_SOURCE_PATHS or len(paths) != len(set(paths)):
        fail("reviewed secret-state source inventory is incomplete or duplicated")
    for review in reviews:
        exact_keys(review, {"path", "sha256"}, "reviewed source")
        path = root / review["path"]
        if not path.is_file() or path.is_symlink() or sha256(path.read_bytes()) != review["sha256"]:
            fail(f"reviewed secret-state source changed: {review['path']}")


def profile_dimensions(profile: dict, owner: str, overrides: dict) -> dict:
    result = {}
    for field, disposition in BUCKETS.items():
        for dimension in profile[field]:
            completion = overrides.get(dimension, owner if disposition == "required" else MILESTONE)
            result[dimension] = {"disposition": disposition, "owner": completion}
    return dict(sorted(result.items()))


def planned_secret_owner(capability: dict, template_name: str, policy: dict) -> dict:
    template = policy["secret-template"][template_name]
    owner = policy["secret-owner-overrides"].get(capability["id"], capability["owner"])
    return {
        "capability": capability["id"],
        "evidence": [capability["test_target"], policy["cleanup"]["mandatory_core_evidence"]],
        "fields": template["fields"],
        "id": f"planned.{capability['id']}",
        "lifecycle_edges": list(LIFECYCLE_EDGES),
        "operations": capability["operations"],
        "owner": owner,
        "residual_risks": list(RESIDUALS),
        "planned_cleanup_contract": "mandatory-core-or-separately-reviewed-equivalent",
        "planned_implementation_target": capability["code_target"],
        "state": "planned",
        "temporaries": template["temporaries"],
    }


def build_register(policy: dict, surfaces: dict, root: Path = ROOT) -> dict:
    assignments = validate_policy(policy, surfaces, root)
    semantic = sorted(
        (row for row in surfaces["surfaces"] if row["kind"] == "semantic"),
        key=lambda row: row["id"],
    )
    capabilities = []
    planned_owners = []
    registered_capabilities = {owner["capability"] for owner in policy["registered-secret-owner"]}
    for row in semantic:
        name = assignments[row["id"]]
        profile = policy["profile"][name]
        capability = {
            "api": profile_dimensions(profile, row["owner"], policy["completion-overrides"].get(row["id"], {})),
            "code_target": row["code_target"],
            "consumer_links": profile["consumers"],
            "disposition": row["disposition"],
            "domain": row["domain"],
            "explicit_rejections": list(REJECTIONS),
            "id": row["id"],
            "normative_sources": row["normative_sources"],
            "operations": profile["operations"],
            "owner": row["owner"],
            "ordinary_hardened_separation": "required" if profile["secret_template"] != "none" else "not-applicable",
            "profile": name,
            "test_target": row["test_target"],
        }
        capabilities.append(capability)
        if (
            profile["secret_template"] != "none"
            and row["id"] not in registered_capabilities
        ):
            planned_owners.append(planned_secret_owner(capability, profile["secret_template"], policy))
    current_owners = []
    for owner in policy["current-secret-owner"]:
        current_owners.append({
            **owner,
            "lifecycle_edges": list(LIFECYCLE_EDGES),
            "output_classification": "typed-secret-owned",
            "partial_failure_policy": "clear-complete-secret-destination",
            "residual_risks": list(RESIDUALS),
            "state": "current",
        })
    registered_owners = []
    for owner in policy["registered-secret-owner"]:
        registered_owners.append({
            **owner,
            "lifecycle_edges": list(LIFECYCLE_EDGES),
            "residual_risks": list(RESIDUALS),
            "state": "registered",
        })
    return {
        "api_dimensions": policy["api"]["dimensions"],
        "capabilities": capabilities,
        "cleanup": policy["cleanup"],
        "current_secret_owners": sorted(current_owners, key=lambda row: row["id"]),
        "explicit_rejections": list(REJECTIONS),
        "planned_secret_owners": sorted(planned_owners, key=lambda row: row["id"]),
        "registered_secret_owners": sorted(registered_owners, key=lambda row: row["id"]),
        "policy_sha256": sha256(POLICY.read_bytes()) if root == ROOT else sha256(json_bytes(policy)),
        "residual_risks": list(RESIDUALS),
        "schema": 1,
        "surface_register_sha256": policy["schema"]["surface_register_sha256"],
    }


def render_coverage(register: dict) -> bytes:
    profiles: dict[str, int] = {}
    dispositions: dict[str, int] = {}
    for capability in register["capabilities"]:
        profiles[capability["profile"]] = profiles.get(capability["profile"], 0) + 1
        dispositions[capability["disposition"]] = dispositions.get(capability["disposition"], 0) + 1
    lines = [
        "# Cryptographic API Profile And Secret-State Register", "",
        "Generated from the reviewed policy and semantic standards surfaces. Do not edit by hand.", "",
        f"- Capabilities: **{len(register['capabilities'])}**",
        f"- API dimensions per capability: **{len(register['api_dimensions'])}**",
        f"- Current secret owners: **{len(register['current_secret_owners'])}**",
        f"- Registered capability owners: **{len(register['registered_secret_owners'])}**",
        f"- Planned secret owners: **{len(register['planned_secret_owners'])}**", "",
        "## Profile Coverage", "", "| Profile | Capabilities |", "| --- | ---: |",
    ]
    lines.extend(f"| `{name}` | {count} |" for name, count in sorted(profiles.items()))
    lines.extend(["", "## Implementation Dispositions", "", "| Disposition | Capabilities |", "| --- | ---: |"])
    lines.extend(f"| `{name}` | {count} |" for name, count in sorted(dispositions.items()))
    lines.extend([
        "", "Every capability classifies every API dimension and binds an owner milestone.",
        "Secret owners enumerate exact fields, temporaries, lifecycle edges, cleanup symbols,",
        "output handling, evidence, and residual risks. Ordinary state never implies hardened",
        "ownership. The optional sanitization adapter cannot replace mandatory core cleanup or",
        "enter the FIPS graph.", "",
    ])
    return "\n".join(lines).encode()
