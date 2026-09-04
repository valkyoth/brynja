#!/usr/bin/env python3
"""Enforce every Brynja package class and resolved feature graph."""

from __future__ import annotations

import argparse
import json
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "package-policy.toml"
MODERN_CLASSES = frozenset(
    {
        "modern-facade",
        "modern-router",
        "modern-engine",
        "modern-shared",
        "platform-adapter",
        "protocol-adapter",
        "cpu-backend",
    }
)
LEGACY_CLASSES = frozenset({"legacy-facade", "legacy-engine"})
PRIVATE_CLASSES = frozenset({"repository-only", "research-only"})
ADAPTER_CLASSES = frozenset({"security-adapter", "host-adapter"})
ALL_CLASSES = MODERN_CLASSES | LEGACY_CLASSES | PRIVATE_CLASSES | ADAPTER_CLASSES
EXTERNAL = {
    "sanitization": {
        "version": "2.0.4",
        "source": "registry+https://github.com/rust-lang/crates.io-index",
        "owner": "brynja-sanitization",
    }
}
AMBIGUOUS_LEGACY_NAMES = frozenset(
    {
        "brynja-pct",
        "brynja-snp",
        "brynja-ssl1-research",
        "brynja-ssl2",
        "brynja-ssl3",
        "brynja-tls10",
        "brynja-tls11",
        "brynja-wtls",
    }
)


def load_policy() -> dict[str, dict]:
    with POLICY.open("rb") as handle:
        document = tomllib.load(handle)
    if document.get("schema") != {"version": 1}:
        raise ValueError("package policy schema must be exactly version 1")
    packages = document.get("packages")
    if not isinstance(packages, dict) or not packages:
        raise ValueError("package policy has no package inventory")
    for name, entry in packages.items():
        if entry.get("class") not in ALL_CLASSES:
            raise ValueError(f"{name} has unknown package class")
        if entry.get("publish") not in {"crates-io", "blocked", "never"}:
            raise ValueError(f"{name} has unknown publication class")
        required = entry.get("required")
        optional = entry.get("optional")
        features = entry.get("features", [])
        if (
            not isinstance(required, list)
            or not isinstance(optional, dict)
            or not isinstance(features, list)
            or any(not isinstance(feature, str) or not feature for feature in features)
            or len(features) != len(set(features))
        ):
            raise ValueError(f"{name} has malformed dependency policy")
        if "default" in features or set(features).intersection(optional):
            raise ValueError(f"{name} has ambiguous standalone feature policy")
        dependencies = required + list(optional.values())
        if len(dependencies) != len(set(dependencies)):
            raise ValueError(f"{name} repeats a dependency")
        if name in dependencies:
            raise ValueError(f"{name} depends on itself")
    return packages


def workspace_packages(document: dict) -> tuple[dict[str, dict], dict[str, str]]:
    members = set(document.get("workspace_members", []))
    by_id = {
        package["id"]: package
        for package in document.get("packages", [])
        if package["id"] in members
    }
    if set(by_id) != members:
        raise ValueError("workspace member metadata is incomplete")
    by_name = {package["name"]: package for package in by_id.values()}
    if len(by_name) != len(by_id):
        raise ValueError("workspace package names are not unique")
    external = {
        package["name"]: package
        for package in document.get("packages", [])
        if package["id"] not in members
    }
    if set(external) != set(EXTERNAL):
        raise ValueError(
            "external packages entered the resolved graph: "
            f"expected={sorted(EXTERNAL)}, actual={sorted(external)}"
        )
    for name, expected in EXTERNAL.items():
        package = external[name]
        if package.get("version") != expected["version"]:
            raise ValueError(f"admitted external version drifted for {name}")
        if package.get("source") != expected["source"]:
            raise ValueError(f"admitted external source drifted for {name}")
    return by_name, {name: package["id"] for name, package in by_name.items()}


def expected_publish(entry: dict) -> list[str]:
    return ["crates-io"] if entry["publish"] == "crates-io" else []


def validate_target(name: str, package: dict) -> None:
    targets = package.get("targets", [])
    libraries = [target for target in targets if target.get("kind") == ["lib"]]
    if len(libraries) != 1:
        raise ValueError(f"{name} target must be a library only")
    target = libraries[0]
    if target.get("kind") != ["lib"] or target.get("crate_types") != ["lib"]:
        raise ValueError(f"{name} target must be a library only")
    expected_library = (ROOT / "crates" / name / "src" / "lib.rs").resolve()
    if Path(target.get("src_path", "")).resolve() != expected_library:
        raise ValueError(f"{name} library source escaped its classified package")
    for extra in targets:
        if extra is target:
            continue
        source = Path(extra.get("src_path", "")).resolve()
        expected_tests = (ROOT / "crates" / name / "tests").resolve()
        if (
            extra.get("kind") != ["test"]
            or extra.get("crate_types") != ["bin"]
            or expected_tests not in source.parents
        ):
            raise ValueError(f"{name} may contain only library and integration-test targets")
    if package.get("edition") != "2024":
        raise ValueError(f"{name} must use Rust edition 2024")
    if package.get("rust_version") != "1.90":
        raise ValueError(f"{name} must declare Rust 1.90")
    if package.get("license") != "MIT OR Apache-2.0":
        raise ValueError(f"{name} has unexpected license metadata")
    expected_repository = "https://github.com/valkyoth/brynja"
    if package.get("repository") != expected_repository:
        raise ValueError(f"{name} has unexpected repository metadata")
    if package.get("homepage") != expected_repository:
        raise ValueError(f"{name} has unexpected homepage metadata")
    expected_manifest = (ROOT / "crates" / name / "Cargo.toml").resolve()
    if Path(package.get("manifest_path", "")).resolve() != expected_manifest:
        raise ValueError(f"{name} manifest escaped its classified package directory")
    if not package.get("description"):
        raise ValueError(f"{name} must have a package description")


def validate_dependencies(
    name: str,
    package: dict,
    entry: dict,
    packages: dict[str, dict],
) -> None:
    required = set(entry["required"])
    optional = set(entry["optional"].values())
    expected = required | optional
    dependencies = package.get("dependencies", [])
    actual = {dependency["name"] for dependency in dependencies}
    if actual != expected:
        raise ValueError(
            f"{name} dependency policy mismatch: "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )
    for dependency in dependencies:
        dependency_name = dependency["name"]
        external = dependency_name in EXTERNAL
        if external:
            expected_external = EXTERNAL[dependency_name]
            if name != expected_external["owner"]:
                raise ValueError(f"external dependency owner drifted: {name} -> {dependency_name}")
            if dependency.get("source") != expected_external["source"]:
                raise ValueError(f"admitted external source drifted for {dependency_name}")
            if dependency.get("path") is not None:
                raise ValueError(f"admitted external path override: {dependency_name}")
        elif dependency.get("source") is not None or dependency.get("path") is None:
            raise ValueError(f"external dependency: {name} -> {dependency_name}")
        if dependency.get("kind") is not None or dependency.get("target") is not None:
            raise ValueError(f"{name} has a non-production dependency")
        if dependency.get("optional") != (dependency_name in optional):
            raise ValueError(f"{name} optionality drifted for {dependency_name}")
        allowed_features = (
            ["cpu"]
            if name == "brynja-crypto-cpu-std"
            and dependency_name == "brynja-hash-sha2"
            else []
        )
        if dependency.get("features") != allowed_features:
            raise ValueError(f"{name} directly enables features on {dependency_name}")
        if dependency.get("uses_default_features") is not (not external):
            raise ValueError(f"{name} default-feature policy drifted for {dependency_name}")
        version = EXTERNAL[dependency_name]["version"] if external else packages[dependency_name]["version"]
        expected_req = f"={version}"
        if dependency.get("req") != expected_req:
            raise ValueError(
                f"{name} must pin {dependency_name} to {expected_req}"
            )


def validate_features(name: str, package: dict, entry: dict) -> None:
    expected = {"default": []}
    expected.update(
        {
            feature: [f"dep:{dependency}"]
            for feature, dependency in entry["optional"].items()
        }
    )
    expected.update({feature: [] for feature in entry.get("features", [])})
    if package.get("features") != expected:
        raise ValueError(f"{name} feature policy differs from its package class")


def validate_manifest_inventory(
    packages: dict[str, dict],
    policy: dict[str, dict],
) -> None:
    if set(packages) != set(policy):
        raise ValueError(
            "workspace differs from package policy: "
            f"missing={sorted(set(policy) - set(packages))}, "
            f"extra={sorted(set(packages) - set(policy))}"
        )
    ambiguous = sorted(AMBIGUOUS_LEGACY_NAMES.intersection(packages))
    if ambiguous:
        raise ValueError(f"legacy package lacks explicit prefix: {ambiguous}")
    deprecated = sorted(
        name
        for name in packages
        if name == "brynja-historical" or name.startswith("brynja-historical-")
    )
    if deprecated:
        raise ValueError(f"deprecated historical package name remains: {deprecated}")
    for name, package in packages.items():
        entry = policy[name]
        if package.get("source") is not None:
            raise ValueError(f"external package source: {name}")
        if package.get("publish") != expected_publish(entry):
            raise ValueError(f"{name} publication class is not enforced")
        validate_target(name, package)
        validate_dependencies(name, package, entry, packages)
        validate_features(name, package, entry)


def resolved_edges(document: dict) -> dict[str, set[str]]:
    resolve = document.get("resolve")
    if not isinstance(resolve, dict):
        raise ValueError("Cargo metadata is missing the resolved graph")
    return {
        node["id"]: {dependency["pkg"] for dependency in node["deps"]}
        for node in resolve["nodes"]
    }


def reachable_names(
    root: str,
    names: dict[str, str],
    packages_by_id: dict[str, dict],
    edges: dict[str, set[str]],
) -> set[str]:
    pending = [names[root]]
    seen: set[str] = set()
    while pending:
        package_id = pending.pop()
        if package_id in seen:
            continue
        seen.add(package_id)
        pending.extend(edges.get(package_id, set()))
    return {packages_by_id[package_id]["name"] for package_id in seen}


def validate_resolved_mode(
    document: dict,
    mode: str,
    packages: dict[str, dict],
    packages_by_id: dict[str, dict],
    names: dict[str, str],
    policy: dict[str, dict],
) -> None:
    edges = resolved_edges(document)
    nodes = {node["id"]: node for node in document["resolve"]["nodes"]}
    for name, package in packages.items():
        entry = policy[name]
        expected_dependencies = set(entry["required"])
        expected_features: set[str] = set()
        if mode == "all-features":
            expected_dependencies.update(entry["optional"].values())
            expected_features.update(package["features"])
        if name == "brynja-hash-sha2":
            # Cargo metadata resolves all workspace members together. The host
            # adapter is a root and explicitly enables this optional edge even
            # in the no-default-features metadata run. Facade isolation is
            # checked below after removing that unrelated root's unification.
            expected_dependencies.add("brynja-crypto-cpu")
            expected_features.add("cpu")
        package_id = names[name]
        actual_dependencies = {
            packages_by_id[dependency_id]["name"]
            for dependency_id in edges.get(package_id, set())
        }
        if actual_dependencies != expected_dependencies:
            raise ValueError(f"{name} resolved {mode} dependency graph drifted")
        actual_features = set(nodes[package_id].get("features", []))
        if mode == "no-default-features":
            actual_features.discard("default")
        if actual_features != expected_features:
            raise ValueError(f"{name} resolved {mode} feature set drifted")

    modern_edges = {package_id: set(dependencies) for package_id, dependencies in edges.items()}
    modern_edges[names["brynja-hash-sha2"]].discard(names["brynja-crypto-cpu"])
    modern = reachable_names("brynja", names, packages_by_id, modern_edges)
    if any(policy[name]["class"] not in MODERN_CLASSES for name in modern):
        raise ValueError("modern facade reaches a non-modern package class")
    legacy = reachable_names("brynja-legacy", names, packages_by_id, edges)
    if any(policy[name]["class"] not in LEGACY_CLASSES for name in legacy):
        raise ValueError("legacy facade reaches a non-legacy package class")
    expected_legacy = {"brynja-legacy"}
    if mode == "all-features":
        expected_legacy.update(policy["brynja-legacy"]["optional"].values())
    if legacy != expected_legacy:
        raise ValueError(f"legacy facade {mode} graph is incomplete")
    quic = reachable_names("brynja-quic-tls", names, packages_by_id, edges)
    forbidden_quic = {"brynja-tls", "brynja-tls12", "brynja-tls13"}
    if forbidden_quic.intersection(quic):
        raise ValueError("QUIC reaches stream TLS or its multi-version router")
    if "brynja-tls13-handshake" not in quic:
        raise ValueError("QUIC does not reach the recordless TLS 1.3 handshake")
    adapter = reachable_names("brynja-sanitization", names, packages_by_id, edges)
    if adapter != {"brynja-sanitization", "brynja-core", "sanitization"}:
        raise ValueError("sanitization adapter resolved graph drifted")
    sanitization_id = next(
        package_id
        for package_id, package in packages_by_id.items()
        if package["name"] == "sanitization"
    )
    owners = {
        packages_by_id[owner]["name"]
        for owner, dependencies in edges.items()
        if sanitization_id in dependencies
    }
    if owners != {"brynja-sanitization"}:
        raise ValueError("sanitization external dependency escaped its adapter")
    external_node = nodes.get(sanitization_id)
    if external_node is None or external_node.get("features") != []:
        raise ValueError("sanitization activated an unadmitted feature")
    if edges.get(sanitization_id, set()):
        raise ValueError("sanitization activated a transitive package")
    cpu = reachable_names("brynja-crypto-cpu", names, packages_by_id, edges)
    if cpu != {"brynja-crypto-cpu"}:
        raise ValueError("no_std CPU backend package gained a dependency")
    detector = reachable_names("brynja-crypto-cpu-std", names, packages_by_id, edges)
    if detector != {
        "brynja-core",
        "brynja-crypto-cpu",
        "brynja-crypto-cpu-std",
        "brynja-hash-core",
        "brynja-hash-sha2",
    }:
        raise ValueError("host CPU detector package graph drifted")
    if {"brynja-crypto-cpu", "brynja-crypto-cpu-std"}.intersection(modern):
        raise ValueError("modern facade must remain independent of CPU packages")
    for engine in (
        "brynja-tls",
        "brynja-tls12",
        "brynja-tls13",
        "brynja-tls13-handshake",
        "brynja-dtls",
        "brynja-quic-tls",
    ):
        reached = reachable_names(engine, names, packages_by_id, modern_edges)
        if {"brynja-crypto-cpu", "brynja-crypto-cpu-std"}.intersection(reached):
            raise ValueError(f"protocol engine reaches a CPU adapter: {engine}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("metadata", type=Path)
    parser.add_argument(
        "--mode",
        required=True,
        choices=("no-default-features", "all-features"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    document = json.loads(args.metadata.read_text(encoding="utf-8"))
    policy = load_policy()
    packages_by_id = {
        package["id"]: package for package in document.get("packages", [])
    }
    packages, names = workspace_packages(document)
    validate_manifest_inventory(packages, policy)
    validate_resolved_mode(
        document,
        args.mode,
        packages,
        packages_by_id,
        names,
        policy,
    )
    print(
        f"{args.mode} graph enforces {len(packages)} classified packages, "
        "one exact adapter-owned first-party external package, and modern/legacy isolation"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
