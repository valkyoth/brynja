#!/usr/bin/env python3
"""Exercise positive and negative package-class and feature-graph fixtures."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path


VALIDATOR = Path(__file__).with_name("validate-workspace-metadata.py")


def package(document: dict, name: str) -> dict:
    return next(item for item in document["packages"] if item["name"] == name)


def package_id(document: dict, name: str) -> str:
    return package(document, name)["id"]


def node(document: dict, name: str) -> dict:
    identifier = package_id(document, name)
    return next(item for item in document["resolve"]["nodes"] if item["id"] == identifier)


def dependency(document: dict, owner: str, name: str) -> dict:
    return next(
        item for item in package(document, owner)["dependencies"] if item["name"] == name
    )


def validator_result(
    document: dict,
    mode: str,
) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as fixture:
        json.dump(document, fixture)
        fixture.flush()
        return subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--mode",
                mode,
                fixture.name,
            ],
            check=False,
            capture_output=True,
            text=True,
        )


def require_rejection(
    document: dict,
    mode: str,
    expected: str,
    label: str,
) -> None:
    result = validator_result(document, mode)
    if result.returncode == 0:
        raise AssertionError(f"workspace validator accepted {label}")
    if expected not in result.stderr:
        raise AssertionError(
            f"{label} did not report {expected!r}: {result.stderr.strip()}"
        )


def metadata(*options: str) -> dict:
    return json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--format-version", "1", *options],
            text=True,
        )
    )


def graph_dependency(document: dict, owner: str, dependency_name: str) -> dict:
    return {
        "name": dependency_name.replace("-", "_"),
        "pkg": package_id(document, dependency_name),
        "dep_kinds": [{"kind": None, "target": None}],
    }


def test_baselines(no_default: dict, all_features: dict) -> None:
    for document, mode in (
        (no_default, "no-default-features"),
        (all_features, "all-features"),
    ):
        accepted = validator_result(document, mode)
        if accepted.returncode != 0:
            raise AssertionError(
                f"workspace validator rejected {mode}: {accepted.stderr}"
            )


def test_inventory_and_names(baseline: dict) -> None:
    ambiguous = copy.deepcopy(baseline)
    package(ambiguous, "brynja-legacy-ssl2")["name"] = "brynja-ssl2"
    require_rejection(
        ambiguous,
        "all-features",
        "workspace differs from package policy",
        "an ambiguously named legacy crate",
    )

    deprecated = copy.deepcopy(baseline)
    package(deprecated, "brynja-legacy-ssl2")["name"] = "brynja-historical-ssl2"
    require_rejection(
        deprecated,
        "all-features",
        "workspace differs from package policy",
        "the deprecated historical prefix",
    )

    missing = copy.deepcopy(baseline)
    removed = package_id(missing, "brynja-proofs")
    missing["workspace_members"].remove(removed)
    require_rejection(
        missing,
        "all-features",
        "external packages entered",
        "an unclassified workspace package",
    )


def test_manifest_classes(baseline: dict) -> None:
    published_legacy = copy.deepcopy(baseline)
    package(published_legacy, "brynja-legacy-ssl2")["publish"] = ["crates-io"]
    require_rejection(
        published_legacy,
        "all-features",
        "publication class is not enforced",
        "a publishable legacy engine",
    )

    published_repository = copy.deepcopy(baseline)
    package(published_repository, "brynja-research-ssl1")["publish"] = [
        "crates-io"
    ]
    require_rejection(
        published_repository,
        "all-features",
        "publication class is not enforced",
        "a publishable research crate",
    )

    wrong_edition = copy.deepcopy(baseline)
    package(wrong_edition, "brynja-core")["edition"] = "2021"
    require_rejection(
        wrong_edition,
        "all-features",
        "must use Rust edition 2024",
        "edition drift",
    )

    binary_target = copy.deepcopy(baseline)
    package(binary_target, "brynja-core")["targets"][0]["kind"] = ["bin"]
    require_rejection(
        binary_target,
        "all-features",
        "target must be a library only",
        "a binary product target",
    )

    escaped_library = copy.deepcopy(baseline)
    package(escaped_library, "brynja-core")["targets"][0]["src_path"] = (
        "/tmp/unreviewed-brynja-core.rs"
    )
    require_rejection(
        escaped_library,
        "all-features",
        "library source escaped its classified package",
        "a library source outside the unsafe inventory",
    )

    wrong_repository = copy.deepcopy(baseline)
    package(wrong_repository, "brynja-core")["repository"] = (
        "https://example.invalid/brynja"
    )
    require_rejection(
        wrong_repository,
        "all-features",
        "unexpected repository metadata",
        "repository metadata drift",
    )


def test_dependency_contracts(baseline: dict) -> None:
    external = copy.deepcopy(baseline)
    dependency(external, "brynja-pki", "brynja-core")["source"] = (
        "registry+https://github.com/rust-lang/crates.io-index"
    )
    require_rejection(
        external,
        "all-features",
        "external dependency",
        "a registry dependency",
    )

    wrong_pin = copy.deepcopy(baseline)
    dependency(wrong_pin, "brynja-pki", "brynja-core")["req"] = "^0.1"
    require_rejection(
        wrong_pin,
        "all-features",
        "must pin brynja-core",
        "a non-exact workspace dependency",
    )

    default_features = copy.deepcopy(baseline)
    dependency(default_features, "brynja-pki", "brynja-core")[
        "uses_default_features"
    ] = False
    require_rejection(
        default_features,
        "all-features",
        "default-feature policy drifted",
        "workspace dependency default-feature drift",
    )

    optionality = copy.deepcopy(baseline)
    dependency(optionality, "brynja", "brynja-dtls")["optional"] = False
    require_rejection(
        optionality,
        "all-features",
        "optionality drifted",
        "an optional boundary made mandatory",
    )

    legacy_dependency = copy.deepcopy(baseline)
    package(legacy_dependency, "brynja-legacy-ssl2")["dependencies"].append(
        copy.deepcopy(dependency(legacy_dependency, "brynja-pki", "brynja-core"))
    )
    require_rejection(
        legacy_dependency,
        "all-features",
        "dependency policy mismatch",
        "an undeclared legacy-to-modern dependency",
    )

    wrong_admitted_pin = copy.deepcopy(baseline)
    dependency(wrong_admitted_pin, "brynja-sanitization", "sanitization")["req"] = "^2"
    require_rejection(
        wrong_admitted_pin,
        "all-features",
        "must pin sanitization to =2.0.3",
        "a floating sanitization adapter pin",
    )

    admitted_defaults = copy.deepcopy(baseline)
    dependency(admitted_defaults, "brynja-sanitization", "sanitization")[
        "uses_default_features"
    ] = True
    require_rejection(
        admitted_defaults,
        "all-features",
        "default-feature policy drifted for sanitization",
        "sanitization upstream defaults",
    )

    admitted_feature = copy.deepcopy(baseline)
    dependency(admitted_feature, "brynja-sanitization", "sanitization")["features"] = [
        "zeroize-interop"
    ]
    require_rejection(
        admitted_feature,
        "all-features",
        "directly enables features on sanitization",
        "sanitization feature activation",
    )

    version_drift = copy.deepcopy(baseline)
    package(version_drift, "sanitization")["version"] = "2.0.4"
    require_rejection(
        version_drift,
        "all-features",
        "admitted external version drifted",
        "sanitization package version drift",
    )


def test_feature_contracts(baseline: dict) -> None:
    modern_feature = copy.deepcopy(baseline)
    package(modern_feature, "brynja")["features"]["legacy-ssl2"] = [
        "dep:brynja-legacy-ssl2"
    ]
    require_rejection(
        modern_feature,
        "all-features",
        "feature policy differs",
        "legacy feature smuggling through the modern facade",
    )

    default_feature = copy.deepcopy(baseline)
    package(default_feature, "brynja")["features"]["default"] = ["dtls"]
    require_rejection(
        default_feature,
        "all-features",
        "feature policy differs",
        "a non-empty default feature",
    )


def test_resolved_isolation(all_features: dict, no_default: dict) -> None:
    modern_leak = copy.deepcopy(all_features)
    node(modern_leak, "brynja")["deps"].append(
        graph_dependency(modern_leak, "brynja", "brynja-legacy-ssl2")
    )
    require_rejection(
        modern_leak,
        "all-features",
        "resolved all-features dependency graph drifted",
        "a modern-to-legacy resolved edge",
    )

    legacy_leak = copy.deepcopy(all_features)
    node(legacy_leak, "brynja-legacy")["deps"].append(
        graph_dependency(legacy_leak, "brynja-legacy", "brynja-core")
    )
    require_rejection(
        legacy_leak,
        "all-features",
        "resolved all-features dependency graph drifted",
        "a legacy-to-modern resolved edge",
    )

    missing_legacy = copy.deepcopy(all_features)
    ssl2 = package_id(missing_legacy, "brynja-legacy-ssl2")
    legacy = node(missing_legacy, "brynja-legacy")
    legacy["deps"] = [item for item in legacy["deps"] if item["pkg"] != ssl2]
    require_rejection(
        missing_legacy,
        "all-features",
        "resolved all-features dependency graph drifted",
        "an incomplete legacy all-feature graph",
    )

    missing_engine = copy.deepcopy(all_features)
    tls12 = package_id(missing_engine, "brynja-tls12")
    router = node(missing_engine, "brynja-tls")
    router["deps"] = [item for item in router["deps"] if item["pkg"] != tls12]
    require_rejection(
        missing_engine,
        "all-features",
        "resolved all-features dependency graph drifted",
        "an evergreen router without TLS 1.2",
    )

    quic_stream = copy.deepcopy(all_features)
    node(quic_stream, "brynja-quic-tls")["deps"].append(
        graph_dependency(quic_stream, "brynja-quic-tls", "brynja-tls13")
    )
    require_rejection(
        quic_stream,
        "all-features",
        "resolved all-features dependency graph drifted",
        "a QUIC-to-stream-TLS dependency",
    )

    no_default_optional = copy.deepcopy(no_default)
    node(no_default_optional, "brynja")["deps"].append(
        graph_dependency(no_default_optional, "brynja", "brynja-dtls")
    )
    require_rejection(
        no_default_optional,
        "no-default-features",
        "resolved no-default-features dependency graph drifted",
        "optional DTLS activation without a feature",
    )

    facade_adapter = copy.deepcopy(all_features)
    node(facade_adapter, "brynja")["deps"].append(
        graph_dependency(facade_adapter, "brynja", "brynja-sanitization")
    )
    require_rejection(
        facade_adapter,
        "all-features",
        "resolved all-features dependency graph drifted",
        "facade activation of the sanitization adapter",
    )

    facade_detector = copy.deepcopy(all_features)
    node(facade_detector, "brynja")["deps"].append(
        graph_dependency(facade_detector, "brynja", "brynja-crypto-cpu-std")
    )
    require_rejection(
        facade_detector,
        "all-features",
        "resolved all-features dependency graph drifted",
        "host CPU detector smuggling through the facade",
    )

    facade_cpu = copy.deepcopy(all_features)
    node(facade_cpu, "brynja")["deps"].append(
        graph_dependency(facade_cpu, "brynja", "brynja-crypto-cpu")
    )
    require_rejection(
        facade_cpu,
        "all-features",
        "resolved all-features dependency graph drifted",
        "CPU package smuggling through the facade",
    )

    engine_cpu = copy.deepcopy(all_features)
    node(engine_cpu, "brynja-tls13")["deps"].append(
        graph_dependency(engine_cpu, "brynja-tls13", "brynja-crypto-cpu")
    )
    require_rejection(
        engine_cpu,
        "all-features",
        "resolved all-features dependency graph drifted",
        "CPU package smuggling through a protocol engine",
    )

    upstream_feature = copy.deepcopy(all_features)
    node(upstream_feature, "sanitization")["features"] = ["zeroize-interop"]
    require_rejection(
        upstream_feature,
        "all-features",
        "sanitization activated an unadmitted feature",
        "resolved upstream feature activation",
    )


def test_keylog_isolation(baseline: dict) -> None:
    support = package(baseline, "brynja-test-support")
    dependency_names = [item["name"] for item in support["dependencies"]]
    if support["publish"] != [] or dependency_names != ["brynja-core"]:
        raise AssertionError("test support is not repository-isolated")
    support_id = package_id(baseline, "brynja-test-support")
    for owner in (
        "brynja",
        "brynja-core",
        "brynja-crypto",
        "brynja-pki",
        "brynja-platform",
        "brynja-tls",
        "brynja-tls12",
        "brynja-tls13",
        "brynja-tls13-handshake",
        "brynja-dtls",
        "brynja-quic-tls",
    ):
        if any(item["pkg"] == support_id for item in node(baseline, owner)["deps"]):
            raise AssertionError(f"production package reaches key logging: {owner}")


def reject_invalid_and_exhausted(baseline: dict) -> None:
    published = copy.deepcopy(baseline)
    package(published, "brynja-test-support")["publish"] = ["crates-io"]
    require_rejection(
        published,
        "all-features",
        "publication class is not enforced",
        "publishable key-log test support",
    )

    production_edge = copy.deepcopy(baseline)
    node(production_edge, "brynja")["deps"].append(
        graph_dependency(production_edge, "brynja", "brynja-test-support")
    )
    require_rejection(
        production_edge,
        "all-features",
        "resolved all-features dependency graph drifted",
        "production key-log dependency smuggling",
    )


def main() -> int:
    no_default = metadata("--no-default-features")
    all_features = metadata("--all-features")
    test_baselines(no_default, all_features)
    test_inventory_and_names(all_features)
    test_manifest_classes(all_features)
    test_dependency_contracts(all_features)
    test_feature_contracts(all_features)
    test_resolved_isolation(all_features, no_default)
    test_keylog_isolation(all_features)
    reject_invalid_and_exhausted(all_features)
    print("workspace policy rejects 33 package-class, external-admission, and feature-graph regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
