#!/usr/bin/env python3
"""Validation for the v0.11.1 sanitization admission decision."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tomllib
import urllib.request
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse


RECORD = Path("security/dependency-admissions/sanitization-2.0.3.toml")
DOCUMENT = Path("docs/sanitization-admission-review.md")
CANDIDATE = Path("assurance/sanitization-admission")
PACKAGE = "sanitization"
VERSION = "2.0.3"
SOURCE_COMMIT = "ffcb211cd931c6966b2e767ce5edffa4b47c4f07"
REVIEWED_COMMIT = "d9578b20a5e0ad9c9226648773409466f662e3b6"
PACKAGE_SHA256 = "75e43f2762b31232062e8ba7bfbdfcbd33c80c43bf7a306a7e195c3c4f734e0f"
PROHIBITED_PACKAGES = {"zeroize", "sanitization-derive", "serde", "subtle"}
COMPILERS = [
    "1.90.0",
    "1.91.0",
    "1.92.0",
    "1.93.0",
    "1.94.0",
    "1.95.0",
    "1.96.0",
    "1.96.1",
    "1.97.0",
    "1.97.1",
]
TARGETS = [
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-freebsd",
    "x86_64-apple-darwin",
    "aarch64-linux-android",
    "aarch64-apple-ios",
    "thumbv7em-none-eabi",
    "riscv32imac-unknown-none-elf",
    "x86_64-unknown-none",
]
USER_AGENT = "brynja-admission-check/0.11.1 (https://github.com/valkyoth/brynja)"
MAX_DOWNLOAD = 4 * 1024 * 1024
MAX_MEMBERS = 128
MAX_UNCOMPRESSED = 8 * 1024 * 1024
ALLOWED_HOSTS = {"crates.io", "static.crates.io"}


class AdmissionError(RuntimeError):
    """The committed admission evidence is inconsistent or unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AdmissionError(message)


def read_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise AdmissionError(f"cannot read {path}: {error}") from error


def table(data: dict, name: str) -> dict:
    value = data.get(name)
    require(isinstance(value, dict), f"admission record missing [{name}]")
    return value


def validate_record(root: Path) -> dict:
    data = read_toml(root / RECORD)
    schema = table(data, "schema")
    decision = table(data, "decision")
    package = table(data, "package")
    selection = table(data, "selection")
    unsafe = table(data, "unsafe_inventory")
    verification = table(data, "verification")
    boundary = table(data, "adapter_boundary")
    rereview = table(data, "rereview")
    residual = table(data, "residual_risk")

    require(schema == {"version": 1, "milestone": "0.11.1", "reviewed_on": "2026-08-09"},
            "admission schema or review date drift")
    require(decision.get("status") == "admitted-for-v0.11.2-adapter-only",
            "admission must be adapter-only")
    require(decision.get("production_graph_changed") is False,
            "v0.11.1 must not change the production graph")
    require(decision.get("adapter") == "brynja-sanitization",
            "protocol-neutral adapter name drift")
    require(decision.get("legacy_adapter") == "rejected",
            "legacy sanitization split must remain rejected")
    require(decision.get("fips_boundary") == "excluded",
            "sanitization adapter must remain outside FIPS")

    expected_package = {
        "name": PACKAGE,
        "version": VERSION,
        "registry": "https://crates.io",
        "repository": "https://github.com/valkyoth/sanitization",
        "release_tag": "v2.0.3",
        "source_commit_sha1": SOURCE_COMMIT,
        "reviewed_code_commit_sha1": REVIEWED_COMMIT,
        "package_sha256": PACKAGE_SHA256,
        "license": "MIT OR Apache-2.0",
        "edition": "2021",
        "rust_version": "1.90",
        "no_std": True,
        "build_script": False,
        "native_links": False,
    }
    require(package == expected_package, "audited package identity or policy drift")
    require(selection.get("default_features") is False, "default features must be disabled")
    require(selection.get("features") == [], "no sanitization feature is admitted")
    require(selection.get("direct_runtime_dependencies") == [],
            "selected package must have no runtime dependency")
    require(selection.get("resolved_runtime_packages") == [PACKAGE],
            "activated graph must contain only sanitization")
    require(set(selection.get("prohibited_packages", [])) == PROHIBITED_PACKAGES,
            "prohibited package inventory drift")
    require("asm-compare" in selection.get("prohibited_features", []),
            "upstream default feature must be prohibited")
    require("zeroize-interop" in selection.get("prohibited_features", []),
            "zeroize interoperability must be prohibited")

    require(set(unsafe.get("selected_feature_tcb_files", [])) ==
            {"src/wipe_backend.rs", "src/owned.rs"}, "selected unsafe inventory drift")
    require(unsafe.get("local_unsafe_authorized") is False,
            "dependency admission cannot authorize local unsafe")
    require(verification.get("compilers") == COMPILERS, "compiler evidence matrix drift")
    require(verification.get("targets") == TARGETS, "target evidence matrix drift")
    require(verification.get("additional_compile_only_targets") == ["wasm32-unknown-unknown"],
            "WASM compatibility evidence drift")
    require(verification.get("candidate_fixture") == "assurance/sanitization-admission",
            "candidate fixture binding drift")
    require("zero advisories" in verification.get("advisory_result", ""),
            "advisory result is not clean")
    require("PASS" in verification.get("upstream_pentest", ""),
            "upstream pentest result is not PASS")

    for key in (
        "explicit_dependency_selection",
        "modern_and_legacy_shared",
        "core_destruction_remains_authoritative",
    ):
        require(boundary.get(key) is True, f"adapter boundary requires {key}")
    for key in (
        "implicit_conversions",
        "foreign_trait_implementations",
        "facade_feature",
        "engine_dependency",
        "default_activation",
    ):
        require(boundary.get(key) is False, f"adapter boundary forbids {key}")
    require(boundary.get("upstream_storage") == "sanitization::SecretBytes<N>",
            "admitted upstream storage surface drift")
    require(boundary.get("non_empty_storage") is True,
            "adapter storage must reject empty ownership")
    require(boundary.get("source_failure_type") ==
            "closed payload-free brynja-owned SourceFailure",
            "adapter must reject arbitrary source error payloads")
    require(len(rereview.get("conditions", [])) >= 6, "re-review conditions are incomplete")
    require("withhold or remove" in rereview.get("failure_action", ""),
            "failed re-review must fail closed")
    require(len(residual.get("items", [])) >= 7, "residual-risk inventory is incomplete")
    return data


def validate_document(root: Path) -> None:
    try:
        document = (root / DOCUMENT).read_text(encoding="utf-8")
    except OSError as error:
        raise AdmissionError(f"cannot read {DOCUMENT}: {error}") from error
    for required in (
        "admitted only for conditional implementation",
        PACKAGE_SHA256,
        "default-features = false",
        "brynja-legacy-sanitization` is rejected",
        "cannot satisfy or imply FIPS",
        "forces a new admission review",
    ):
        require(required in document, f"admission document missing {required!r}")


def dependency_names(manifest: dict) -> set[str]:
    names: set[str] = set()
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        values = manifest.get(key, {})
        if isinstance(values, dict):
            names.update(values)
    target = manifest.get("target", {})
    if isinstance(target, dict):
        for settings in target.values():
            if isinstance(settings, dict):
                names.update(dependency_names(settings))
    return names


def validate_production_absence(root: Path) -> None:
    manifests = [root / "Cargo.toml", *sorted((root / "crates").glob("*/Cargo.toml"))]
    for path in manifests:
        names = dependency_names(read_toml(path))
        require(PACKAGE not in names, f"v0.11.1 production dependency found in {path}")
        require("zeroize" not in names, f"prohibited zeroize dependency found in {path}")
    lock = (root / "Cargo.lock").read_text(encoding="utf-8")
    require(f'name = "{PACKAGE}"' not in lock, "sanitization entered the workspace lockfile")
    require('name = "zeroize"' not in lock, "zeroize entered the workspace lockfile")


def validate_candidate(root: Path) -> None:
    manifest = read_toml(root / CANDIDATE / "Cargo.toml")
    require(manifest.get("workspace") == {}, "candidate must be an independent workspace")
    package = table(manifest, "package")
    require(package.get("name") == "brynja-sanitization-admission-fixture",
            "candidate package identity drift")
    require(package.get("version") == "0.0.0" and package.get("publish") is False,
            "candidate must remain unpublished")
    require(package.get("rust-version") == "1.90", "candidate MSRV drift")
    dependency = table(manifest, "dependencies").get(PACKAGE)
    require(dependency == {"version": "=2.0.3", "default-features": False},
            "candidate dependency selection drift")

    lock = read_toml(root / CANDIDATE / "Cargo.lock").get("package", [])
    require(isinstance(lock, list) and len(lock) == 2, "candidate lock graph drift")
    packages = {entry.get("name"): entry for entry in lock}
    require(set(packages) == {"brynja-sanitization-admission-fixture", PACKAGE},
            "candidate lock contains an unexpected package")
    selected = packages[PACKAGE]
    require(selected.get("version") == VERSION and selected.get("checksum") == PACKAGE_SHA256,
            "candidate lock identity or checksum drift")

    source = (root / CANDIDATE / "src/lib.rs").read_text(encoding="utf-8")
    require("#![no_std]" in source and "#![forbid(unsafe_code)]" in source,
            "candidate no_std or unsafe boundary drift")
    for prohibited in ("impl From", "impl Into", "impl core::ops::Deref", "pub inner"):
        require(prohibited not in source, f"candidate exposes prohibited boundary {prohibited}")
    for prohibited in (
        "try_from_fallible<E>",
        "try_replace_from_fallible<E>",
        "map_err(|_error|",
    ):
        require(prohibited not in source,
                f"candidate accepts or discards an arbitrary source error: {prohibited}")
    for required in (
        "CandidateSecret",
        "SecretBytes",
        "EmptySecret",
        "pub struct SourceFailure;",
        "Result<u8, SourceFailure>",
        "map_err(|SourceFailure| CandidateError::SourceFailure)",
    ):
        require(required in source, f"candidate missing frozen behavior {required}")
    require(source.count("Result<u8, SourceFailure>") == 2,
            "both fallible candidate APIs must require SourceFailure")
    require(source.count("map_err(|SourceFailure| CandidateError::SourceFailure)") == 2,
            "both fallible candidate APIs must map the closed error explicitly")


def validate_release_state(root: Path) -> None:
    release = read_toml(root / "release-crates.toml")
    metadata = table(release, "release")
    require(metadata.get("version") == "0.11.1" and metadata.get("milestone") == "0.11.1",
            "release metadata is not v0.11.1")
    require(metadata.get("baseline") == "0.10.0", "cumulative baseline drift")
    require(metadata.get("cumulative_milestones") == ["0.11.0", "0.11.1"],
            "cumulative milestone range drift")
    require(metadata.get("stage") == "internal", "v0.11.1 must remain internal")
    require(metadata.get("exceptional") is True,
            "assessed v0.11.1 must remain exceptional")
    require("Medium secret-bearing error-remanence finding" in
            metadata.get("exception_reason", ""),
            "v0.11.1 exceptional reason must bind the remediated finding")


def archive_member(archive: tarfile.TarFile, suffix: str) -> bytes:
    matches = [member for member in archive.getmembers() if member.name.endswith(suffix)]
    require(len(matches) == 1, f"package archive must contain one {suffix}")
    extracted = archive.extractfile(matches[0])
    require(extracted is not None, f"cannot read package member {suffix}")
    return extracted.read()


def validate_archive(content: bytes) -> None:
    require(hashlib.sha256(content).hexdigest() == PACKAGE_SHA256,
            "sanitization package checksum mismatch")
    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
            members = archive.getmembers()
            require(len(members) <= MAX_MEMBERS, "sanitization package has too many members")
            require(sum(member.size for member in members) <= MAX_UNCOMPRESSED,
                    "sanitization package expands beyond the review bound")
            names = [member.name for member in members]
            for name in names:
                path = PurePosixPath(name)
                require(not path.is_absolute() and ".." not in path.parts,
                        "sanitization package contains an unsafe path")
                require(path.parts and path.parts[0] == f"{PACKAGE}-{VERSION}",
                        "sanitization package root directory drift")
            require(not any(name.endswith("/build.rs") for name in names),
                    "sanitization package unexpectedly contains build.rs")
            manifest = tomllib.loads(archive_member(archive, "/Cargo.toml").decode("utf-8"))
            vcs = json.loads(archive_member(archive, "/.cargo_vcs_info.json"))
            require(all(not member.issym() and not member.islnk() for member in members),
                    "sanitization package contains a link")
    except (tarfile.TarError, UnicodeDecodeError, tomllib.TOMLDecodeError, json.JSONDecodeError) as error:
        raise AdmissionError(f"invalid sanitization package archive: {error}") from error

    package = table(manifest, "package")
    require(package.get("name") == PACKAGE and package.get("version") == VERSION,
            "package archive name or version mismatch")
    require(package.get("license") == "MIT OR Apache-2.0", "package license mismatch")
    require(package.get("rust-version") == "1.90", "package MSRV mismatch")
    require(package.get("edition") == "2021", "package edition mismatch")
    require(package.get("build") is False and "links" not in package,
            "package build or native-link boundary mismatch")
    require(vcs.get("git", {}).get("sha1") == SOURCE_COMMIT, "package source commit mismatch")
    features = table(manifest, "features")
    require(features.get("default") == ["asm-compare"], "upstream default feature drift")
    dependencies = table(manifest, "dependencies")
    require(set(dependencies) == PROHIBITED_PACKAGES,
            "optional dependency inventory drift")
    require(all(value.get("optional") is True for value in dependencies.values()),
            "upstream dependency became mandatory")


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            final = urlparse(response.geturl())
            require(final.scheme == "https" and final.hostname in ALLOWED_HOSTS,
                    "crates.io request redirected outside the authority allowlist")
            content = response.read(MAX_DOWNLOAD + 1)
            require(len(content) <= MAX_DOWNLOAD, "crates.io response exceeds the review bound")
            return content
    except OSError as error:
        raise AdmissionError(f"cannot fetch {url}: {error}") from error


def validate_online() -> None:
    metadata = json.loads(fetch(f"https://crates.io/api/v1/crates/{PACKAGE}"))
    require(metadata.get("crate", {}).get("newest_version") == VERSION,
            "a newer sanitization release requires re-review")
    versions = {entry.get("num"): entry for entry in metadata.get("versions", [])}
    require(versions.get(VERSION, {}).get("checksum") == PACKAGE_SHA256,
            "crates.io sanitization checksum drift")
    validate_archive(fetch(f"https://crates.io/api/v1/crates/{PACKAGE}/{VERSION}/download"))


def validate(root: Path, package_archive: Path | None = None, online: bool = False) -> None:
    validate_record(root)
    validate_document(root)
    validate_production_absence(root)
    validate_candidate(root)
    validate_release_state(root)
    if package_archive is not None:
        validate_archive(package_archive.read_bytes())
    if online:
        validate_online()
