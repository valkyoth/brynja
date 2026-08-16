#!/usr/bin/env python3
"""Validate and execute the v0.22.3 SHA-256 public acceptance boundary."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tarfile
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path("assurance/sha256-public-api")
MANIFEST = FIXTURE / "Cargo.toml"
LOCK = FIXTURE / "Cargo.lock"
LIB = FIXTURE / "src/lib.rs"
MAIN = FIXTURE / "src/main.rs"
CONTENT = FIXTURE / "fixtures/representative.txt"
SHA256_SOURCE = Path("crates/brynja-hash-sha2/src/sha256.rs")
SHA256_TEST = Path("crates/brynja-hash-sha2/tests/sha256.rs")
CHECK_SCRIPT = Path("scripts/check-sha256-public-api.py")
TEST_SCRIPT = Path("scripts/test-sha256-public-api.py")
CHECKS = Path("scripts/checks.sh")
RUST_MATRIX = Path("scripts/check-rust-version-matrix.sh")
BARE_METAL = Path("scripts/check-bare-metal.sh")
WORKFLOW = Path(".github/workflows/ci.yml")
FILES = (
    MANIFEST,
    LOCK,
    LIB,
    MAIN,
    CONTENT,
    SHA256_SOURCE,
    SHA256_TEST,
    CHECK_SCRIPT,
    TEST_SCRIPT,
    CHECKS,
    RUST_MATRIX,
    BARE_METAL,
    WORKFLOW,
)
EXPECTED_SHA256 = {
    MANIFEST: "e5324f6ad25053620f470217e0332aa6dc2955384cd5e5d157599efe5658e247",
    LOCK: "a5967f247416a1104f007bee03148d39edab89cd12676a7352e74b67466c84e4",
    LIB: "096ef101b31b38ededc2aeda9e3b0546757f57fc2875419f920876ce883f64ff",
    MAIN: "5147536fd2bdc395ceed7fb023c9a06971347a8d531c66c0cfde7b78fc878522",
    CONTENT: "a8f34a54459e9655229bb554c15ebb87f89a0bfbc600da8eb56999422fc0487f",
    SHA256_SOURCE: "efbe3a588947e127dd0b0cecbe2b3e3b0a876a354d8d1f798052060d35ddb68d",
    SHA256_TEST: "c3eebf6ae0202321f72ddc131691720c94709e5281f905a5bd7d0fe4a603a3d1",
    CHECK_SCRIPT: "d424a02dcfc778f83ccf8004fc23c9456bd71a759ece3235bdb56f1f0f02ad9d",
    TEST_SCRIPT: "10155923e8769cd405c2e9eaa813c02b50f665daacadfc2da3a90f9dc7f9ab7f",
    CHECKS: "27c51a9cb1a8dfaeadcf337abfbd20698536f9c8d097c4991d62ffc93c0ec84c",
    RUST_MATRIX: "53c776118e5566fd60840fe1f8ac0af87d075165d720524d42836d0721d3fe8e",
    BARE_METAL: "557156b3b6c90603953b717dcd6a027c60955d459049dc2fef8b47a91e112b59",
    WORKFLOW: "fd9c4db449b30be25407372e509a757f67807b1763cd3336293d1ab34d61e755",
}
PACKAGES = (
    ("brynja-hash-core", "0.1.0", ("src/lib.rs",)),
    (
        "brynja-crypto-cpu",
        "0.1.1",
        (
            "src/lib.rs",
            "src/sha256.rs",
            "src/sha256_schedule.rs",
            "src/x86_sha.rs",
            "src/aarch64_sha2.rs",
            "src/riscv64_zknh.rs",
        ),
    ),
    (
        "brynja-hash-sha2",
        "0.1.0",
        (
            "src/lib.rs",
            "src/compress.rs",
            "src/digest.rs",
            "src/error.rs",
            "src/sha224.rs",
            "src/sha256.rs",
        ),
    ),
    ("brynja-crypto", "0.1.2", ("src/lib.rs",)),
)


class AcceptancePolicyError(RuntimeError):
    """The v0.22.3 public acceptance boundary differs from policy."""


def fail(message: str) -> None:
    raise AcceptancePolicyError(message)


def require(text: str, token: str, label: str) -> None:
    if token not in text:
        fail(f"{label} drift: {token}")


def read_regular(root: Path, relative: Path) -> str:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        fail(f"acceptance input must be a regular file: {relative}")
    return path.read_text(encoding="utf-8")


def validate_repository(root: Path = ROOT, check_hashes: bool = True) -> None:
    loaded = {relative: read_regular(root, relative) for relative in FILES}
    for relative in (LIB, MAIN, CHECK_SCRIPT, TEST_SCRIPT):
        if len(loaded[relative].splitlines()) > 500:
            fail(f"acceptance code exceeds 500 lines: {relative}")

    manifest = tomllib.loads(loaded[MANIFEST])
    package = manifest.get("package", {})
    if package != {
        "name": "brynja-sha256-public-api-fixture",
        "version": "0.0.0",
        "edition": "2024",
        "rust-version": "1.90",
        "publish": False,
    }:
        fail("acceptance package identity changed")
    dependencies = manifest.get("dependencies", {})
    if set(dependencies) != {"brynja-crypto", "brynja-hash-sha2"}:
        fail("acceptance dependency boundary changed")
    expected_dependencies = {
        "brynja-crypto": {
            "path": "../../crates/brynja-crypto",
            "version": "=0.1.2",
            "default-features": False,
        },
        "brynja-hash-sha2": {
            "path": "../../crates/brynja-hash-sha2",
            "version": "=0.1.0",
            "default-features": False,
            "features": ["cpu"],
        },
    }
    if dependencies != expected_dependencies:
        fail("acceptance dependencies are not exact ordinary package edges")
    if manifest.get("features") or manifest.get("build-dependencies"):
        fail("acceptance fixture gained hidden features or build dependencies")

    lock = tomllib.loads(loaded[LOCK])
    locked = {
        (entry["name"], entry["version"])
        for entry in lock.get("package", [])
    }
    expected_locked = {
        ("brynja-sha256-public-api-fixture", "0.0.0"),
        *((name, version) for name, version, _required in PACKAGES),
    }
    if locked != expected_locked:
        fail("acceptance lockfile package set changed")
    if any("source" in entry for entry in lock.get("package", [])):
        fail("acceptance fixture gained an external package")

    library = loaded[LIB]
    for token in (
        "#![no_std]",
        "use brynja_crypto::{Sha256 as CryptoSha256, sha256 as crypto_sha256};",
        "use brynja_hash_sha2::{",
        "pub fn run() -> Result<AcceptanceReport, AcceptanceError>",
        "include_bytes!(\"../fixtures/representative.txt\")",
        "MILLION_A_SHA256",
        "check_additional_bytes(Sha256::MAX_MESSAGE_BYTES + 1)",
        "Sha256BackendSession::for_compiled_target().is_some()",
        "let _accelerated_public_entry = sha256_with_backend;",
        "admitted_backends: 0",
        "skipped_unadmitted_backends: 3",
    ):
        require(library, token, "acceptance fixture")
    for forbidden in (
        "unsafe",
        "cfg(brynja_cpu_evidence)",
        "for_candidate_evidence",
        "from_runtime_detection",
        "std::",
        "alloc::",
        "env!",
        "option_env!",
        "Command::",
        "File::",
        "TcpStream",
        "UdpSocket",
    ):
        if forbidden in library:
            fail(f"acceptance fixture crossed forbidden boundary: {forbidden}")

    main = loaded[MAIN]
    for token in (
        "SHA-256 public API acceptance: PASS",
        "independently verified: NO",
        "FIPS 140-3 validated: NO",
        "unkeyed hash; not authentication, a MAC, or password hashing",
        "std::process::exit(1)",
    ):
        require(main, token, "runnable acceptance output")

    source = loaded[SHA256_SOURCE]
    for token in (
        "pub fn check_additional_bytes(&self, additional_bytes: u64)",
        "checked_message_length(self.message_bytes, additional_bytes).map(|_| ())",
        "checked_message_length(self.message_bytes, additional)",
    ):
        require(source, token, "public exhaustion contract")
    tests = loaded[SHA256_TEST]
    require(tests, "fn public_length_preflight_is_exact_and_non_mutating", "SHA-256 tests")

    command = "python3 scripts/check-sha256-public-api.py"
    require(loaded[CHECKS], command, "repository gate")
    require(loaded[RUST_MATRIX], "assurance/sha256-public-api/Cargo.toml", "Rust matrix")
    require(loaded[BARE_METAL], "assurance/sha256-public-api/Cargo.toml", "bare-metal matrix")
    require(loaded[WORKFLOW], "Run SHA-256 public API acceptance", "host CI")

    if check_hashes:
        if set(EXPECTED_SHA256) != set(FILES):
            fail("acceptance reviewed hash inventory is incomplete")
        for relative, text in loaded.items():
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if digest != EXPECTED_SHA256[relative]:
                fail(f"acceptance reviewed source hash drift: {relative}")


def run(command: list[str], cwd: Path = ROOT, success: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
    )
    if (result.returncode == 0) is not success:
        fail(f"unexpected command result ({result.returncode}): {' '.join(command)}\n{result.stdout}")
    return result


def copy_fixture(destination: Path) -> Path:
    fixture = destination / "consumer"
    shutil.copytree(ROOT / FIXTURE, fixture, ignore=shutil.ignore_patterns("target"))
    manifest = (fixture / "Cargo.toml").read_text(encoding="utf-8")
    manifest = manifest.replace("../../crates/brynja-crypto", (ROOT / "crates/brynja-crypto").as_posix())
    manifest = manifest.replace("../../crates/brynja-hash-sha2", (ROOT / "crates/brynja-hash-sha2").as_posix())
    (fixture / "Cargo.toml").write_text(manifest, encoding="utf-8")
    return fixture


def safe_extract(archive: Path, destination: Path) -> Path:
    with tarfile.open(archive, "r:gz") as handle:
        members = handle.getmembers()
        if not members:
            fail(f"empty package archive: {archive.name}")
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk():
                fail(f"unsafe package member: {member.name}")
        handle.extractall(destination, members=members, filter="data")
        roots = {Path(member.name).parts[0] for member in members}
    if len(roots) != 1:
        fail(f"package archive has multiple roots: {archive.name}")
    return destination / next(iter(roots))


def isolated_package_workspace(destination: Path) -> Path:
    workspace = destination / "package-workspace"
    crates = workspace / "crates"
    crates.mkdir(parents=True)
    for name, _version, _required in PACKAGES:
        shutil.copytree(ROOT / "crates" / name, crates / name)

    manifest = """[workspace]
members = ["crates/*"]
resolver = "3"

[workspace.package]
edition = "2024"
rust-version = "1.90"
license = "MIT OR Apache-2.0"
homepage = "https://github.com/valkyoth/brynja"
repository = "https://github.com/valkyoth/brynja"

[workspace.lints.rust]
unsafe_code = "deny"
unsafe_op_in_unsafe_fn = "forbid"
unused_must_use = "deny"
missing_docs = "deny"
unexpected_cfgs = { level = "warn", check-cfg = ['cfg(kani)', 'cfg(brynja_cpu_evidence)'] }

[workspace.lints.clippy]
panic = "forbid"
unwrap_used = "forbid"
expect_used = "forbid"
undocumented_unsafe_blocks = "forbid"
indexing_slicing = "forbid"
arithmetic_side_effects = "forbid"
cast_possible_truncation = "forbid"
cast_sign_loss = "forbid"
too_many_arguments = "forbid"

[workspace.dependencies]
brynja-crypto = { path = "crates/brynja-crypto", version = "=0.1.2" }
brynja-hash-core = { path = "crates/brynja-hash-core", version = "=0.1.0" }
brynja-hash-sha2 = { path = "crates/brynja-hash-sha2", version = "=0.1.0" }
brynja-crypto-cpu = { path = "crates/brynja-crypto-cpu", version = "=0.1.1" }
"""
    (workspace / "Cargo.toml").write_text(manifest, encoding="utf-8")
    return workspace


def package_roots(destination: Path) -> dict[str, Path]:
    workspace = isolated_package_workspace(destination)
    target = destination / "target"
    environment = os.environ.copy()
    environment["CARGO_HOME"] = str(destination / "empty-cargo-home")
    environment["CARGO_TARGET_DIR"] = str(target)
    command = ["cargo", "package"]
    for name, _version, _required in PACKAGES:
        command.extend(("-p", name))
    command.extend(("--allow-dirty", "--no-verify", "--offline"))
    result = subprocess.run(
        command,
        cwd=workspace,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
    )
    if result.returncode != 0:
        fail(f"could not package SHA-256 closure:\n{result.stdout}")

    roots: dict[str, Path] = {}
    for name, version, required in PACKAGES:
        archive = target / "package" / f"{name}-{version}.crate"
        if not archive.is_file():
            fail(f"missing package archive: {archive}")
        root = safe_extract(archive, destination / "packages")
        for common in ("Cargo.toml", "Cargo.toml.orig", "README.md", "LICENSE-APACHE", "LICENSE-MIT"):
            if not (root / common).is_file():
                fail(f"{name} package is missing {common}")
        for relative in required:
            if not (root / relative).is_file():
                fail(f"{name} package is missing {relative}")
        roots[name] = root
    return roots


def packaged_consumer(destination: Path, roots: dict[str, Path]) -> Path:
    fixture = destination / "packaged-consumer"
    shutil.copytree(ROOT / FIXTURE, fixture, ignore=shutil.ignore_patterns("target", "Cargo.lock"))
    manifest = (fixture / "Cargo.toml").read_text(encoding="utf-8")
    manifest = manifest.replace('path = "../../crates/brynja-crypto", ', "")
    manifest = manifest.replace('path = "../../crates/brynja-hash-sha2", ', "")
    (fixture / "Cargo.toml").write_text(manifest, encoding="utf-8")
    config = fixture / ".cargo"
    config.mkdir()
    lines = ["[patch.crates-io]"]
    for name, root in roots.items():
        lines.append(f'{name} = {{ path = "{root.as_posix()}" }}')
    (config / "config.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return fixture


def execute_acceptance() -> str:
    run(["cargo", "test", "--locked", "--manifest-path", str(ROOT / MANIFEST)])
    result = run(["cargo", "run", "--quiet", "--locked", "--manifest-path", str(ROOT / MANIFEST)])
    return result.stdout
