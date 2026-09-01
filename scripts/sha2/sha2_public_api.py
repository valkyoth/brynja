#!/usr/bin/env python3
"""Validate and execute the v0.23.4 complete SHA-2 public acceptance."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tarfile
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path("assurance/sha2-public-api")
MANIFEST = FIXTURE / "Cargo.toml"
LOCK = FIXTURE / "Cargo.lock"
LIB = FIXTURE / "src/lib.rs"
ALGORITHMS = FIXTURE / "src/algorithms.rs"
VECTORS = FIXTURE / "src/vectors.rs"
MAIN = FIXTURE / "src/main.rs"
CONTENT = FIXTURE / "fixtures/representative.txt"
LEAF_LIB = Path("crates/brynja-hash-sha2/src/lib.rs")
DIGEST = Path("crates/brynja-hash-sha2/src/digest.rs")
FACADE_LIB = Path("crates/brynja/src/lib.rs")
LEAF_README = Path("crates/brynja-hash-sha2/README.md")
FACADE_README = Path("crates/brynja/README.md")
CHECK_SCRIPT = Path("scripts/sha2/check-sha2-public-api.py")
TEST_SCRIPT = Path("scripts/sha2/test-sha2-public-api.py")
CHECKS = Path("scripts/checks.sh")
RUST_MATRIX = Path("scripts/ci/check-rust-version-matrix.sh")
BARE_METAL = Path("scripts/assurance/check-bare-metal.sh")
WORKFLOW = Path(".github/workflows/ci.yml")
FILES = (
    MANIFEST, LOCK, LIB, ALGORITHMS, VECTORS, MAIN, CONTENT, LEAF_LIB, DIGEST,
    FACADE_LIB, LEAF_README, FACADE_README, CHECK_SCRIPT, TEST_SCRIPT, CHECKS,
    RUST_MATRIX, BARE_METAL, WORKFLOW,
)
EXPECTED_SHA256 = {
    MANIFEST: "dd2d04918f98bf35c9815fa98df51d8e0476c90b2b15bb9dc1725c80ec0282d3",
    LOCK: "e46cb4d41801cceac1de21df25258bbff7a3a276566cbeda2952d5111de374d1",
    LIB: "2186c58ea09ffe3e9dcf7a03b70bf4031ec26cd23096569be8016f797b668bca",
    ALGORITHMS: "f5c798334508de76015c92f2929dee7b51e7b76a61fe3bc353bf67e4677a1e63",
    VECTORS: "cc4a0209cd9bbc322a0f2ad0dfaffc3e72337a28e189d9a311b94229e5d8b6d6",
    MAIN: "c16794c16dfabdfc4fbb588c0752e2ef63625657e95df44c987b84103fcddd1c",
    CONTENT: "fcb4220a9a063622c8c2f19d66c56e813a8add0814ece5cb6ec09ca5830d2a71",
    LEAF_LIB: "aa1a4f0ce77768b180daae6ead51a739452d7bd057bbfa8f348df5a7ee3732d2",
    DIGEST: "a861b334e041502bfb56b5de12a4c83468cbfa2440881288aca94c1aa6c08634",
    FACADE_LIB: "90a5ed9ca877470c2f72b2cba9201fb741d9d2edf3a1180fb9c77497245d2f0f",
    LEAF_README: "fa805a3349b095aa6157351f0734cc9f0bdc5adadd939ccd98c55b267b3b409b",
    FACADE_README: "258801b26bdede1d4f63c405a89ff3895f4da500f3d79631b8a5c9e2d97d30ef",
    CHECK_SCRIPT: "08a8b7baae515ba1bb945e14b1a2022a5023b2de02aab94c8d80e67775433b1c",
    TEST_SCRIPT: "7439d5528706f619327d0531a06c11d20877052681f1cacae0a79b19cca6d7e2",
    CHECKS: "19ea5ecb9edf42c7cbaa0cbc6ffa9a0584d17085d9ce9c7e992883145e205773",
    RUST_MATRIX: "507516d61f7479220829908c3be21330047ff9b67099533811af8c842534f7bb",
    BARE_METAL: "ffa91450aa0bd6e28d7e22443944221523e8ef4f264239d0fda26fa8387364fb",
    WORKFLOW: "9cc9ed0c9d324575faf1a79db342a812e66bb4283737e649d607e988b22fc6d9",
}
ALGORITHMS_NAMES = ("SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256")
PACKAGES = (
    ("brynja-core", "0.9.0", ("src/lib.rs",)),
    ("brynja-crypto-cpu", "0.1.1", ("src/lib.rs", "src/sha256.rs", "src/sha512.rs")),
    ("brynja-hash-core", "0.1.0", ("src/lib.rs",)),
    ("brynja-hash-sha2", "0.1.0", (
        "src/lib.rs", "src/compress.rs", "src/compress64.rs", "src/digest.rs",
        "src/error.rs", "src/sha224.rs", "src/sha256.rs", "src/sha384.rs",
        "src/sha512.rs", "src/sha512_224.rs", "src/sha512_256.rs",
        "src/sha512_state.rs", "src/sha512_t.rs",
    )),
    ("brynja-hash-sha3", "0.1.0", (
        "src/lib.rs", "src/digest.rs", "src/error.rs", "src/keccak.rs",
        "src/sha3_224.rs", "src/sha3_256.rs", "src/sha3_384.rs",
        "src/sha3_512.rs", "src/shake128.rs", "src/shake256.rs", "src/sponge.rs",
    )),
    ("brynja-crypto", "0.1.2", ("src/lib.rs",)),
    ("brynja-pki", "0.2.0", ("src/lib.rs",)),
    ("brynja-protocol", "0.1.0", ("src/lib.rs",)),
    ("brynja-tls13-handshake", "0.1.8", ("src/lib.rs",)),
    ("brynja-tls12", "0.1.8", ("src/lib.rs",)),
    ("brynja-tls13", "0.1.8", ("src/lib.rs",)),
    ("brynja-tls", "0.1.8", ("src/lib.rs",)),
    ("brynja-dtls", "0.1.8", ("src/lib.rs",)),
    ("brynja-platform", "0.1.8", ("src/lib.rs",)),
    ("brynja-quic-tls", "0.1.8", ("src/lib.rs",)),
    ("brynja", "0.24.6", ("src/lib.rs",)),
)


class AcceptancePolicyError(RuntimeError):
    """The complete SHA-2 acceptance boundary differs from policy."""


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
    for relative in (LIB, ALGORITHMS, VECTORS, MAIN, CHECK_SCRIPT, TEST_SCRIPT):
        if len(loaded[relative].splitlines()) > 500:
            fail(f"acceptance code exceeds 500 lines: {relative}")
    manifest = tomllib.loads(loaded[MANIFEST])
    if manifest.get("package") != {
        "name": "brynja-sha2-public-api-fixture", "version": "0.0.0",
        "edition": "2024", "rust-version": "1.90", "publish": False,
    }:
        fail("acceptance package identity changed")
    expected_dependencies = {
        "brynja": {"path": "../../crates/brynja", "version": "=0.24.6", "default-features": False},
        "brynja-hash-sha2": {
            "path": "../../crates/brynja-hash-sha2", "version": "=0.1.0",
            "default-features": False, "features": ["cpu"],
        },
    }
    if manifest.get("dependencies") != expected_dependencies:
        fail("acceptance dependencies are not exact ordinary package edges")
    if manifest.get("features") or manifest.get("build-dependencies"):
        fail("acceptance fixture gained hidden features or build dependencies")
    lock = tomllib.loads(loaded[LOCK])
    locked = {(item["name"], item["version"]) for item in lock.get("package", [])}
    expected_locked = {
        ("brynja-sha2-public-api-fixture", "0.0.0"),
        *((name, version) for name, version, _required in PACKAGES if name not in {"brynja-dtls", "brynja-platform", "brynja-quic-tls"}),
    }
    if locked != expected_locked or any("source" in item for item in lock.get("package", [])):
        fail("acceptance lockfile package set changed or gained an external source")
    library = loaded[LIB]
    for token in (
        "#![no_std]", "pub fn run() -> Result<AcceptanceReport, AcceptanceError>",
        "one_shot_results: 30", "streaming_results: 36", "check_distinct_identities()?",
        "skipped_unadmitted_backends: 5", "Sha256BackendSession::for_compiled_target().is_some()",
        "Sha512BackendSession::for_compiled_target().is_some()", "sha512_256_with_backend",
    ):
        require(library, token, "complete-family fixture")
    for forbidden in (
        "cfg(brynja_cpu_evidence)", "for_candidate_evidence", "from_runtime_detection",
        "std::", "alloc::", "env!", "option_env!", "Command::", "File::", "TcpStream", "UdpSocket",
    ):
        if forbidden in library + loaded[ALGORITHMS] + loaded[VECTORS]:
            fail(f"acceptance fixture crossed forbidden boundary: {forbidden}")
    for name in ALGORITHMS_NAMES:
        require(loaded[MAIN], f"{name}: portable scalar; independently verified: NO; FIPS validated: NO", "runnable report")
        require(loaded[LEAF_README], name, "leaf documentation")
        require(loaded[FACADE_README], name, "facade documentation")
    leaf_family_label = "SHA-2 (all six identities have complete byte APIs; arbitrary-bit and hardened secret-bearing profiles pending)"
    facade_family_label = "SHA-2 (FIPS 180-4: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256 have complete byte APIs; arbitrary-bit and hardened profiles pending)"
    require(loaded[LEAF_README], leaf_family_label, "leaf family documentation")
    require(loaded[FACADE_README], facade_family_label, "facade family documentation")
    public_algorithms = (
        ("sha224", "Sha224"),
        ("sha256", "Sha256"),
        ("sha384", "Sha384"),
        ("sha512", "Sha512"),
        ("sha512_224", "Sha512_224"),
        ("sha512_256", "Sha512_256"),
    )
    for function, state in public_algorithms:
        for namespace in ("leaf", "facade"):
            require(loaded[ALGORITHMS], f"{namespace}::{function}(input)", "public one-shot coverage")
            require(loaded[ALGORITHMS], f"{namespace}::{state}::new()", "public streaming coverage")
    for token in ("Sha224Digest, 28", "Sha256Digest, 32", "Sha384Digest, 48", "Sha512Digest, 64", "Sha512_224Digest, 28", "Sha512_256Digest, 32"):
        require(loaded[DIGEST], token, "output identity")
    require(loaded[CHECKS], "python3 scripts/sha2/check-sha2-public-api.py", "repository gate")
    require(loaded[RUST_MATRIX], "assurance/sha2-public-api/Cargo.toml", "Rust matrix")
    require(loaded[BARE_METAL], "assurance/sha2-public-api/Cargo.toml", "bare-metal matrix")
    require(loaded[WORKFLOW], "Run complete SHA-2 public API acceptance", "host CI")
    if check_hashes:
        if set(EXPECTED_SHA256) != set(FILES):
            fail("acceptance reviewed hash inventory is incomplete")
        for relative, text in loaded.items():
            if hashlib.sha256(text.encode()).hexdigest() != EXPECTED_SHA256[relative]:
                fail(f"acceptance reviewed source hash drift: {relative}")


def run(command: list[str], cwd: Path = ROOT, success: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, check=False, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=240)
    if (result.returncode == 0) is not success:
        fail(f"unexpected command result ({result.returncode}): {' '.join(command)}\n{result.stdout}")
    return result


def copy_policy_tree(destination: Path) -> Path:
    root = destination / "repository"
    for relative in FILES:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    return root


def copy_fixture(destination: Path) -> Path:
    fixture = destination / "consumer"
    shutil.copytree(ROOT / FIXTURE, fixture, ignore=shutil.ignore_patterns("target"))
    manifest = (fixture / "Cargo.toml").read_text(encoding="utf-8")
    manifest = manifest.replace("../../crates/brynja\"", f'{(ROOT / "crates/brynja").as_posix()}\"')
    manifest = manifest.replace("../../crates/brynja-hash-sha2\"", f'{(ROOT / "crates/brynja-hash-sha2").as_posix()}\"')
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
    dependencies = "\n".join(
        f'{name} = {{ path = "crates/{name}", version = "={version}" }}'
        for name, version, _required in PACKAGES if name != "brynja"
    )
    manifest = f'''[workspace]
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
unexpected_cfgs = {{ level = "warn", check-cfg = ['cfg(kani)', 'cfg(brynja_cpu_evidence)'] }}

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
{dependencies}
'''
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
    result = subprocess.run(command, cwd=workspace, env=environment, check=False, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240)
    if result.returncode != 0:
        fail(f"could not package complete SHA-2 closure:\n{result.stdout}")
    roots = {}
    packages = destination / "packages"
    packages.mkdir()
    for name, version, required in PACKAGES:
        archive = target / "package" / f"{name}-{version}.crate"
        if not archive.is_file():
            fail(f"missing package archive: {archive}")
        root = safe_extract(archive, packages)
        for relative in ("Cargo.toml", "Cargo.toml.orig", "README.md", "LICENSE-APACHE", "LICENSE-MIT", *required):
            if not (root / relative).is_file():
                fail(f"{name} package is missing {relative}")
        roots[name] = root
    return roots


def packaged_consumer(destination: Path, roots: dict[str, Path]) -> Path:
    fixture = destination / "packaged-consumer"
    shutil.copytree(ROOT / FIXTURE, fixture, ignore=shutil.ignore_patterns("target", "Cargo.lock"))
    manifest = (fixture / "Cargo.toml").read_text(encoding="utf-8")
    manifest = manifest.replace('path = "../../crates/brynja", ', "")
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
