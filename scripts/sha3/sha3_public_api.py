#!/usr/bin/env python3
"""Freeze and validate v0.24.3 portable FIPS 202 public acceptance."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tarfile
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path("assurance/sha3-public-api")
MANIFEST = FIXTURE / "Cargo.toml"
LOCK = FIXTURE / "Cargo.lock"
LIB = FIXTURE / "src/lib.rs"
ALGORITHMS = FIXTURE / "src/algorithms.rs"
VECTORS = FIXTURE / "src/vectors.rs"
MAIN = FIXTURE / "src/main.rs"
CONTENT = FIXTURE / "fixtures/representative.txt"
LEAF_MANIFEST = Path("crates/brynja-hash-sha3/Cargo.toml")
LEAF_LIB = Path("crates/brynja-hash-sha3/src/lib.rs")
LEAF_README = Path("crates/brynja-hash-sha3/README.md")
CRYPTO_LIB = Path("crates/brynja-crypto/src/lib.rs")
FACADE_MANIFEST = Path("crates/brynja/Cargo.toml")
FACADE_LIB = Path("crates/brynja/src/lib.rs")
FACADE_README = Path("crates/brynja/README.md")
CHECK_SCRIPT = Path("scripts/sha3/check-sha3-public-api.py")
TEST_SCRIPT = Path("scripts/sha3/test-sha3-public-api.py")
CHECKS = Path("scripts/checks.sh")
RUST_MATRIX = Path("scripts/ci/check-rust-version-matrix.sh")
BARE_METAL = Path("scripts/assurance/check-bare-metal.sh")
WORKFLOW = Path(".github/workflows/ci.yml")
FILES = (
    MANIFEST, LOCK, LIB, ALGORITHMS, VECTORS, MAIN, CONTENT, LEAF_MANIFEST,
    LEAF_LIB, LEAF_README, CRYPTO_LIB, FACADE_MANIFEST, FACADE_LIB,
    FACADE_README, CHECK_SCRIPT, TEST_SCRIPT, CHECKS, RUST_MATRIX,
    BARE_METAL, WORKFLOW,
)
EXPECTED_SHA256: dict[Path, str] = {
    MANIFEST: "f2f1906a3b02d5783e58509643a3ebf6f15cdf12a6c747eb20b4ce1def058164",
    LOCK: "fae0a5eaf46b7640b007c19d945292a98f95bb87470d73a1e41bb58885bae1b2",
    LIB: "07f19e18011ee25f4dbf86742c5a6d8d51e9ad7bf27709a46b662b4eace559f3",
    ALGORITHMS: "adb8985464a1c2a5656eeb927791f680098d72847a67164539d72f56ad69ffd7",
    VECTORS: "677ff52adaa6b88a2b19e93219238b0751e539afaa7c7d3934740a2c68588d6f",
    MAIN: "5b197ea233e484084eb5a558ca7f39e5f5d031f0f79d15b07c423b36800b21a4",
    CONTENT: "ab72282b43ccf28714e57ff9c4cedde2d3736a5e38eb1016c2d8956615c9cdd3",
    LEAF_MANIFEST: "eada2e7e176152ce759291751a9f65b188d91bb7fd8fa434ac06f4b71097d5af",
    LEAF_LIB: "921dfabcc57ca544af6d15ea5265b804f54a9964d30d7072c87b86f571656757",
    LEAF_README: "3684cb62f1d6001917fb09b58ab00a791434b95e34c4e8982b868c2a4a2e81a5",
    CRYPTO_LIB: "4bec0d1d5fe024652fddeca00f94f7e99de9d93f46734335d57afc1922296569",
    FACADE_MANIFEST: "613815f42c78916c983aed14b275e85fd11c24a45ce543b62e9dbd4da5def56d",
    FACADE_LIB: "4cf4dd2cd7717d13b1b9b96fb6a015ebe73221b8e44ecd8cb4eb67758435e837",
    FACADE_README: "4306c60a7e377e77a24d4e09c920128d53b767d28159afeec670080196cefb90",
    CHECK_SCRIPT: "9bc87be69a13d476a58e6bf7e63f5fd70697d7f57389b03de1a24dc78e679a4e",
    TEST_SCRIPT: "9f0731100eae808a96f049f471bec1d394866828bab6d111bca90e3ac4d3e2eb",
    CHECKS: "babc543411968bcdfe6103352a02fb8e5d98a01646fcb477ca6550fe168d7177",
    RUST_MATRIX: "507516d61f7479220829908c3be21330047ff9b67099533811af8c842534f7bb",
    BARE_METAL: "ffa91450aa0bd6e28d7e22443944221523e8ef4f264239d0fda26fa8387364fb",
    WORKFLOW: "a3f753738c7afd5ec05326f9306d588159dfdd29f087b766d393965271a2741c",
}
PACKAGES = (
    ("brynja-core", "0.9.0", ("src/lib.rs",)),
    ("brynja-crypto-cpu", "0.1.1", (
        "src/lib.rs", "src/sha256.rs", "src/sha512.rs", "src/keccak.rs",
        "src/keccak_constants.rs", "src/x86_avx2_keccak.rs",
        "src/aarch64_sha3_keccak.rs",
    )),
    ("brynja-hash-core", "0.1.0", ("src/lib.rs",)),
    ("brynja-hash-sha2", "0.1.0", ("src/lib.rs", "src/sha256.rs")),
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
    ("brynja", "0.24.7", ("src/lib.rs",)),
)


class AcceptancePolicyError(RuntimeError):
    """The frozen portable FIPS 202 acceptance boundary differs from policy."""


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
        "name": "brynja-sha3-public-api-fixture", "version": "0.0.0",
        "edition": "2024", "rust-version": "1.90", "publish": False,
    }:
        fail("acceptance package identity changed")
    expected_dependencies = {
        "brynja": {"path": "../../crates/brynja", "version": "=0.24.7", "default-features": False},
        "brynja-hash-sha3": {
            "path": "../../crates/brynja-hash-sha3", "version": "=0.1.0",
            "default-features": False,
        },
    }
    if manifest.get("dependencies") != expected_dependencies:
        fail("acceptance dependencies are not exact ordinary package edges")
    if manifest.get("features") or manifest.get("build-dependencies"):
        fail("acceptance fixture gained hidden features or build dependencies")
    leaf_manifest = tomllib.loads(loaded[LEAF_MANIFEST])
    if leaf_manifest.get("features") != {"default": []}:
        fail("portable leaf gained a selectable execution feature")
    if set(leaf_manifest.get("dependencies", {})) != {"brynja-hash-core"}:
        fail("portable leaf dependency boundary changed")
    lock = tomllib.loads(loaded[LOCK])
    locked = {(item["name"], item["version"]) for item in lock.get("package", [])}
    expected_locked = {
        ("brynja-sha3-public-api-fixture", "0.0.0"),
        *((name, version) for name, version, _required in PACKAGES
          if name not in {"brynja-crypto-cpu", "brynja-dtls", "brynja-platform", "brynja-quic-tls"}),
    }
    if locked != expected_locked or any("source" in item for item in lock.get("package", [])):
        fail("acceptance lockfile package set changed or gained an external source")
    fixture = loaded[LIB] + loaded[ALGORITHMS] + loaded[VECTORS]
    for token in (
        "#![no_std]", "pub fn run() -> Result<AcceptanceReport, AcceptanceError>",
        "fixed_output_results: 24", "xof_results: 10", "incremental_squeeze_results: 20",
        "check_exact_rates()?", "check_zero_output()?", "check_exhaustion()?",
        "check_domain_separation()?", "SHAKE128_ABC_343", "SHAKE256_ABC_343",
        "include_bytes!(\"../fixtures/representative.txt\")",
    ):
        require(fixture, token, "complete-family fixture")
    public_algorithms = (
        ("sha3_224", "Sha3_224"), ("sha3_256", "Sha3_256"),
        ("sha3_384", "Sha3_384"), ("sha3_512", "Sha3_512"),
    )
    for function, state in public_algorithms:
        for namespace in ("leaf", "facade"):
            require(loaded[ALGORITHMS], f"{namespace}::{function}(input)", "public digest coverage")
            require(loaded[ALGORITHMS], f"{namespace}::{state}::new()", "public stream coverage")
    for namespace in ("leaf", "facade"):
        require(loaded[LIB], f"{namespace}::shake128(input", "public SHAKE128 coverage")
        require(loaded[LIB], f"{namespace}::shake256(input", "public SHAKE256 coverage")
    for forbidden in (
        "cfg(brynja_cpu_evidence)", "for_candidate_evidence", "std::", "alloc::",
        "unsafe {", "extern \"C\"", "Command::", "File::", "TcpStream", "UdpSocket",
        "crate::keccak", "leaf::keccak", "raw_keccak",
    ):
        if forbidden in fixture:
            fail(f"acceptance fixture crossed forbidden boundary: {forbidden}")
    for token in (
        "execution path: portable-only", "independently verified: NO",
        "FIPS 140-3 validated: NO", "family status: In progress pending v0.24.11",
    ):
        require(loaded[MAIN], token, "runnable acceptance report")
    family_label = "SHA-3/SHAKE"
    require(loaded[LEAF_README], family_label, "leaf family documentation")
    require(loaded[FACADE_README], family_label, "facade family documentation")
    require(loaded[CHECKS], "python3 scripts/sha3/check-sha3-public-api.py", "repository gate")
    require(
        loaded[CHECKS],
        "cargo clippy --locked --manifest-path assurance/sha3-public-api/Cargo.toml",
        "repository Clippy gate",
    )
    require(loaded[CHECKS], "-A clippy::chunks_exact_to_as_chunks -D warnings", "Clippy lint policy")
    require(loaded[RUST_MATRIX], "assurance/sha3-public-api/Cargo.toml", "Rust matrix")
    require(loaded[BARE_METAL], "assurance/sha3-public-api/Cargo.toml", "bare-metal matrix")
    require(loaded[WORKFLOW], "Run complete SHA-3/SHAKE portable public API acceptance", "host CI")
    require(loaded[WORKFLOW], "Lint SHA-3/SHAKE public API fixture", "host Clippy CI")
    require(loaded[WORKFLOW], "-A clippy::chunks_exact_to_as_chunks", "host Clippy compatibility")
    require(loaded[WORKFLOW], "-D warnings", "host Clippy denial")
    if check_hashes:
        if set(EXPECTED_SHA256) != set(FILES):
            fail("acceptance reviewed hash inventory is incomplete")
        for relative, text in loaded.items():
            if hashlib.sha256(text.encode()).hexdigest() != EXPECTED_SHA256[relative]:
                fail(f"acceptance reviewed source hash drift: {relative}")


def run(command: list[str], cwd: Path = ROOT, success: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command, cwd=cwd, check=False, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=240,
    )
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
    manifest = manifest.replace(
        "../../crates/brynja-hash-sha3\"", f'{(ROOT / "crates/brynja-hash-sha3").as_posix()}\"'
    )
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
    result = subprocess.run(
        command, cwd=workspace, env=environment, check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240,
    )
    if result.returncode != 0:
        fail(f"could not package complete SHA-3 closure:\n{result.stdout}")
    roots: dict[str, Path] = {}
    packages = destination / "packages"
    packages.mkdir()
    for name, version, required in PACKAGES:
        archive = target / "package" / f"{name}-{version}.crate"
        if not archive.is_file():
            fail(f"missing package archive: {archive}")
        root = safe_extract(archive, packages)
        for relative in (
            "Cargo.toml", "Cargo.toml.orig", "README.md", "LICENSE-APACHE", "LICENSE-MIT", *required,
        ):
            if not (root / relative).is_file():
                fail(f"{name} package is missing {relative}")
        roots[name] = root
    return roots


def packaged_consumer(destination: Path, roots: dict[str, Path]) -> Path:
    fixture = destination / "packaged-consumer"
    shutil.copytree(ROOT / FIXTURE, fixture, ignore=shutil.ignore_patterns("target", "Cargo.lock"))
    manifest = (fixture / "Cargo.toml").read_text(encoding="utf-8")
    manifest = manifest.replace('path = "../../crates/brynja", ', "")
    manifest = manifest.replace('path = "../../crates/brynja-hash-sha3", ', "")
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
