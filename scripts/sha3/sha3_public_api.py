#!/usr/bin/env python3
"""Freeze and validate final v0.24.11 portable FIPS 202 public acceptance."""

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
BIT_API = FIXTURE / "src/bit_api.rs"
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
    MANIFEST, LOCK, LIB, BIT_API, ALGORITHMS, VECTORS, MAIN, CONTENT, LEAF_MANIFEST,
    LEAF_LIB, LEAF_README, CRYPTO_LIB, FACADE_MANIFEST, FACADE_LIB,
    FACADE_README, CHECK_SCRIPT, TEST_SCRIPT, CHECKS, RUST_MATRIX,
    BARE_METAL, WORKFLOW,
)
EXPECTED_SHA256: dict[Path, str] = {
    MANIFEST: "33363f84dd5e08bc101b9158ade9f53229a1d9a2b7b46ed9c46c0cd9f9126a43",
    LOCK: "cf2c4991865a25e10c0917a79c7877f30003f1fcf89e308d52d807e3bd3312fc",
    LIB: "06a093ae03acef95271d075c5582c51b5b83d63a62d30a3e1e547d1b72ce4395",
    BIT_API: "f63d7862befc7ad6ce82c63d05919ac556ef64d5ecd4d28f2b1e849ac8d6174e",
    ALGORITHMS: "adb8985464a1c2a5656eeb927791f680098d72847a67164539d72f56ad69ffd7",
    VECTORS: "677ff52adaa6b88a2b19e93219238b0751e539afaa7c7d3934740a2c68588d6f",
    MAIN: "676f7e6dfc44120ea26cc0a2cf69717ab21fb6bbd22c68039b20c8807e810161",
    CONTENT: "ab72282b43ccf28714e57ff9c4cedde2d3736a5e38eb1016c2d8956615c9cdd3",
    LEAF_MANIFEST: "bf0467a994e4fa3a879e9e66dc2cda39e12738e7073f1bff96c008704bda3408",
    LEAF_LIB: "dbfe8430883784c4efadd9392bb56daee860a9631db82287402d558614b54fc7",
    LEAF_README: "77eadf3e2bb196ba0d8d21f2f71acf2388718ec9a09d5ad072d1b92eab21aa5d",
    CRYPTO_LIB: "bb425769dbf02a1c39a386196d013ab38f92f200f368f95d0911914f321f8785",
    FACADE_MANIFEST: "f46b87c914698b3047603fd895f83ab1b0d37d98c59882c8a9006aabd035452a",
    FACADE_LIB: "dfa6311a5a73bed4547611739752052e8e98c30de7c8cd9536d1b0d0ebad8deb",
    FACADE_README: "1327263f8fd19aa5e6741b04bab1c52dd9767317dfbdeab124aa1dd409e6d2d4",
    CHECK_SCRIPT: "37b6f0605770c8948fd8972640bf4ca978c3536ac832c1ffc733cea235f2b62b",
    TEST_SCRIPT: "20010f7a853d382b1b7f12a0df2e0b65793d3be02bf9e6b16db70f4e9977ae40",
    CHECKS: "e3f90fd79c67ed3c850335a3bea81cd67c1722b657046ced8ccbaa17175d9402",
    RUST_MATRIX: "7bd260c89d648a989482f9ad657565f55e416862d8361b0aa2de731454de89e7",
    BARE_METAL: "5795c3631464d8369d816cbb542680c8790a91cbf01e286e16a5a0e3c7a64876",
    WORKFLOW: "9b5ed1a139641356c6267b0190486786de40f1c549c7d3dd2fb750dfcfee29ed",
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
        "src/lib.rs", "src/bit_api.rs", "src/bit_string.rs", "src/digest.rs",
        "src/error.rs", "src/keccak.rs",
        "src/sha3_224.rs", "src/sha3_256.rs", "src/sha3_384.rs",
        "src/sha3_512.rs", "src/shake128.rs", "src/shake256.rs", "src/sponge.rs",
    )),
    ("brynja-mac-kmac", "0.1.0", (
        "src/lib.rs", "src/backend.rs", "src/core_state.rs", "src/error.rs",
        "src/fixed.rs", "src/output.rs", "src/packer.rs", "src/policy.rs",
        "src/verify.rs", "src/xof.rs",
    )),
    ("brynja-hash-tuple", "0.1.0", (
        "src/lib.rs", "src/backend.rs", "src/core_state.rs", "src/error.rs",
        "src/fixed.rs", "src/item.rs", "src/output.rs", "src/xof.rs",
    )),
    ("brynja-hash-parallel", "0.1.0", (
        "src/lib.rs", "src/backend.rs", "src/core_state.rs", "src/error.rs",
        "src/fixed.rs", "src/output.rs", "src/scheduled.rs", "src/xof.rs",
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
    ("brynja", "0.24.19", ("src/lib.rs",)),
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
    for relative in (LIB, BIT_API, ALGORITHMS, VECTORS, MAIN, CHECK_SCRIPT, TEST_SCRIPT):
        if len(loaded[relative].splitlines()) > 500:
            fail(f"acceptance code exceeds 500 lines: {relative}")
    manifest = tomllib.loads(loaded[MANIFEST])
    if manifest.get("package") != {
        "name": "brynja-sha3-public-api-fixture", "version": "0.0.0",
        "edition": "2024", "rust-version": "1.90", "publish": False,
    }:
        fail("acceptance package identity changed")
    expected_dependencies = {
        "brynja": {"path": "../../crates/brynja", "version": "=0.24.19", "default-features": False},
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
    if set(leaf_manifest.get("dependencies", {})) != {"brynja-core", "brynja-hash-core"}:
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
    fixture = loaded[LIB] + loaded[BIT_API] + loaded[ALGORITHMS] + loaded[VECTORS]
    for token in (
        "#![no_std]", "pub fn run() -> Result<AcceptanceReport, AcceptanceError>",
        "fixed_output_results: 24", "xof_results: 10", "incremental_squeeze_results: 20",
        "let bit_domain_results = bit_api::check()?", "bit_domain_results,",
        "leaf::FIPS202_BIT_INPUT_IMPLEMENTED", "leaf::FIPS202_BIT_OUTPUT_IMPLEMENTED",
        "facade::FIPS202_BIT_INPUT_IMPLEMENTED", "facade::FIPS202_BIT_OUTPUT_IMPLEMENTED",
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
        require(loaded[BIT_API], f"{namespace}::Fips202BitString::new", "bit input coverage")
        require(loaded[BIT_API], f"{namespace}::Fips202Output::new", "bit output coverage")
        require(loaded[BIT_API], f"{namespace}::shake128_bits", "SHAKE128 bit coverage")
        require(loaded[BIT_API], f"{namespace}::shake256_bits", "SHAKE256 bit coverage")
        expected_output_paths = 3 if namespace == "leaf" else 2
        if loaded[BIT_API].count(f"{namespace}::Fips202Output::new") != expected_output_paths:
            fail(f"{namespace} bit output coverage count changed")
    for forbidden in (
        "cfg(brynja_cpu_evidence)", "for_candidate_evidence", "std::", "alloc::",
        "unsafe {", "extern \"C\"", "Command::", "File::", "TcpStream", "UdpSocket",
        "crate::keccak", "leaf::keccak", "raw_keccak",
    ):
        if forbidden in fixture:
            fail(f"acceptance fixture crossed forbidden boundary: {forbidden}")
    for token in (
        "execution path: portable-only", "independently verified: NO",
        "FIPS 140-3 validated: NO", "family status: Fully implemented at v0.24.11",
    ):
        require(loaded[MAIN], token, "runnable acceptance report")
    family_label = "SHA-3/SHAKE"
    require(loaded[LEAF_README], family_label, "leaf family documentation")
    require(loaded[FACADE_README], family_label, "facade family documentation")
    require(loaded[CHECKS], "python3 scripts/sha3/check-sha3-public-api.py", "repository gate")
    require(loaded[CHECKS], "python3 scripts/sha3/check-sha3-bit-differential.py", "bit differential gate")
    require(
        loaded[CHECKS],
        "cargo clippy --locked --manifest-path assurance/sha3-public-api/Cargo.toml",
        "repository Clippy gate",
    )
    require(loaded[CHECKS], "-A clippy::chunks_exact_to_as_chunks -D warnings", "Clippy lint policy")
    require(loaded[RUST_MATRIX], "assurance/sha3-public-api/Cargo.toml", "Rust matrix")
    require(loaded[BARE_METAL], "assurance/sha3-public-api/Cargo.toml", "bare-metal matrix")
    require(loaded[WORKFLOW], "Run complete SHA-3/SHAKE portable public API acceptance", "host CI")
    require(loaded[WORKFLOW], "Run SHA-3/SHAKE arbitrary-bit differential acceptance", "host CI")
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
