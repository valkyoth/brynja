#!/usr/bin/env python3
"""Validate and execute the v0.24.8 SHA-2 byte, bit, and hardened acceptance."""

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
BIT_INPUTS = FIXTURE / "src/bit_inputs.rs"
HARDENED = FIXTURE / "src/hardened.rs"
VECTORS = FIXTURE / "src/vectors.rs"
MAIN = FIXTURE / "src/main.rs"
CONTENT = FIXTURE / "fixtures/representative.txt"
CORE_BITS = Path("crates/brynja-hash-core/src/bit_string.rs")
LEAF_LIB = Path("crates/brynja-hash-sha2/src/lib.rs")
LEAF_BIT_API = Path("crates/brynja-hash-sha2/src/bit_api.rs")
LEAF_BIT_INPUT = Path("crates/brynja-hash-sha2/src/bit_input.rs")
LEAF_BIT_TEST = Path("crates/brynja-hash-sha2/tests/bit_inputs.rs")
NIST_BIT_VECTORS = Path("crates/brynja-hash-sha2/tests/vectors/nist-bit-selected.txt")
DIFFERENTIAL_MANIFEST = Path("assurance/sha2-bit-differential/Cargo.toml")
DIFFERENTIAL_LOCK = Path("assurance/sha2-bit-differential/Cargo.lock")
DIFFERENTIAL_MAIN = Path("assurance/sha2-bit-differential/src/main.rs")
DIFFERENTIAL_CHECK = Path("scripts/sha2/check-sha2-bit-differential.py")
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
    MANIFEST, LOCK, LIB, ALGORITHMS, BIT_INPUTS, HARDENED, VECTORS, MAIN, CONTENT,
    CORE_BITS, LEAF_LIB, LEAF_BIT_API, LEAF_BIT_INPUT, LEAF_BIT_TEST,
    NIST_BIT_VECTORS, DIFFERENTIAL_MANIFEST, DIFFERENTIAL_LOCK,
    DIFFERENTIAL_MAIN, DIFFERENTIAL_CHECK, DIGEST, FACADE_LIB, LEAF_README,
    FACADE_README, CHECK_SCRIPT, TEST_SCRIPT, CHECKS, RUST_MATRIX, BARE_METAL,
    WORKFLOW,
)
EXPECTED_SHA256 = {
    MANIFEST: "04d5fe77f6a36d4b1ed51a04329d984f61c16ebf951397fe71ed191ea2803b93",
    LOCK: "4e9aad060678f01ee12237829d8f7eecb63835e70158925ef61fa615b51502a2",
    LIB: "516c0901f6dfd3b3979771368f11777ff34d40cd02979baa9a187b390f988913",
    ALGORITHMS: "f5c798334508de76015c92f2929dee7b51e7b76a61fe3bc353bf67e4677a1e63",
    BIT_INPUTS: "8f882911914e82ce7dfef7713296a696f5d3966ea9f55ee9d0cdda8dfb65812d",
    HARDENED: "5a04f3402a55bf4035672c74361a29cac60f2f3216953818da4fa262ca2bfc51",
    VECTORS: "cc4a0209cd9bbc322a0f2ad0dfaffc3e72337a28e189d9a311b94229e5d8b6d6",
    MAIN: "f1a8952197f962ee0c8a27e1605e9c388fa9bea5eaf4d3f25478b21d6b9047dc",
    CONTENT: "fcb4220a9a063622c8c2f19d66c56e813a8add0814ece5cb6ec09ca5830d2a71",
    CORE_BITS: "0b5c23c4a789cef43a3bf913c5d75c0beb1fb16bcc89036b7f1431e7b1af0fd8",
    LEAF_LIB: "eef622caf04f4db206ffd38104deeb8a67b0602f063a489059fc18461246796e",
    LEAF_BIT_API: "007b960b0d869dcd6abb5bcb7f13397dfd9a41e45fdb38f13ab684782f6f662d",
    LEAF_BIT_INPUT: "eccb31f3ebc8056bc7f51319483002c27feddf76203cc7bb7a3d0d073fc9e16a",
    LEAF_BIT_TEST: "df9d40cd6e19f71b989f95cc82877919ed5f144bf790b3adb2b72c5dd3b78927",
    NIST_BIT_VECTORS: "a23d9c097b3f2218441b72707ba3b6094e0e85bf63ed0eb24fc70b635f846b8f",
    DIFFERENTIAL_MANIFEST: "6b1f8929ace8039b132af488cb2b0e2746d00684c2ed5dcfd32baff92bc763c3",
    DIFFERENTIAL_LOCK: "81b71c99c04ce21079a5426446cb8ebf00e179329c30bfc5ea59c5406771fce4",
    DIFFERENTIAL_MAIN: "72a6459c642c353fc64687e5fd29ba3e25f427c756e87ab79d3b940848b99752",
    DIFFERENTIAL_CHECK: "263990644d6176b5817893f1f0008b355c5aeef9f22e7e10be72ed92b9a2fcfc",
    DIGEST: "a861b334e041502bfb56b5de12a4c83468cbfa2440881288aca94c1aa6c08634",
    FACADE_LIB: "fdbd3d9f8117d5a11fc400b6515e6c8c10629b036b536ef46e0bd7a05c6632e2",
    LEAF_README: "1ebed7863a3e9638e2bc639ef171d573e9c2ab9e72fcef1aa1c8d052a5f4a029",
    FACADE_README: "5c1de3247959cdfe79f42359486deead697ff6241781663106a4ac02b3c5236a",
    CHECK_SCRIPT: "08a8b7baae515ba1bb945e14b1a2022a5023b2de02aab94c8d80e67775433b1c",
    TEST_SCRIPT: "152605f88d141968ae005fc6850abc25ecd2f6b8896bbfafc219bbd75cd4a7bd",
    CHECKS: "79dfd3a61096f7c6e92ca6b210b296cf11184125c2f69d88b4e18c29ace6e7cb",
    RUST_MATRIX: "507516d61f7479220829908c3be21330047ff9b67099533811af8c842534f7bb",
    BARE_METAL: "ffa91450aa0bd6e28d7e22443944221523e8ef4f264239d0fda26fa8387364fb",
    WORKFLOW: "37bd8c59bcca9cfeba126a467f80b234a590cf935360d2301eb655dc79f7ba90",
}
ALGORITHMS_NAMES = ("SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256")
PACKAGES = (
    ("brynja-core", "0.9.0", ("src/lib.rs",)),
    ("brynja-crypto-cpu", "0.1.1", ("src/lib.rs", "src/sha256.rs", "src/sha512.rs")),
    ("brynja-hash-core", "0.1.0", ("src/lib.rs", "src/bit_string.rs")),
    ("brynja-hash-sha2", "0.1.0", (
        "src/lib.rs", "src/bit_api.rs", "src/bit_input.rs", "src/compress.rs",
        "src/compress64.rs", "src/digest.rs", "src/error.rs", "src/sha224.rs", "src/sha256.rs", "src/sha384.rs",
        "src/sha512.rs", "src/sha512_224.rs", "src/sha512_256.rs",
        "src/sha512_state.rs", "src/sha512_t.rs", "src/hardened/mod.rs",
        "src/hardened/compress32.rs", "src/hardened/compress64.rs",
        "src/hardened/output.rs", "src/hardened/owner.rs",
        "src/hardened/state32.rs", "src/hardened/state64.rs",
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
    ("brynja", "0.24.9", ("src/lib.rs",)),
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
    for relative in (LIB, ALGORITHMS, BIT_INPUTS, VECTORS, MAIN, LEAF_BIT_API,
                     LEAF_BIT_INPUT, LEAF_BIT_TEST, DIFFERENTIAL_MAIN,
                     DIFFERENTIAL_CHECK, CHECK_SCRIPT, TEST_SCRIPT):
        if len(loaded[relative].splitlines()) > 500:
            fail(f"acceptance code exceeds 500 lines: {relative}")
    manifest = tomllib.loads(loaded[MANIFEST])
    if manifest.get("package") != {
        "name": "brynja-sha2-public-api-fixture", "version": "0.0.0",
        "edition": "2024", "rust-version": "1.90", "publish": False,
    }:
        fail("acceptance package identity changed")
    expected_dependencies = {
        "brynja": {"path": "../../crates/brynja", "version": "=0.24.9", "default-features": False},
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
        "one_shot_results: 30", "streaming_results: 36", "bit_input_results",
        "hardened_results", "hardened_results: 12",
        "bit_inputs::check()?", "check_distinct_identities()?",
        "leaf::SHA2_BIT_INPUT_IMPLEMENTED",
        "facade::SHA2_BIT_INPUT_IMPLEMENTED",
        "facade::SHA2_HARDENED_STATE_IMPLEMENTED",
        "skipped_unadmitted_backends: 5", "Sha256BackendSession::for_compiled_target().is_some()",
        "Sha512BackendSession::for_compiled_target().is_some()", "sha512_256_with_backend",
    ):
        require(library, token, "complete-family fixture")
    for forbidden in (
        "cfg(brynja_cpu_evidence)", "for_candidate_evidence", "from_runtime_detection",
        "std::", "alloc::", "env!", "option_env!", "Command::", "File::", "TcpStream", "UdpSocket",
    ):
        if forbidden in library + loaded[ALGORITHMS] + loaded[BIT_INPUTS] + loaded[HARDENED] + loaded[VECTORS]:
            fail(f"acceptance fixture crossed forbidden boundary: {forbidden}")
    for name in ALGORITHMS_NAMES:
        require(loaded[MAIN], f"{name}: portable scalar; independently verified: NO; FIPS validated: NO", "runnable report")
        require(loaded[LEAF_README], name, "leaf documentation")
        require(loaded[FACADE_README], name, "facade documentation")
    require(loaded[MAIN], "hardened public/secret results", "runnable hardened report")
    leaf_family_label = "SHA-2 (all six identities have complete ordinary and hardened byte and arbitrary-bit APIs; combined acceptance pending)"
    facade_family_label = "SHA-2 (FIPS 180-4: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256 have complete ordinary and hardened byte and arbitrary-bit APIs; combined acceptance pending)"
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
        require(loaded[BIT_INPUTS], f"    {function}_bits,", "public bit one-shot coverage")
        require(loaded[BIT_INPUTS], f"    {state},", "public bit state coverage")
    for state in (
        "HardenedSha224", "HardenedSha256", "HardenedSha384",
        "HardenedSha512", "HardenedSha512_224", "HardenedSha512_256",
    ):
        require(loaded[HARDENED], state, "packaged hardened-state coverage")
    for token in ("finalize_public", "finalize_secret", "PublicDeclassification::acknowledge"):
        require(loaded[HARDENED], token, "packaged hardened-output coverage")
    for token in ("leaf::$function(complete)", "facade::$function(complete)", ".finalize_bits(tail)"):
        require(loaded[BIT_INPUTS], token, "bit macro coverage")
    for token in ("Sha224Digest, 28", "Sha256Digest, 32", "Sha384Digest, 48", "Sha512Digest, 64", "Sha512_224Digest, 28", "Sha512_256Digest, 32"):
        require(loaded[DIGEST], token, "output identity")
    require(loaded[CHECKS], "python3 scripts/sha2/check-sha2-public-api.py", "repository gate")
    require(loaded[CHECKS], "python3 scripts/sha2/check-sha2-bit-differential.py", "bit differential gate")
    require(loaded[WORKFLOW], "Run SHA-2 arbitrary-bit differential oracle", "host bit differential CI")
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
