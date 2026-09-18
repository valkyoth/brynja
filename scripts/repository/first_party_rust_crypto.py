#!/usr/bin/env python3
"""Enforce the first-party Rust cryptographic implementation boundary."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path


PACKAGE_ROOTS = (Path("crates"), Path("integrations"))
NATIVE_SUFFIXES = {
    ".a",
    ".asm",
    ".bc",
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".dll",
    ".dylib",
    ".h",
    ".hh",
    ".hpp",
    ".lib",
    ".ll",
    ".m",
    ".mm",
    ".o",
    ".obj",
    ".s",
    ".so",
}
FOREIGN_ABI = re.compile(r'\bextern\s*(?:/\*.*?\*/\s*)?"(?:C|system|stdcall|cdecl)"', re.DOTALL)
# These are Rust function DEFINITIONS, not imported foreign implementations.
# The separate unsafe inventory binds their complete first-party assembly bytes.
LOCAL_C_ABI = {
    Path("crates/brynja-crypto-cpu/src/sha512_hardened_batch/transfer.rs"),
    Path("crates/brynja-crypto-cpu/src/sha256_hardened_batch/transfer.rs"),
    Path("crates/brynja-legacy-md5/src/cpu/x86_secret/kernel.rs"),
    Path("crates/brynja-legacy-md5/src/cpu/arm_secret/kernel.rs"),
    Path("crates/brynja-legacy-sha1/src/cpu/x86_sha1/secret.rs"),
    Path("crates/brynja-legacy-sha1/src/cpu/aarch64_sha1/secret.rs"),
    Path("crates/brynja-crypto-cpu/src/keccak_hardened_batch/x86/secret.rs"),
    Path("crates/brynja-crypto-cpu/src/keccak_hardened_batch/arm/secret.rs"),
    Path("crates/brynja-crypto-cpu/src/sha512_hardened_batch/x86/secret.rs"),
    Path("crates/brynja-crypto-cpu/src/sha512_hardened_batch/arm/secret.rs"),
    Path("crates/brynja-crypto-cpu/src/sha256_hardened_batch/x86/secret.rs"),
    Path("crates/brynja-crypto-cpu/src/sha256_hardened_batch/arm/secret.rs"),
    Path("crates/brynja-crypto-cpu/src/x86_avx2_keccak/secret.rs"),
    Path("crates/brynja-crypto-cpu/src/aarch64_sha3_keccak/secret.rs"),
    Path("crates/brynja-crypto-cpu/src/x86_sha/secret.rs"),
    Path("crates/brynja-crypto-cpu/src/aarch64_sha2/secret256.rs"),
    Path("crates/brynja-crypto-cpu/src/x86_sha512/secret.rs"),
    Path("crates/brynja-crypto-cpu/src/aarch64_sha2/secret512.rs"),
}
LOCAL_SIGNATURE = '''pub unsafe extern "C" fn compress(
    state: &mut [u8; 64],
    block: &[u8; 128],
    scratch: &mut [u8; 704],
    constants: &[u64; 80],
) {'''
NATIVE_LINK = re.compile(r"#\s*\[\s*link(?:_name|_section)?\b")
NATIVE_INCLUDE = re.compile(
    r"include_bytes\s*!\s*\([^)]*\.(?:a|bc|dll|dylib|lib|ll|o|obj|so)[\"']",
    re.IGNORECASE | re.DOTALL,
)


class FirstPartyRustCryptoError(RuntimeError):
    """The repository contains a prohibited foreign implementation edge."""


def fail(message: str) -> None:
    raise FirstPartyRustCryptoError(message)


def package_files(root: Path) -> list[Path]:
    files: list[Path] = []
    workspace_manifest = root / "Cargo.toml"
    if workspace_manifest.is_file():
        files.append(workspace_manifest)
    for relative_root in PACKAGE_ROOTS:
        directory = root / relative_root
        if not directory.exists():
            continue
        for path in directory.rglob("*"):
            if "target" in path.relative_to(directory).parts:
                continue
            if path.is_file():
                files.append(path)
    return sorted(files)


def nested_key(value: object, key: str) -> bool:
    if not isinstance(value, dict):
        return False
    return key in value or any(nested_key(item, key) for item in value.values())


def validate_manifest(path: Path) -> None:
    try:
        manifest = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot parse package manifest {path}: {error}")
    package = manifest.get("package", {})
    if isinstance(package, dict) and "build" in package:
        fail(f"package manifest declares a custom build target: {path}")
    if isinstance(package, dict) and "links" in package:
        fail(f"package manifest declares a native link identity: {path}")
    if nested_key(manifest, "build-dependencies"):
        fail(f"package manifest declares build dependencies: {path}")


def validate(root: Path) -> None:
    files = package_files(root)
    manifests = [path for path in files if path.name == "Cargo.toml"]
    if not manifests:
        fail("first-party Rust policy found no package manifests")

    for path in files:
        relative = path.relative_to(root)
        if path.name == "build.rs":
            fail(f"package build script is forbidden: {relative}")
        if path.suffix.lower() in NATIVE_SUFFIXES:
            fail(f"foreign source or native binary artifact is forbidden: {relative}")
        if path.name == "Cargo.toml":
            validate_manifest(path)
        if path.suffix == ".rs":
            text = path.read_text(encoding="utf-8")
            abi_text = text
            if relative in LOCAL_C_ABI:
                signature = LOCAL_SIGNATURE
                if relative.name == 'transfer.rs':
                    signature = ('pub(super) unsafe extern "C" fn transpose<const WORDS: usize, const PACK: bool>(\n'
                                 '    destination: *mut u8,\n    source: *const u8,\n'
                                 '    width: usize,\n    swap: u32,\n) {')
                if relative.parent.name in {'x86_secret', 'arm_secret'}:
                    signature = 'pub unsafe extern "C" fn compress(scratch: &mut [u8; 864], constants: &[u32; 80]) {'
                if relative.parent.parent.name == 'sha512_hardened_batch':
                    signature = 'pub unsafe extern "C" fn compress(scratch: &mut [u8; 3264], constants: &[u64; 80]) {'
                if relative.parent.parent.name == 'sha256_hardened_batch':
                    signature = 'pub unsafe extern "C" fn compress(scratch: &mut [u8; 2752], constants: &[u32; 64]) {'
                if relative.name == 'secret256.rs' or relative.parent.name == 'x86_sha':
                    signature = signature.replace('[u64; 80]', '[u32; 64]')
                if relative.parent.name in {'x86_avx2_keccak', 'aarch64_sha3_keccak'}:
                    signature = ('pub unsafe extern "C" fn permute(\n'
                                 '    scratch: &mut [u8; 576],\n    constants: &[u64; 24],\n'
                                 '    state: &mut [u8; 200],\n) {')
                if relative.parent.parent.name == 'keccak_hardened_batch':
                    signature = 'pub unsafe extern "C" fn permute(scratch: &mut [u8; 1920], constants: &[u64; 24]) {'
                if relative.parent.name in {'x86_sha1', 'aarch64_sha1'}:
                    signature = ('pub unsafe extern "C" fn compress(\n'
                                 '    state: &mut [u8; 20],\n    block: &[u8; 64],\n'
                                 '    schedule: &mut [u8; 320],\n) {')
                if text.count(signature) != 1:
                    fail(f"local Rust ABI definition changed: {relative}")
                abi_text = text.replace(signature, '', 1)
            if FOREIGN_ABI.search(abi_text):
                fail(f"foreign ABI declaration is forbidden: {relative}")
            if NATIVE_LINK.search(text):
                fail(f"native link attribute is forbidden: {relative}")
            if NATIVE_INCLUDE.search(text):
                fail(f"included native binary is forbidden: {relative}")
