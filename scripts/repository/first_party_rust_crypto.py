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
            if FOREIGN_ABI.search(text):
                fail(f"foreign ABI declaration is forbidden: {relative}")
            if NATIVE_LINK.search(text):
                fail(f"native link attribute is forbidden: {relative}")
            if NATIVE_INCLUDE.search(text):
                fail(f"included native binary is forbidden: {relative}")
