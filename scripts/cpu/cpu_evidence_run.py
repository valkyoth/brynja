#!/usr/bin/env python3
"""Validate non-authorizing SHA-256 native candidate-run bundles."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


MAXIMUM_FILE_BYTES = 16_777_216
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
LANES = {
    "local-amd-x86_64": ("x86-sha", "x86_64", "linux"),
    "aws-intel-x86_64": ("x86-sha", "x86_64", "linux"),
    "apple-m2-aarch64": ("aarch64-sha2", "aarch64", "macos"),
    "aws-aarch64": ("aarch64-sha2", "aarch64", "linux"),
    "riscv64-cloud": ("riscv-scalar-crypto", "riscv64", "linux"),
}
REQUIRED_FILES = {
    "cargo.txt",
    "candidate-tests.log",
    "codegen.log",
    "host.txt",
    "manifest.txt",
    "rustc.txt",
}
MANIFEST_FIELDS = {
    "schema",
    "source_commit",
    "source_tree",
    "lane",
    "backend",
    "architecture",
    "os",
    "captured_utc",
    "tree_state",
    "status",
    "authority",
}


class CandidateRunError(RuntimeError):
    """A detached candidate run failed its local validation boundary."""


def fail(message: str) -> None:
    raise CandidateRunError(message)


def read_regular(path: Path, maximum: int = MAXIMUM_FILE_BYTES) -> bytes:
    if not path.is_file() or path.is_symlink():
        fail(f"candidate evidence input is not a regular file: {path}")
    with path.open("rb") as handle:
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        fail(f"candidate evidence input exceeds its bound: {path}")
    return data


def parse_assignments(data: bytes, label: str) -> dict[str, str]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError as error:
        fail(f"{label} is not UTF-8: {error}")
    values: dict[str, str] = {}
    for line in lines:
        if not line or "=" not in line:
            fail(f"{label} contains a malformed line")
        key, value = line.split("=", 1)
        if not key or key in values or not value:
            fail(f"{label} contains an empty or duplicate field")
        values[key] = value
    return values


def sha256(path: Path) -> str:
    return hashlib.sha256(read_regular(path)).hexdigest()


def parse_checksums(path: Path) -> dict[str, str]:
    try:
        lines = read_regular(path).decode("ascii").splitlines()
    except UnicodeError as error:
        fail(f"candidate checksum inventory is not ASCII: {error}")
    values: dict[str, str] = {}
    for line in lines:
        parts = line.split("  ", 1)
        if len(parts) != 2 or HEX_64.fullmatch(parts[0]) is None:
            fail("candidate checksum inventory contains a malformed line")
        name = parts[1]
        if name.startswith("./"):
            name = name[2:]
        if "/" in name or name in values or name not in REQUIRED_FILES:
            fail("candidate checksum inventory contains an unexpected path")
        values[name] = parts[0]
    if set(values) != REQUIRED_FILES:
        fail("candidate checksum inventory is incomplete")
    return values


def validate_bundle(directory: Path) -> dict[str, str]:
    if not directory.is_dir() or directory.is_symlink():
        fail("candidate bundle must be a real directory")
    names = {entry.name for entry in directory.iterdir()}
    if names != REQUIRED_FILES | {"SHA256SUMS"}:
        fail("candidate bundle file inventory drifted")
    checksums = parse_checksums(directory / "SHA256SUMS")
    for name, expected in checksums.items():
        if sha256(directory / name) != expected:
            fail(f"candidate bundle checksum mismatch: {name}")
    manifest = parse_assignments(read_regular(directory / "manifest.txt"), "candidate manifest")
    if set(manifest) != MANIFEST_FIELDS:
        fail("candidate manifest fields drifted")
    if manifest["schema"] != "brynja-sha256-native-candidate-v1":
        fail("candidate manifest schema drifted")
    if HEX_40.fullmatch(manifest["source_commit"]) is None:
        fail("candidate source commit is invalid")
    if HEX_40.fullmatch(manifest["source_tree"]) is None:
        fail("candidate source tree is invalid")
    if UTC.fullmatch(manifest["captured_utc"]) is None:
        fail("candidate timestamp is invalid")
    lane = manifest["lane"]
    if lane not in LANES:
        fail("candidate lane is outside the registered evidence lanes")
    backend, architecture, operating_system = LANES[lane]
    if (manifest["backend"], manifest["architecture"], manifest["os"]) != (
        backend,
        architecture,
        operating_system,
    ):
        fail("candidate lane identity differs from the registered lane")
    if manifest["tree_state"] != "clean" or manifest["status"] != "pass":
        fail("candidate run did not complete from a clean source")
    if manifest["authority"] != "non-authorizing-native-candidate-observation":
        fail("candidate run gained unsupported admission authority")
    test_log = read_regular(directory / "candidate-tests.log").decode("utf-8", "strict")
    expected_test = (
        "statically_proven_backend_matches_scalar_when_available"
        if backend == "riscv-scalar-crypto"
        else "evidence_route_is_exact_and_accelerated"
    )
    if expected_test not in test_log or "test result: ok" not in test_log:
        fail("candidate test transcript lacks exact accelerated execution")
    codegen = read_regular(directory / "codegen.log").decode("utf-8", "strict")
    instruction = {
        "x86-sha": "sha256rnds2",
        "aarch64-sha2": "sha256h",
        "riscv-scalar-crypto": "sha256sum0",
    }[backend]
    if f"required_instruction={instruction}" not in codegen or "status=pass" not in codegen:
        fail("candidate codegen transcript lacks the required instruction")
    return manifest
