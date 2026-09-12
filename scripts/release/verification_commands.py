"""Strict command catalog reader and ownership for incremental checks.

The existing full shell catalogs remain runnable diagnostics. Only straight-line
commands are accepted here; unknown syntax/owners block planning, never skip work.
"""
from __future__ import annotations

import shlex
import re
from pathlib import Path

from verification_plan import ROOT, scope

ALL = set(scope.GROUPS)
DIRECTORIES = {
    "md5": {"md5"}, "sha1": {"sha1"}, "sha2": {"sha2"}, "sha3": {"sha3"},
    "kmac": {"kmac"}, "tuplehash": {"tuplehash"}, "parallelhash": {"parallelhash"},
    "legacy-hash": {"legacy"}, "hash": {"sha2", "sha3"},
    "sp800185": {"sha3", "kmac", "tuplehash", "parallelhash"},
    "cpu": {"static_cpu"}, "constant-time": {"core"},
    "sanitization": {"sanitization"}, "cryptography": ALL, "foundations": {"core"},
}
BASE_DIRECTORIES = {"repository", "release", "assurance", "ci", "standards", "pki", "protocols"}
BASE_COMMANDS = {
    "python3 scripts/cryptography/test-mir-cleanup-flow.py",
    "python3 scripts/cryptography/test-secret-owner-compiler.py",
    "python3 scripts/cryptography/check-secret-owner-compiler.py",
    "python3 scripts/cryptography/check-api-profiles.py",
    "python3 scripts/cryptography/test-api-profiles.py",
    "python3 scripts/zeroization/check-zeroization-evidence.py",
    "python3 scripts/zeroization/test-zeroization-evidence.py",
    "python3 scripts/sha2/check-sha2-hardened-execution.py --policy-only",
    "python3 scripts/cpu/check-static-execution.py --policy-only",
    "python3 scripts/cpu/check-hosted-execution.py --policy-only",
    "python3 scripts/cpu/check-acceleration-availability.py",
    "python3 scripts/cpu/test-acceleration-availability.py",
    "cargo test --locked --offline --manifest-path assurance/acceleration-contract/Cargo.toml",
    "cargo clippy --locked --offline --manifest-path assurance/acceleration-contract/Cargo.toml --all-targets -- -D warnings",
    "cargo test --locked --offline --manifest-path assurance/crate-readmes/Cargo.toml --doc",
}


def catalog(path: Path, marker: str | None = None) -> list[str]:
    text = path.read_text().replace("\r\n", "\n")
    if marker is not None:
        if text.count(marker) != 1:
            raise ValueError("missing or duplicate verification catalog marker")
        text = text.split(marker, 1)[1]
    text = text.replace("\\\n", " ")
    commands = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line in {"set -eu", "set -euo pipefail"}:
            continue
        # These catalogs intentionally have no substitutions, shell branching,
        # pipelines, redirections or comments on command lines.
        if any(token in line for token in ("$", "`", ";", "|", "&", "<", ">", "#")):
            raise ValueError(f"unclassified catalog shell syntax: {line}")
        argv = shlex.split(line)
        if not argv or argv[0] not in {"cargo", "python3", 'RUSTFLAGS=-Zsanitizer=address'} and not argv[0].startswith("scripts/"):
            raise ValueError(f"unclassified catalog command: {line}")
        commands.append(" ".join(line.split()))
    if len(commands) != len(set(commands)):
        raise ValueError("duplicate verification catalog command")
    return commands


def owners(command: str) -> set[str]:
    if command in BASE_COMMANDS:
        return set()
    argv = shlex.split(command)
    if not argv:
        raise ValueError("empty verification command")
    if argv[0].startswith("RUSTFLAGS="):
        argv = argv[1:]
    if argv[0] == "cargo":
        if "--workspace" in argv or argv[1] in {"fetch", "fmt", "doc"}:
            return set()  # Broad but cheap build/lint/native compatibility baseline.
        if "--manifest-path" in argv:
            path = argv[argv.index("--manifest-path") + 1]
            full, groups = scope.select([path])
            if full or not groups:
                raise ValueError(f"unclassified fixture command: {command}")
            return set(groups)
        packages = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "-p"]
        if packages:
            found = set()
            for package in packages:
                full, groups = scope.select([f"crates/{package}/src/lib.rs"])
                if full or not groups:
                    raise ValueError(f"unclassified package command: {command}")
                found.update(groups)
            return found
        raise ValueError(f"unclassified Cargo command: {command}")
    path = argv[1] if argv[0] == "python3" else argv[0]
    parts = Path(path).parts
    if len(parts) != 3 or parts[0] != "scripts":
        raise ValueError(f"unclassified script command: {command}")
    directory = parts[1]
    if directory in BASE_DIRECTORIES:
        return set()
    if directory == "zeroization":
        if parts[2] in {"miri_scope.py", "test-miri-scope.py", "test-scope-inputs.py"}:
            return set()
        return ALL
    if directory not in DIRECTORIES:
        raise ValueError(f"unclassified command owner: {command}")
    return DIRECTORIES[directory]


def selected(commands: list[str], groups: list[str], *, full: bool = False) -> list[str]:
    result = []
    for command in commands:
        group = owners(command)
        if full or not group or group.intersection(groups):
            result.append(command)
    return result


def repository_commands(root: Path = ROOT) -> list[str]:
    return catalog(root / "scripts/checks.sh", "# BEGIN VERIFICATION CATALOG")


def matrix_commands(root: Path = ROOT) -> list[tuple[str, str | None]]:
    text = (root / "scripts/ci/check-rust-version-matrix.sh").read_text().replace("\\\n", " ")
    versions = re.findall(r'^toolchains=\(([0-9. ]+)\)$', text, re.M)
    if len(versions) != 1 or text.count("# BEGIN MATRIX CATALOG") != 1:
        raise ValueError("unknown compiler matrix catalog")
    body = text.split("# BEGIN MATRIX CATALOG", 1)[1]
    if not body.rstrip().endswith("\ndone"):
        raise ValueError("unknown compiler matrix terminator")
    lines = body.rstrip()[:-len("done")].strip().splitlines()
    result = []
    for version in versions[0].split():
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            raise ValueError("invalid compiler version")
        for line in lines:
            line = " ".join(line.split()).replace('$toolchain', version)
            command, separator, stdin = line.partition(" < ")
            if any(c in command for c in ('$','`',';','|','&','<','>','#')) or not command.startswith('cargo '):
                raise ValueError("unknown compiler matrix command")
            if separator and (not stdin.startswith("crates/") or ".." in Path(stdin).parts or " " in stdin):
                raise ValueError("unknown matrix input vector")
            owners(command)
            result.append((command, stdin if separator else None))
    return result
