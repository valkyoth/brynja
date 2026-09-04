#!/usr/bin/env python3
"""Select fail-closed Miri groups affected since the previous signed tag."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GROUPS = ("core", "sanitization", "sha2", "sha3", "kmac", "tuplehash", "parallelhash")
FULL_EXACT = {
    "Cargo.lock",
    "Cargo.toml",
    "assurance/policy.toml",
    "assurance/zeroization-matrix.toml",
    "rust-toolchain.toml",
    "scripts/tag_gate.sh",
}
FULL_PREFIXES = ("scripts/zeroization/",)
GROUP_PREFIXES = {
    "core": ("crates/brynja-core/",),
    "sanitization": (
        "assurance/sanitization-admission/",
        "crates/brynja-sanitization/",
        "scripts/sanitization/",
    ),
    "sha2": (
        "assurance/sha2-",
        "crates/brynja-hash-core/",
        "crates/brynja-hash-sha2/",
        "scripts/sha2/",
    ),
    "sha3": (
        "assurance/cshake-",
        "assurance/sha3-",
        "crates/brynja-hash-core/",
        "crates/brynja-hash-sha3/",
        "scripts/sha3/",
    ),
    "kmac": (
        "assurance/kmac-",
        "crates/brynja-mac-kmac/",
        "scripts/kmac/",
    ),
    "tuplehash": (
        "assurance/tuplehash-",
        "crates/brynja-hash-tuple/",
        "scripts/tuplehash/",
    ),
    "parallelhash": (
        "assurance/parallelhash-",
        "crates/brynja-hash-parallel/",
        "scripts/parallelhash/",
    ),
}
DOWNSTREAM = {
    "core": {"sanitization", "sha2", "sha3", "kmac", "tuplehash", "parallelhash"},
    "sanitization": set(),
    "sha2": set(),
    "sha3": {"kmac", "tuplehash", "parallelhash"},
    "kmac": set(),
    "tuplehash": set(),
    "parallelhash": set(),
}


class MiriScopeError(RuntimeError):
    """The focused Miri boundary cannot be selected safely."""


def normalized(path: str) -> str | None:
    value = path.replace("\\", "/")
    if not value or value.startswith("/") or ".." in Path(value).parts:
        return None
    return value


def select(paths: list[str]) -> tuple[bool, tuple[str, ...]]:
    selected: set[str] = set()
    for raw in paths:
        path = normalized(raw)
        if path is None:
            return True, GROUPS
        if path in FULL_EXACT or path.startswith(FULL_PREFIXES):
            return True, GROUPS
        for group, prefixes in GROUP_PREFIXES.items():
            if path.startswith(prefixes):
                selected.add(group)

    pending = list(selected)
    while pending:
        group = pending.pop()
        for dependent in DOWNSTREAM[group] - selected:
            selected.add(dependent)
            pending.append(dependent)
    return False, tuple(group for group in GROUPS if group in selected)


def changed_paths(base: str) -> list[str]:
    try:
        output = subprocess.check_output(
            [
                "git",
                "diff",
                "--name-only",
                "--no-renames",
                "--diff-filter=ACDMRTUXB",
                f"{base}..HEAD",
            ],
            cwd=ROOT,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise MiriScopeError(f"cannot determine Miri change scope: {error}") from error
    return [line for line in output.splitlines() if line]


def validate_repository() -> None:
    runner = (ROOT / "scripts/zeroization/check-zeroization-miri.sh").read_text()
    tag_runner = (ROOT / "scripts/zeroization/check-tag-miri.sh").read_text()
    tag_gate = (ROOT / "scripts/tag_gate.sh").read_text()
    literal = "all_groups=(core sanitization sha2 sha3 kmac tuplehash parallelhash)"
    if runner.count(literal) != 1:
        raise MiriScopeError("Miri runner group inventory drifted")
    for group in GROUPS:
        for profile in ("quick", "full"):
            if runner.count(f"{profile}_{group}()") != 1:
                raise MiriScopeError(f"missing {profile} Miri group: {group}")
    if tag_gate.count('scripts/zeroization/check-tag-miri.sh "$stage"') != 1:
        raise MiriScopeError("tag gate focused-Miri binding drifted")
    if tag_runner.count('"$miri_runner" --full') != 4:
        raise MiriScopeError("tag Miri runner lost a complete-suite boundary")
    if tag_runner.count('"$miri_runner" --focused "${groups[@]}"') != 1:
        raise MiriScopeError("tag Miri runner lost its focused-suite boundary")
    describe = 'git describe --tags --first-parent --match "v[0-9]*" --abbrev=0 HEAD^'
    if tag_runner.count(describe) != 1:
        raise MiriScopeError("tag Miri runner lost its signed-tag baseline")
    if tag_runner.count('git verify-tag "$base"') != 1:
        raise MiriScopeError("tag Miri runner no longer authenticates its baseline")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        validate_repository()
        print("Miri scope policy: PASS")
        return 0
    if not args.base:
        parser.error("--base is required unless --check is used")
    full, groups = select(changed_paths(args.base))
    print("full" if full else " ".join(groups))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
