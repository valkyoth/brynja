#!/usr/bin/env python3
"""Select fail-closed Miri groups affected since the previous signed tag."""

from __future__ import annotations

import argparse
import subprocess
import re
import sys
from pathlib import Path
import scope_inputs


ROOT = Path(__file__).resolve().parents[2]
GROUPS = ("core", "sanitization", "md5", "sha1", "sha2", "sha3", "kmac", "tuplehash", "parallelhash", "legacy")
FULL_EXACT = {
    "Cargo.lock",
    "Cargo.toml",
    "assurance/policy.toml",
    "assurance/zeroization-matrix.toml",
    "rust-toolchain.toml",
    "scripts/tag_gate.sh",
}
FULL_PREFIXES = ("scripts/zeroization/", ".cargo/")
GROUP_PREFIXES = {
    "core": ("crates/brynja-core/",),
    "sanitization": (
        "assurance/sanitization-admission/",
        "crates/brynja-sanitization/",
        "scripts/sanitization/",
    ),
    "md5": ("crates/brynja-legacy-md5/", "crates/brynja-hash-core/", "assurance/md5-", "scripts/md5/"),
    "sha1": ("crates/brynja-legacy-sha1/", "crates/brynja-hash-core/", "assurance/sha1-", "scripts/sha1/"),
    "legacy": ("assurance/legacy-hash-", "scripts/legacy-hash/"),
    "sha2": (
        "assurance/hash-final-acceptance/",
        "assurance/sha2-",
        "crates/brynja-hash-core/",
        "crates/brynja-hash-sha2/",
        "scripts/sha2/",
    ),
    "sha3": (
        "assurance/hash-final-acceptance/", "assurance/sp800185-", "scripts/sp800185/",
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
    "core": {"sanitization", "md5", "sha1", "sha2", "sha3", "kmac", "tuplehash", "parallelhash", "legacy"},
    "sanitization": set(),
    "md5": {"legacy"},
    "sha1": {"legacy"},
    "legacy": set(),
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
        if path.endswith(('.rs', '.c', '.cc', '.cpp', '.h', '.hpp', '.s', '.S', '.asm', 'Cargo.toml')) and not any(
            path.startswith(prefix) for prefixes in GROUP_PREFIXES.values() for prefix in prefixes
        ):
            return True, GROUPS

    return False, closure(selected)


def closure(selected: set[str]) -> tuple[str, ...]:
    selected = set(selected)
    pending = list(selected)
    while pending:
        group = pending.pop()
        for dependent in DOWNSTREAM[group] - selected:
            selected.add(dependent)
            pending.append(dependent)
    return tuple(group for group in GROUPS if group in selected)


def select_repository(base: str, root: Path = ROOT) -> tuple[bool, tuple[str, ...]]:
    """Semantic metadata classification; unknown or malformed inputs fail closed."""
    try:
        if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?', base):
            raise ValueError('invalid baseline tag')
        scope_inputs.git(root, 'verify-tag', base)
        scope_inputs.git(root, 'merge-base', '--is-ancestor', base, 'HEAD')
        paths = scope_inputs.git(root, 'diff', '--name-only', '-z', '--no-renames', base).split(b'\0')
        paths += scope_inputs.git(root, 'ls-files', '--others', '--exclude-standard', '-z').split(b'\0')
        affected: set[str] = set()
        retained = []
        orchestration = {
            'scripts/zeroization/miri_scope.py', 'scripts/zeroization/scope_inputs.py',
            'scripts/zeroization/test-miri-scope.py', 'scripts/zeroization/test-scope-inputs.py',
            'scripts/zeroization/check-tag-miri.sh', 'scripts/tag_gate.sh',
            'scripts/zeroization/check-zeroization-sanitizer.sh',
        }
        for encoded in set(paths) - {b''}:
            path = encoded.decode('utf-8')
            if normalized(path) != path:
                raise ValueError('noncanonical change path')
            if path.endswith('.md'):
                continue
            before, after = scope_inputs.snapshot(root, base, path)
            if path in {'scripts/sha2/sha2_public_api.py', 'scripts/sha3/sha3_public_api.py',
                        'scripts/sp800185/portable_acceptance.py'}:
                manifests = scope_inputs.snapshot(root, base, 'crates/brynja/Cargo.toml')
                versions = [scope_inputs.document(m)['package']['version'] for m in manifests]
                if not scope_inputs.facade_pin_only(before, after, *versions):
                    retained.append(path)
            elif path in {'scripts/sha2/sha256_public_api.py', 'scripts/sha2/sha2_reviewed_hashes.py',
                          'scripts/tuplehash/tuplehash_reviewed_hashes.py',
                          'scripts/parallelhash/parallelhash_reviewed_hashes.py'} and scope_inputs.python_bindings_only(before, after):
                continue
            elif path.endswith('Cargo.lock'):
                if (before is None or after is None) and path != 'Cargo.lock':
                    # Added/removed fixture locks must be a subset of the
                    # corresponding workspace lock; they cannot conceal a pin.
                    index = 1 if after is not None else 0
                    data = after if after is not None else before
                    workspace = scope_inputs.snapshot(root, base, 'Cargo.lock')[index]
                    manifest = scope_inputs.snapshot(root, base, path[:-4] + 'toml')[index]
                    scope_inputs.fixture_lock(data, workspace, manifest)
                    if not any(path.startswith(p) for ps in GROUP_PREFIXES.values() for p in ps):
                        raise ValueError('unclassified fixture lock')
                    retained.append(path)
                else:
                    affected |= scope_inputs.lock_groups(before, after)
            elif path.endswith('Cargo.toml') and before is not None and after is not None and scope_inputs.version_only(before, after):
                continue
            elif path == 'scripts/zeroization/check-zeroization-miri.sh':
                affected |= scope_inputs.runner_groups(before, after)
            elif path == 'assurance/policy.toml' and scope_inputs.verifier_only(before, after):
                continue
            elif path == 'assurance/zeroization-matrix.toml' and scope_inputs.matrix_verifier_only(before, after):
                continue
            elif path.endswith(('-reviewed.toml', '-hashes.toml')) and before is not None and after is not None and scope_inputs.hash_binding_only(before, after):
                continue
            elif path in orchestration:
                # Coverage orchestration has mandatory structural and execution
                # regressions; it is not itself a cryptographic implementation.
                continue
            elif path.endswith('.md'):
                continue
            else:
                retained.append(path)
        full, groups = select(retained)
        if full:
            return True, GROUPS
        affected.update(groups)
        return False, closure(affected)
    except (OSError, ValueError, SyntaxError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as error:
        print(f'Miri scope requires full coverage: {error}', file=sys.stderr)
        return True, GROUPS


def validate_repository() -> None:
    runner = (ROOT / "scripts/zeroization/check-zeroization-miri.sh").read_text()
    tag_runner = (ROOT / "scripts/zeroization/check-tag-miri.sh").read_text()
    tag_gate = (ROOT / "scripts/tag_gate.sh").read_text()
    literal = "all_groups=(core sanitization md5 sha1 sha2 sha3 kmac tuplehash parallelhash legacy)"
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
    describe = 'git describe --tags --first-parent --match "v[0-9]*" --abbrev=0 HEAD'
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
    validate_repository()
    full, groups = select_repository(args.base)
    print("full" if full else " ".join(groups))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
