#!/usr/bin/env python3
"""Adversarial fixtures for complete v0.23.4 SHA-2 public acceptance."""

from __future__ import annotations

import tempfile
from pathlib import Path

import sha2_public_api as acceptance


def replace(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"fixture token missing: {old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def reject_runtime(label: str, old: str, new: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"brynja-sha2-{label}-") as temporary:
        fixture = acceptance.copy_fixture(Path(temporary))
        replace(fixture / "src/vectors.rs", old, new)
        acceptance.run(["cargo", "run", "--quiet", "--manifest-path", str(fixture / "Cargo.toml")], success=False)


def reject_policy(label: str, relative: Path, old: str, new: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"brynja-sha2-policy-{label}-") as temporary:
        root = acceptance.copy_policy_tree(Path(temporary))
        replace(root / relative, old, new)
        try:
            acceptance.validate_repository(root, check_hashes=False)
        except acceptance.AcceptancePolicyError:
            return
        raise AssertionError(f"complete SHA-2 policy accepted: {label}")


def main() -> int:
    acceptance.validate_repository()
    expected_mutations = (
        ("sha224", "23097d223405d822", "33097d223405d822"),
        ("sha256", "ba7816bf8f01cfea", "aa7816bf8f01cfea"),
        ("sha384", "cb00753f45a35e8b", "db00753f45a35e8b"),
        ("sha512", "ddaf35a193617aba", "cdaf35a193617aba"),
        ("sha512-224", "4634270f707b6a54", "5634270f707b6a54"),
        ("sha512-256", "53048e2681941ef9", "43048e2681941ef9"),
    )
    for label, old, new in expected_mutations:
        reject_runtime(label, old, new)
    reject_policy("missing-family-API", acceptance.ALGORITHMS, "facade::sha512_256", "facade::missing_sha512_256")
    reject_policy(
        "missing-documentation",
        acceptance.LEAF_README,
        "SHA-2 (all six identities have complete byte APIs; arbitrary-bit and hardened secret-bearing profiles pending)",
        "incomplete hash family",
    )
    reject_policy(
        "backend-accounting",
        acceptance.LIB,
        "skipped_unadmitted_backends: 5",
        "skipped_unadmitted_backends: 4",
    )
    reject_policy("identity-check", acceptance.LIB, "check_distinct_identities()?;", "")
    reject_policy("output-width", acceptance.DIGEST, "Sha512_224Digest, 28", "Sha512_224Digest, 27")
    with tempfile.TemporaryDirectory(prefix="brynja-sha2-feature-") as temporary:
        fixture = acceptance.copy_fixture(Path(temporary))
        replace(fixture / "Cargo.toml", 'features = ["cpu"]', 'features = ["cpu", "brynja_cpu_evidence"]')
        acceptance.run(["cargo", "check", "--quiet", "--manifest-path", str(fixture / "Cargo.toml")], success=False)
    with tempfile.TemporaryDirectory(prefix="brynja-sha2-package-") as temporary:
        destination = Path(temporary)
        roots = acceptance.package_roots(destination)
        (roots["brynja-hash-sha2"] / "src/sha512_256.rs").unlink()
        consumer = acceptance.packaged_consumer(destination, roots)
        acceptance.run(
            ["cargo", "check", "--quiet", "--offline", "--manifest-path", str(consumer / "Cargo.toml")],
            cwd=consumer,
            success=False,
        )
    print("complete SHA-2 acceptance rejects six corrupted results plus API, documentation, backend, identity, width, feature, and package regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
