#!/usr/bin/env python3
"""Adversarial fixtures for v0.24.3 portable FIPS 202 acceptance."""

from __future__ import annotations

import tempfile
from pathlib import Path

import sha3_public_api as acceptance


def replace(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"fixture token missing: {old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def reject_runtime(label: str, old: str, new: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"brynja-sha3-{label}-") as temporary:
        fixture = acceptance.copy_fixture(Path(temporary))
        replace(fixture / "src/vectors.rs", old, new)
        acceptance.run(
            ["cargo", "run", "--quiet", "--manifest-path", str(fixture / "Cargo.toml")],
            success=False,
        )


def reject_policy(label: str, relative: Path, old: str, new: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"brynja-sha3-policy-{label}-") as temporary:
        root = acceptance.copy_policy_tree(Path(temporary))
        replace(root / relative, old, new)
        try:
            acceptance.validate_repository(root, check_hashes=False)
        except acceptance.AcceptancePolicyError:
            return
        raise AssertionError(f"complete SHA-3 policy accepted: {label}")


def reject_compile(label: str, old: str, new: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"brynja-sha3-compile-{label}-") as temporary:
        fixture = acceptance.copy_fixture(Path(temporary))
        replace(fixture / "src/lib.rs", old, new)
        acceptance.run(
            ["cargo", "check", "--quiet", "--manifest-path", str(fixture / "Cargo.toml")],
            success=False,
        )


def main() -> int:
    acceptance.validate_repository()
    for label, old, new in (
        ("sha3-224", "e642824c3f8cf24a", "f642824c3f8cf24a"),
        ("sha3-256", "3a985da74fe225b2", "2a985da74fe225b2"),
        ("sha3-384", "ec01498288516fc9", "fc01498288516fc9"),
        ("sha3-512", "b751850b1a57168a", "a751850b1a57168a"),
        ("shake128", "5881092dd818bf5c", "4881092dd818bf5c"),
        ("shake256", "483366601360a877", "583366601360a877"),
    ):
        reject_runtime(label, old, new)
    reject_policy("missing-facade", acceptance.ALGORITHMS, "facade::sha3_512(input)", "facade::missing(input)")
    reject_policy("missing-rate", acceptance.LIB, "check_exact_rates()?;", "")
    reject_policy("missing-zero-output", acceptance.LIB, "check_zero_output()?;", "")
    reject_policy("missing-exhaustion", acceptance.LIB, "check_exhaustion()?;", "")
    reject_policy("missing-domain", acceptance.LIB, "check_domain_separation()?;", "")
    reject_policy("false-path", acceptance.MAIN, "execution path: portable-only", "execution path: accelerated")
    reject_policy("leaf-feature", acceptance.LEAF_MANIFEST, "default = []", 'default = ["cpu"]')
    reject_policy("hidden-feature", acceptance.MANIFEST, "[dependencies]", "[features]\ncpu = []\n\n[dependencies]")
    reject_compile(
        "absorb-after-squeeze",
        "let mut reader128 = state128.finalize_xof();",
        "let mut reader128 = state128.finalize_xof();\n    let _ = reader128.update(b\"forbidden\");",
    )
    reject_compile(
        "private-permutation",
        "fn check_claims() -> Result<(), AcceptanceError> {",
        "fn check_claims() -> Result<(), AcceptanceError> {\n    let _ = leaf::keccak::byte_location(0);",
    )
    with tempfile.TemporaryDirectory(prefix="brynja-sha3-package-") as temporary:
        destination = Path(temporary)
        roots = acceptance.package_roots(destination)
        (roots["brynja-hash-sha3"] / "src/shake256.rs").unlink()
        consumer = acceptance.packaged_consumer(destination, roots)
        acceptance.run(
            ["cargo", "check", "--quiet", "--offline", "--manifest-path", str(consumer / "Cargo.toml")],
            cwd=consumer,
            success=False,
        )
    print("complete SHA-3 acceptance rejects six corrupted outputs plus API, rate, zero-output, exhaustion, domain, path, feature, phase, private-module, and package regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
