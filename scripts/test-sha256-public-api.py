#!/usr/bin/env python3
"""Broken fixtures for v0.22.3 SHA-256 public API acceptance."""

from __future__ import annotations

import tempfile
from pathlib import Path

import sha256_public_api as acceptance


def replace(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"fixture token missing: {old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def run_mutation(label: str, old: str, new: str, success: bool = False) -> None:
    with tempfile.TemporaryDirectory(prefix=f"brynja-sha256-{label}-") as temporary:
        fixture = acceptance.copy_fixture(Path(temporary))
        replace(fixture / "src/lib.rs", old, new)
        acceptance.run(
            ["cargo", "run", "--quiet", "--manifest-path", str(fixture / "Cargo.toml")],
            success=success,
        )


def main() -> int:
    acceptance.validate_repository()
    run_mutation(
        "digest",
        "a8f34a54459e9655229bb554c15ebb87f89a0bfbc600da8eb56999422fc0487f",
        "b8f34a54459e9655229bb554c15ebb87f89a0bfbc600da8eb56999422fc0487f",
    )
    run_mutation(
        "public-export",
        "sha256, sha256_with_backend,",
        "sha256_missing, sha256_with_backend,",
    )
    run_mutation(
        "backend-report",
        "if admitted != 0 || skipped != 3",
        "if admitted != 1 || skipped != 3",
    )
    run_mutation(
        "exhaustion",
        "check_additional_bytes(Sha256::MAX_MESSAGE_BYTES - 2)",
        "check_additional_bytes(Sha256::MAX_MESSAGE_BYTES - 3)",
    )

    with tempfile.TemporaryDirectory(prefix="brynja-sha256-feature-") as temporary:
        fixture = acceptance.copy_fixture(Path(temporary))
        replace(
            fixture / "Cargo.toml",
            'features = ["cpu"]',
            'features = ["cpu", "brynja_cpu_evidence"]',
        )
        acceptance.run(
            ["cargo", "check", "--quiet", "--manifest-path", str(fixture / "Cargo.toml")],
            success=False,
        )

    with tempfile.TemporaryDirectory(prefix="brynja-sha256-package-") as temporary:
        destination = Path(temporary)
        roots = acceptance.package_roots(destination)
        (roots["brynja-hash-sha2"] / "src/sha256.rs").unlink()
        consumer = acceptance.packaged_consumer(destination, roots)
        acceptance.run(
            ["cargo", "check", "--quiet", "--offline", "--manifest-path", str(consumer / "Cargo.toml")],
            cwd=consumer,
            success=False,
        )

    print(
        "SHA-256 public acceptance rejects corrupted digests, missing exports, "
        "backend misreporting, exhaustion bypass, unadmitted features, and altered packages"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
