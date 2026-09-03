#!/usr/bin/env python3
"""Adversarial tests for combined modern-hash closure policy."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import final_acceptance


def mutate(root: Path, relative: Path, old: str, new: str) -> None:
    path = root / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"missing mutation token: {relative}: {old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def rejected(relative: Path, old: str, new: str) -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-final-hash-mutation-") as temporary:
        root = Path(temporary)
        for item in (*final_acceptance.FILES, final_acceptance.HASHES):
            target = root / item
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(final_acceptance.ROOT / item, target)
        mutate(root, relative, old, new)
        try:
            final_acceptance.validate(root, check_hashes=False)
        except final_acceptance.FinalAcceptanceError:
            return
        raise AssertionError(f"mutation was accepted: {relative}: {old}")


def main() -> int:
    cases = (
        (final_acceptance.LIB, "ADMITTED_BACKEND_COUNT == 0", "ADMITTED_BACKEND_COUNT <= 1"),
        (final_acceptance.LIB, "FIPS202_HARDENED_STATE_IMPLEMENTED", "FIPS202_HARDENED_PENDING"),
        (Path("README.md"), "| SHA-2 | ✅ Fully implemented", "| SHA-2 | 🚧 In progress"),
        (Path("README.md"), "❌ Not independently verified", "✅ Independently verified"),
        (Path("docs/current-status.md"), "SHA-2 and SHA-3/SHAKE are Fully implemented", "SHA families pending"),
        (
            Path("docs/RELEASE_PLAN.md"),
            "### v0.24.11 - SHA-2 And SHA-3/SHAKE Cross-Backend Final Acceptance\n\n"
            "Status: released",
            "### v0.24.11 - SHA-2 And SHA-3/SHAKE Cross-Backend Final Acceptance\n\n"
            "Status: awaiting pentest",
        ),
        (Path("scripts/checks.sh"), "python3 scripts/hash/check-final-acceptance.py", "true # final check removed"),
        (Path(".github/workflows/ci.yml"), "assurance/hash-final-acceptance/Cargo.toml", "assurance/sha3-public-api/Cargo.toml"),
        (Path("standards/surface-policy.json"), "scripts/hash/check-final-acceptance.py#main", "tests/missing.rs#missing"),
        (Path("security/cryptographic-api-profile-policy.toml"), "scripts/hash/check-final-acceptance.py", "scripts/hash/missing.py"),
    )
    for case in cases:
        rejected(*case)
    with tempfile.TemporaryDirectory(prefix="brynja-final-hash-drift-") as temporary:
        root = Path(temporary)
        for item in (*final_acceptance.FILES, final_acceptance.HASHES):
            target = root / item
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(final_acceptance.ROOT / item, target)
        mutate(root, final_acceptance.MAIN, "final acceptance: PASS", "final acceptance: FAIL")
        try:
            final_acceptance.validate(root)
        except final_acceptance.FinalAcceptanceError:
            pass
        else:
            raise AssertionError("reviewed hash drift was accepted")
    print(f"combined hash closure rejects {len(cases) + 1} claim and evidence regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
