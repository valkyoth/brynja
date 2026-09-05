#!/usr/bin/env python3
"""Adversarial tests for the portable SP 800-185 closure policy."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import portable_acceptance


def reject(relative: Path, old: str, new: str) -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-sp800185-mutation-") as directory:
        root = Path(directory)
        for item in (*portable_acceptance.FILES, portable_acceptance.HASHES):
            target = root / item
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(portable_acceptance.ROOT / item, target)
        target = root / relative
        text = target.read_text(encoding="utf-8")
        if old not in text:
            raise AssertionError(f"missing mutation token: {relative}: {old}")
        target.write_text(text.replace(old, new, 1), encoding="utf-8")
        try:
            portable_acceptance.validate(root, check_hashes=False)
        except portable_acceptance.PortableAcceptanceError:
            return
        raise AssertionError(f"portable policy accepted mutation: {relative}: {old}")


def main() -> int:
    fixture = portable_acceptance.FIXTURE
    cases = (
        (fixture / "src/lib.rs", "        identities: 14,", "        identities: 13,"),
        (fixture / "src/lib.rs", "#![no_std]", "extern crate std;"),
        (
            fixture / "src/cshake.rs",
            "let mut state = HardenedCshake256::new",
            "let mut state = Cshake256::new",
        ),
        (fixture / "src/kmac.rs", "Kmac128::new_conformance", "Kmac128::new"),
        (
            fixture / "src/tuplehash.rs",
            "let mut item = fixed.begin_item(48)",
            "let mut item = fixed.push_item(48)",
        ),
        (
            fixture / "src/parallelhash.rs",
            "let plan = ParallelHash256Plan::new",
            "let plan = ParallelHash128Plan::new",
        ),
        (fixture / "src/main.rs", "independently verified: NO", "independently verified: YES"),
        (Path("README.md"), "portable acceptance passed at v0.24.16", "portable acceptance pending"),
        (Path("docs/RELEASE_PLAN.md"), "Status: awaiting pentest", "Status: released"),
        (Path("scripts/checks.sh"), "python3 scripts/sp800185/check-portable-acceptance.py", "true"),
        (Path(".github/workflows/ci.yml"), "assurance/sp800185-public-api/Cargo.toml", "assurance/cshake-public-api/Cargo.toml"),
    )
    for case in cases:
        reject(*case)
    with tempfile.TemporaryDirectory(prefix="brynja-sp800185-hash-") as directory:
        root = Path(directory)
        for item in (*portable_acceptance.FILES, portable_acceptance.HASHES):
            target = root / item
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(portable_acceptance.ROOT / item, target)
        target = root / portable_acceptance.MAIN
        target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        try:
            portable_acceptance.validate(root)
        except portable_acceptance.PortableAcceptanceError:
            pass
        else:
            raise AssertionError("portable reviewed-hash drift was accepted")
    print(f"SP 800-185 portable policy rejects {len(cases) + 1} closure regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
