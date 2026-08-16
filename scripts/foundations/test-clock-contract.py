#!/usr/bin/env python3
"""Exercise fail-closed v0.15.0 clock-policy fixtures."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import clock_contract_policy


ROOT = Path(__file__).resolve().parents[2]
COPIED = clock_contract_policy.SOURCES + (
    Path("crates/brynja-test-support/Cargo.toml"),
    Path("package-policy.toml"),
)


def copy_fixture(root: Path) -> None:
    for relative in COPIED:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


def replace(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"fixture source missing {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def reject(root: Path, expected: str) -> None:
    try:
        clock_contract_policy.validate(root)
    except clock_contract_policy.ClockContractPolicyError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"clock fixture accepted {expected}")


def test() -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-clock-") as temporary:
        root = Path(temporary)
        copy_fixture(root)
        clock_contract_policy.validate(root)

        monotonic = root / clock_contract_policy.SOURCES[3]
        replace(monotonic, "tick_nanoseconds: u64", "pub tick_nanoseconds: u64")
        reject(root, "exposed raw construction state")
        copy_fixture(root)

        monotonic = root / clock_contract_policy.SOURCES[3]
        replace(monotonic, "self.failed = true;", "self.failed = false;")
        reject(root, "monotonic clock contract drift")
        copy_fixture(root)

        monotonic = root / clock_contract_policy.SOURCES[3]
        replace(monotonic, "self.require_purpose(purpose)?;", "let _ = purpose;")
        reject(root, "monotonic clock contract drift")
        copy_fixture(root)

        wall = root / clock_contract_policy.SOURCES[2]
        wall.write_text(wall.read_text(encoding="utf-8") + "\nfn now() { SystemTime; }\n", encoding="utf-8")
        reject(root, "forbidden boundary")
        copy_fixture(root)

        fixture = root / clock_contract_policy.SOURCES[4]
        replace(fixture, "impl WallClockSource", "impl MissingWallClockSource")
        reject(root, "deterministic clock fixture drift")
        copy_fixture(root)

        cargo = root / "crates/brynja-test-support/Cargo.toml"
        replace(cargo, "publish = false", 'publish = ["crates-io"]')
        reject(root, "became publishable")
        copy_fixture(root)

        policy = root / "package-policy.toml"
        replace(
            policy,
            '[packages.brynja-test-support]\nclass = "repository-only"\npublish = "never"\nrequired = ["brynja-core"]',
            '[packages.brynja-test-support]\nclass = "repository-only"\npublish = "never"\nrequired = []',
        )
        reject(root, "package policy drift")
        copy_fixture(root)

        duration = root / clock_contract_policy.SOURCES[1]
        duration.write_text(duration.read_text(encoding="utf-8") + "\n" * 400, encoding="utf-8")
        reject(root, "exceeds 500 lines")
        copy_fixture(root)

        clock = root / clock_contract_policy.SOURCES[0]
        clock.write_text(clock.read_text(encoding="utf-8") + "\n// review drift\n", encoding="utf-8")
        reject(root, "reviewed source hash drift")


if __name__ == "__main__":
    test()
    print("clock policy rejects nine type, state, isolation, low-level, size, and hash regressions")
