#!/usr/bin/env python3
"""Exercise fail-closed v0.14.0 entropy-policy fixtures."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import entropy_contract_policy


ROOT = Path(__file__).resolve().parents[2]
COPIED = entropy_contract_policy.SOURCES + (
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
        entropy_contract_policy.validate(root)
    except entropy_contract_policy.EntropyContractPolicyError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"entropy fixture accepted {expected}")


def test() -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-entropy-") as temporary:
        root = Path(temporary)
        copy_fixture(root)
        entropy_contract_policy.validate(root)

        entropy = root / entropy_contract_policy.SOURCES[0]
        secure = root / entropy_contract_policy.SOURCES[1]
        fixture = root / entropy_contract_policy.SOURCES[2]
        replace(entropy, "pub struct RawEntropy<'entropy>", "#[derive(Clone)]\npub struct RawEntropy<'entropy>")
        reject(root, "duplication or formatting")
        copy_fixture(root)

        secure = root / entropy_contract_policy.SOURCES[1]
        replace(secure, "pub struct SecureRandom<E", "#[derive(Debug)]\npub struct SecureRandom<E")
        reject(root, "duplication or formatting")
        copy_fixture(root)

        secure = root / entropy_contract_policy.SOURCES[1]
        replace(secure, "pub fn mark_fork", "pub fn record_fork")
        reject(root, "state-machine drift")
        copy_fixture(root)

        secure = root / entropy_contract_policy.SOURCES[1]
        replace(secure, "engine.handle_destruction_failure();", "return;")
        reject(root, "destruction failure handling drift")
        copy_fixture(root)

        fixture = root / entropy_contract_policy.SOURCES[2]
        replace(fixture, "clear_owned_region(&mut self.state)", "Ok(())")
        reject(root, "test-provider boundary drift")
        copy_fixture(root)

        fixture = root / entropy_contract_policy.SOURCES[2]
        fixture.write_text(fixture.read_text(encoding="utf-8") + "\nunsafe fn escape() {}\n", encoding="utf-8")
        reject(root, "forbidden boundary")
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

        entropy = root / entropy_contract_policy.SOURCES[0]
        entropy.write_text(entropy.read_text(encoding="utf-8") + "\n// review drift\n", encoding="utf-8")
        reject(root, "reviewed source hash drift")


if __name__ == "__main__":
    test()
    print("entropy policy rejects nine trait, state, teardown, isolation, low-level, and hash regressions")
