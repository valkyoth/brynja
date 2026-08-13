#!/usr/bin/env python3
"""Exercise fail-closed v0.17.0 FIPS architecture fixtures."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import fips_architecture_policy


ROOT = Path(__file__).resolve().parents[1]


def copy_fixture(root: Path) -> None:
    for relative in fips_architecture_policy.SOURCES:
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
        fips_architecture_policy.validate(root)
    except fips_architecture_policy.FipsArchitecturePolicyError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"FIPS fixture accepted {expected}")


def test() -> None:
    fixtures = (
        (0, "BackendIdentity::ValidatedModule", "BackendIdentity::Scalar", "configuration boundary"),
        (0, "features != backend.required_features()", "false", "configuration boundary"),
        (0, "destruction_targets.is_empty()", "false", "configuration boundary"),
        (0, "for operation in ProviderOperation::ALL", "for operation in []", "configuration boundary"),
        (0, "ServiceOverlap(operation)", "ServiceUnclassified(operation)", "configuration boundary"),
        (0, "approved: FipsServiceSet", "pub approved: FipsServiceSet", "exposed mutable"),
        (0, "self.self_tests = self.self_tests.require(FipsSelfTest::Conditional)", "return self", "configuration boundary"),
        (1, ".contains(&[0; 32])", ".contains(&[9; 32])", "deterministic-build boundary"),
        (2, "Err(FipsServiceSetError::Duplicate(operation))", "Ok(self)", "service-set boundary"),
        (2, "pub const fn empty() -> Self", "pub const fn omitted_empty() -> Self", "service-set boundary"),
        (3, "pub trait FipsSelfTestRunner", "pub trait BypassRunner", "permanent-failure boundary"),
        (3, "let result = runner.run(guard.plan());", "let result = FipsSelfTestResult::Passed;", "permanent-failure boundary"),
        (3, "self.fail_permanently(FipsModuleFault::ReentrantSelfTest)", "return", "permanent-failure boundary"),
        (3, ".fail_permanently(FipsModuleFault::SelfTestFailed)", ".fail_permanently(FipsModuleFault::ImpossibleState)", "permanent-failure boundary"),
        (3, "self.fail_permanently(FipsModuleFault::CatastrophicFailure)", "return", "permanent-failure boundary"),
        (3, ".fail_permanently(FipsModuleFault::SelfTestInterrupted)", ".fail_permanently(FipsModuleFault::ImpossibleState)", "permanent-failure boundary"),
        (3, "snapshot.generation() == self.generation", "true", "permanent-failure boundary"),
        (3, "struct FipsSelfTestGuard", "pub struct FipsSelfTestGuard", "became forgeable"),
        (3, "pub struct FipsServiceAuthorization", "#[derive(Clone)]\npub struct FipsServiceAuthorization", "gained duplication"),
    )
    with tempfile.TemporaryDirectory(prefix="brynja-fips-") as temporary:
        root = Path(temporary)
        copy_fixture(root)
        fips_architecture_policy.validate(root)
        for source_index, old, new, expected in fixtures:
            copy_fixture(root)
            replace(root / fips_architecture_policy.SOURCES[source_index], old, new)
            reject(root, expected)

        copy_fixture(root)
        source = root / fips_architecture_policy.SOURCES[3]
        source.write_text(source.read_text(encoding="utf-8") + "\npub const fn provider_handle() {}\n", encoding="utf-8")
        reject(root, "became forgeable")

        copy_fixture(root)
        source = root / fips_architecture_policy.SOURCES[0]
        source.write_text(source.read_text(encoding="utf-8") + "\nfn native() { unsafe {} }\n", encoding="utf-8")
        reject(root, "forbidden boundary")

        copy_fixture(root)
        source = root / fips_architecture_policy.SOURCES[2]
        source.write_text(source.read_text(encoding="utf-8") + "\n" * 500, encoding="utf-8")
        reject(root, "exceeds 500 lines")

        copy_fixture(root)
        source = root / fips_architecture_policy.SOURCES[3]
        source.write_text(source.read_text(encoding="utf-8") + "\n// review drift\n", encoding="utf-8")
        reject(root, "reviewed source hash drift")


if __name__ == "__main__":
    test()
    print("FIPS policy rejects twenty-three architecture, isolation, lifecycle, authorization, size, unsafe, and hash regressions")
