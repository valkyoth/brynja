#!/usr/bin/env python3
"""Exercise fail-closed v0.12.0 constant-time source fixtures."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import constant_time_policy


ROOT = Path(__file__).resolve().parents[1]


def copy_fixture(destination: Path) -> None:
    source = ROOT / constant_time_policy.SOURCE_ROOT
    target = destination / constant_time_policy.SOURCE_ROOT
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)


def replace(path: Path, old: str, new: str) -> None:
    content = path.read_text(encoding="utf-8")
    if old not in content:
        raise AssertionError(f"fixture source missing {old!r}")
    path.write_text(content.replace(old, new, 1), encoding="utf-8")


def require_rejection(root: Path, expected: str) -> None:
    try:
        constant_time_policy.validate(root)
    except constant_time_policy.ConstantTimePolicyError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"constant-time fixture accepted {expected}")


def test() -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-constant-time-") as temporary:
        root = Path(temporary)
        copy_fixture(root)
        constant_time_policy.validate(root)

        choice = root / constant_time_policy.SOURCE_ROOT / "choice.rs"
        replace(choice, "#[derive(Clone, Copy)]", "#[derive(Clone, Copy, Debug)]")
        require_rejection(root, "formatting or comparison")
        copy_fixture(root)

        choice = root / constant_time_policy.SOURCE_ROOT / "choice.rs"
        replace(choice, "let nonzero =", "if value == 0 {}\n        let nonzero =")
        require_rejection(root, "data-dependent control flow")
        copy_fixture(root)

        word = root / constant_time_policy.SOURCE_ROOT / "word.rs"
        replace(word, "macro_rules! implement_word", "while false {}\nmacro_rules! implement_word")
        require_rejection(root, "data-dependent control flow")
        copy_fixture(root)

        byte_source = root / constant_time_policy.SOURCE_ROOT / "bytes.rs"
        replace(byte_source, "for (left, right)", "loop {}\n        for (left, right)")
        require_rejection(root, "data-dependent control flow")
        copy_fixture(root)

        byte_source = root / constant_time_policy.SOURCE_ROOT / "bytes.rs"
        replace(byte_source, "for [u8; N]", "for [u8]")
        require_rejection(root, "dynamic byte slice")
        copy_fixture(root)

        barrier = root / constant_time_policy.SOURCE_ROOT / "barrier.rs"
        replace(barrier, "pub fn compiler_barrier<T>(value: T) -> T", "pub fn compiler_barrier<T>(value: T) -> Result<T, ()>")
        require_rejection(root, "variable error surface")
        copy_fixture(root)

        choice = root / constant_time_policy.SOURCE_ROOT / "choice.rs"
        replace(choice, "fn expose_public", "fn expose_public_again")
        require_rejection(root, "declassification point")
        copy_fixture(root)

        barrier = root / constant_time_policy.SOURCE_ROOT / "barrier.rs"
        replace(barrier, "compiler_fence(Ordering::SeqCst);", "")
        require_rejection(root, "compiler fence")
        copy_fixture(root)

        barrier = root / constant_time_policy.SOURCE_ROOT / "barrier.rs"
        replace(barrier, "black_box(value)", "core::convert::identity(value)")
        require_rejection(root, "optimization barrier")
        copy_fixture(root)

        word = root / constant_time_policy.SOURCE_ROOT / "word.rs"
        replace(word, "implement_word!(u128, select_u128);", "")
        require_rejection(root, "word coverage drift")
        copy_fixture(root)

        choice = root / constant_time_policy.SOURCE_ROOT / "choice.rs"
        replace(
            choice,
            "let mask = super::compiler_barrier(self.u32());",
            "let mask = self.u32();",
        )
        require_rejection(root, "word-mask optimization barriers")
        copy_fixture(root)

        byte_source = root / constant_time_policy.SOURCE_ROOT / "bytes.rs"
        replace(
            byte_source,
            "let mask = super::compiler_barrier(choice.mask().u8());",
            "let mask = choice.mask().u8();",
        )
        require_rejection(root, "array-mask optimization barriers")
        copy_fixture(root)

        byte_source = root / constant_time_policy.SOURCE_ROOT / "bytes.rs"
        replace(byte_source, "other.iter()", "other.iter().take(N)")
        require_rejection(root, "fixed-array iteration")
        copy_fixture(root)

        choice = root / constant_time_policy.SOURCE_ROOT / "choice.rs"
        choice.write_text(choice.read_text(encoding="utf-8") + "\n// review drift\n", encoding="utf-8")
        require_rejection(root, "reviewed source hash drift")


if __name__ == "__main__":
    test()
    print("constant-time policy rejects fourteen control, width, trait, barrier, coverage, and hash regressions")
