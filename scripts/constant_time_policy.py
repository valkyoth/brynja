#!/usr/bin/env python3
"""Validate the narrow v0.12.0 constant-time source boundary."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


SOURCE_ROOT = Path("crates/brynja-core/src/constant_time")
SOURCES = (
    Path("barrier.rs"),
    Path("bytes.rs"),
    Path("choice.rs"),
    Path("mod.rs"),
    Path("word.rs"),
)
EXPECTED_SHA256 = {
    Path("barrier.rs"): "6f51ea95d5494f6bb803f08ef7c22f6f52db7c70f286cd3330a569d7e8ed6374",
    Path("bytes.rs"): "f95bb9edf6ca01f3734bc843c82f4f84a5dc8624bead5b14c5c751d9d5e8b75d",
    Path("choice.rs"): "846e876f5f749f361acc5a731e4d2a047b117bddec15a88aa01ce3a6a0dc0a4b",
    Path("mod.rs"): "1956066f0e4b8e25b97ad6742b325f47c02d1763b95049d5390d824b5df830bf",
    Path("word.rs"): "1d904a5fcc9ad7050b9027374cb76efa87c95dee9fb9eaa1c6965a9d2827123f",
}
CONTROL_FLOW = re.compile(r"\b(?:if|match|while|loop|return)\b")
ERROR_SURFACE = re.compile(r"\b(?:Result|Option)\s*<")
DECLASSIFY = re.compile(r"\bfn\s+expose_public\b")


class ConstantTimePolicyError(RuntimeError):
    """The constant-time source boundary differs from reviewed policy."""


def fail(message: str) -> None:
    raise ConstantTimePolicyError(message)


def code_without_line_comments(text: str) -> str:
    """Remove line comments so documentation does not masquerade as code."""

    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def load_sources(root: Path) -> dict[Path, tuple[str, str]]:
    directory = root / SOURCE_ROOT
    actual = sorted(path.relative_to(directory) for path in directory.glob("*.rs"))
    if actual != list(SOURCES):
        fail("constant-time source inventory drift")

    loaded: dict[Path, tuple[str, str]] = {}
    for relative in SOURCES:
        path = directory / relative
        if not path.is_file() or path.is_symlink():
            fail(f"constant-time source must be a regular file: {relative}")
        text = path.read_text(encoding="utf-8")
        if len(text.splitlines()) > 500:
            fail(f"constant-time source exceeds 500 lines: {relative}")
        loaded[relative] = (text, code_without_line_comments(text))
    return loaded


def validate_structure(sources: dict[Path, tuple[str, str]]) -> None:
    all_code = "\n".join(code for _text, code in sources.values())
    if CONTROL_FLOW.search(all_code) is not None:
        fail("constant-time implementation contains data-dependent control flow")
    if ERROR_SURFACE.search(all_code) is not None:
        fail("constant-time implementation introduced a variable error surface")
    if "&[u8]" in all_code or "&mut [u8]" in all_code or "for [u8]" in all_code:
        fail("constant-time implementation accepts a dynamic byte slice")
    if ".get(" in all_code or ".get_mut(" in all_code:
        fail("constant-time implementation introduced indexed access")
    if len(DECLASSIFY.findall(all_code)) != 1:
        fail("constant-time decision must have one explicit declassification point")

    bytes_code = sources[Path("bytes.rs")][1]
    if len(re.findall(r"\bfor\s*\(", all_code)) != 3 or len(
        re.findall(r"\bfor\s*\(", bytes_code)
    ) != 3:
        fail("constant-time loops must remain confined to three fixed-array passes")
    for required in (
        "self.iter().zip(other.iter())",
        ".zip(if_false.iter())",
        ".zip(if_true.iter())",
        "left.iter_mut().zip(right.iter_mut())",
    ):
        if bytes_code.count(required) != 1:
            fail("constant-time fixed-array iteration structure drift")

    choice_code = sources[Path("choice.rs")][1]
    if any(
        trait in choice_code
        for trait in ("Debug", "PartialEq", "Eq", "Ord", "Hash")
    ):
        fail("constant-time decisions or masks gained formatting or comparison traits")
    if choice_code.count("#[derive(Clone, Copy)]") != 2:
        fail("choice and mask representation traits drift")
    representations = re.findall(
        r"pub struct (?:Choice|CtMask)\s*\{\s*value: u8,\s*\}", choice_code
    )
    if len(representations) != 2:
        fail("choice or mask representation became forgeable or variable-width")
    if choice_code.count("super::compiler_barrier(self.") != 6:
        fail("constant-time word-mask optimization barriers drifted")
    if choice_code.count("#[inline(always)]") != 6:
        fail("constant-time word selection inlining contract drifted")
    if choice_code.count("if_false ^ ((if_false ^ if_true) & mask)") != 6:
        fail("constant-time word selection formula drifted")
    if bytes_code.count("super::compiler_barrier(choice.mask().u8())") != 2:
        fail("constant-time array-mask optimization barriers drifted")

    barrier_code = sources[Path("barrier.rs")][1]
    if barrier_code.count("compiler_fence(Ordering::SeqCst)") != 2:
        fail("constant-time compiler fence count drift")
    if barrier_code.count("black_box(value)") != 1:
        fail("constant-time optimization barrier drift")
    if barrier_code.count("#[inline(never)]") != 1:
        fail("constant-time barrier inlining contract drift")

    word_code = sources[Path("word.rs")][1]
    expected_words = (
        "u8",
        "u16",
        "u32",
        "u64",
        "u128",
        "usize",
    )
    for word in expected_words:
        if word_code.count(f"implement_word!({word},") != 1:
            fail(f"constant-time word coverage drift: {word}")


def validate_hashes(sources: dict[Path, tuple[str, str]]) -> None:
    for relative, (text, _code) in sources.items():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != EXPECTED_SHA256[relative]:
            fail(f"constant-time reviewed source hash drift: {relative}")


def validate(root: Path) -> None:
    sources = load_sources(root)
    validate_structure(sources)
    validate_hashes(sources)
