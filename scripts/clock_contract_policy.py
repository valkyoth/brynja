#!/usr/bin/env python3
"""Validate the reviewed v0.15.0 wall and monotonic clock boundary."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path


SOURCES = (
    Path("crates/brynja-core/src/clock.rs"),
    Path("crates/brynja-core/src/clock/duration.rs"),
    Path("crates/brynja-core/src/clock/wall.rs"),
    Path("crates/brynja-core/src/clock/monotonic.rs"),
    Path("crates/brynja-test-support/src/deterministic_clock.rs"),
)
EXPECTED_SHA256 = {
    SOURCES[0]: "48d85ef7738412dfb733e5192507e7082f145ad3985f59284baa987fba9a14d3",
    SOURCES[1]: "8e503de6a2f55631f2806faa6e89a4039f64f9db7a50cd95777d92fe5baf1b77",
    SOURCES[2]: "85971f9dc03a33b88ae504a12a8a1618008566648c908ac15589bf698628b30c",
    SOURCES[3]: "56b428377beeb3066ed672bccf288479f5ee53010f3773e1851c502495151de0",
    SOURCES[4]: "ae5180f98131366a5f5834cecb898c7bb4947d5e4bc283a27b99affae4042bbc",
}


class ClockContractPolicyError(RuntimeError):
    """The typed clock boundary differs from reviewed policy."""


def fail(message: str) -> None:
    raise ClockContractPolicyError(message)


def code_without_comments(text: str) -> str:
    """Remove line comments before checking executable tokens."""

    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def load_sources(root: Path) -> dict[Path, tuple[str, str]]:
    loaded = {}
    for relative in SOURCES:
        source = root / relative
        if not source.is_file() or source.is_symlink():
            fail(f"clock source must be a regular file: {relative}")
        text = source.read_text(encoding="utf-8")
        if len(text.splitlines()) > 500:
            fail(f"clock source exceeds 500 lines: {relative}")
        loaded[relative] = (text, code_without_comments(text))
    return loaded


def validate_structure(sources: dict[Path, tuple[str, str]]) -> None:
    all_code = "\n".join(code for _text, code in sources.values())
    for forbidden in (
        "unsafe",
        'extern "C"',
        "std::",
        "alloc::",
        "SystemTime",
        "Instant::now",
        "clock_gettime",
        "QueryPerformanceCounter",
        "mach_absolute_time",
    ):
        if forbidden in all_code:
            fail(f"clock implementation crossed forbidden boundary: {forbidden}")

    duration = sources[SOURCES[1]][1]
    wall = sources[SOURCES[2]][1]
    monotonic = sources[SOURCES[3]][1]
    fixture = sources[SOURCES[4]][1]
    for required in (
        "pub struct ClockDuration",
        "pub enum TimeError",
        "pub const fn checked_add",
        "pub fn checked_sub",
    ):
        if duration.count(required) != 1:
            fail(f"checked duration contract drift: {required}")
    for required in (
        "pub struct WallTime {",
        "pub struct WallTimeRange {",
        "pub enum WallTimeStatus",
        "pub trait WallClockSource",
    ):
        if wall.count(required) != 1:
            fail(f"wall-clock contract drift: {required}")
    for required in (
        "pub struct ClockGeneration",
        "pub struct MonotonicInstant",
        "pub struct MonotonicDeadline",
        "pub trait MonotonicClockSource",
        "pub struct MonotonicClock<S: MonotonicClockSource>",
        "self.require_purpose(purpose)?;",
        "self.failed = true;",
        'formatter.write_str("MonotonicInstant(REDACTED)")',
    ):
        if monotonic.count(required) != 1:
            fail(f"monotonic clock contract drift: {required}")
    for purpose in ("Timer", "Freshness", "Ticket", "Replay"):
        if monotonic.count(purpose) < 1:
            fail(f"monotonic purpose disappeared: {purpose}")
    instant = re.search(
        r"pub struct MonotonicInstant\s*\{(?P<body>[^}]*)\}", monotonic
    )
    if instant is None or "pub " in instant.group("body"):
        fail("monotonic instant exposed raw construction state")
    if "pub const fn tick" in monotonic or "pub fn tick" in monotonic:
        fail("monotonic instant exposed raw tick access")
    for required in (
        "pub enum DeterministicReading<T>",
        "pub struct DeterministicWallClock",
        "impl WallClockSource for DeterministicWallClock",
        "pub struct DeterministicMonotonicClock",
        "impl MonotonicClockSource for DeterministicMonotonicClock",
    ):
        if fixture.count(required) != 1:
            fail(f"deterministic clock fixture drift: {required}")


def validate_isolation(root: Path) -> None:
    support = tomllib.loads(
        (root / "crates/brynja-test-support/Cargo.toml").read_text(encoding="utf-8")
    )
    if support["package"].get("publish") is not False:
        fail("deterministic clock package became publishable")
    if support.get("dependencies") != {"brynja-core": {"workspace": True}}:
        fail("deterministic clock dependency boundary drift")
    policy = tomllib.loads((root / "package-policy.toml").read_text(encoding="utf-8"))
    entry = policy["packages"]["brynja-test-support"]
    if entry != {
        "class": "repository-only",
        "publish": "never",
        "required": ["brynja-core"],
        "optional": {},
    }:
        fail("deterministic clock package policy drift")


def validate_hashes(sources: dict[Path, tuple[str, str]]) -> None:
    for relative, (text, _code) in sources.items():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != EXPECTED_SHA256[relative]:
            fail(f"clock reviewed source hash drift: {relative}")


def validate(root: Path) -> None:
    sources = load_sources(root)
    validate_structure(sources)
    validate_isolation(root)
    validate_hashes(sources)
