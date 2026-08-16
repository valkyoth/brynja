#!/usr/bin/env python3
"""Validate the reviewed v0.14.0 entropy and secure-random boundary."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path


SOURCES = (
    Path("crates/brynja-core/src/entropy.rs"),
    Path("crates/brynja-core/src/secure_random.rs"),
    Path("crates/brynja-test-support/src/deterministic_random.rs"),
)
EXPECTED_SHA256 = {
    Path("crates/brynja-core/src/entropy.rs"): "b1a0b0793da8517c34f0d0aed8694c4ca0d5e848672699fbcfcf33cd99d960f3",
    Path("crates/brynja-core/src/secure_random.rs"): "54a950a18b6bccad3a0c78a21667ab39ed00fb4fd1972d9b3ea79a47cbb7366a",
    Path("crates/brynja-test-support/src/deterministic_random.rs"): "9a8568e92ac3c008b2572c763528d913f8a9146848724a87b6e34e8126c9c58f",
}


class EntropyContractPolicyError(RuntimeError):
    """The entropy boundary differs from reviewed policy."""


def fail(message: str) -> None:
    raise EntropyContractPolicyError(message)


def code_without_comments(text: str) -> str:
    """Remove line comments before checking executable tokens."""

    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def load_sources(root: Path) -> dict[Path, tuple[str, str]]:
    loaded = {}
    for relative in SOURCES:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            fail(f"entropy source must be a regular file: {relative}")
        text = path.read_text(encoding="utf-8")
        if len(text.splitlines()) > 500:
            fail(f"entropy source exceeds 500 lines: {relative}")
        loaded[relative] = (text, code_without_comments(text))
    return loaded


def validate_structure(sources: dict[Path, tuple[str, str]]) -> None:
    all_code = "\n".join(code for _text, code in sources.values())
    for forbidden in (
        "unsafe",
        'extern "C"',
        "std::",
        "alloc::",
        "getrandom",
        "OsRng",
        "/dev/urandom",
        "BCryptGenRandom",
        "SecRandomCopyBytes",
    ):
        if forbidden in all_code:
            fail(f"entropy implementation crossed forbidden boundary: {forbidden}")

    entropy = sources[SOURCES[0]][1]
    secure = sources[SOURCES[1]][1]
    fixture = sources[SOURCES[2]][1]
    for required in (
        "pub struct RawEntropyRequest",
        "pub struct RawEntropy<'entropy>",
        "pub enum EntropyFailureKind",
        "pub enum EntropyPurpose",
    ):
        if entropy.count(required) != 1:
            fail(f"raw entropy contract drift: {required}")
    for required in (
        "pub trait SecureRandomEngine",
        "pub struct SecureRandom<E: SecureRandomEngine>",
        "pub fn mark_fork",
        "pub fn reseed",
        "pub fn generate<'output>",
        "SecretRegionInitialization::begin(output)",
        "self.latch_permanent",
    ):
        if secure.count(required) < 1:
            fail(f"secure-random state-machine drift: {required}")
    if secure.count("engine.handle_destruction_failure()") != 4:
        fail("secure-random destruction failure handling drift")
    if re.search(r"#\[derive\([^]]*(?:Clone|Copy|Debug)[^]]*\)\]\s*pub struct RawEntropy<'", entropy):
        fail("raw entropy gained duplication or formatting traits")
    if re.search(r"#\[derive\([^]]*(?:Clone|Copy|Debug)[^]]*\)\]\s*pub struct SecureRandom<", secure):
        fail("initialized secure-random state gained duplication or formatting traits")
    for required in (
        "pub struct DeterministicRandom",
        "pub enum DeterministicFault",
        "impl SecureRandomEngine for DeterministicRandom",
        "fn handle_destruction_failure(&mut self)",
    ):
        if fixture.count(required) < 1:
            fail(f"deterministic test-provider boundary drift: {required}")
    if fixture.count("clear_owned_region(&mut self.state)") != 2:
        fail("deterministic test-provider boundary drift: state clearing")


def validate_isolation(root: Path) -> None:
    support = tomllib.loads(
        (root / "crates/brynja-test-support/Cargo.toml").read_text(encoding="utf-8")
    )
    if support["package"].get("publish") is not False:
        fail("deterministic provider package became publishable")
    if support.get("dependencies") != {"brynja-core": {"workspace": True}}:
        fail("deterministic provider dependency boundary drift")
    policy = tomllib.loads((root / "package-policy.toml").read_text(encoding="utf-8"))
    entry = policy["packages"]["brynja-test-support"]
    if entry != {
        "class": "repository-only",
        "publish": "never",
        "required": ["brynja-core"],
        "optional": {},
    }:
        fail("deterministic provider package policy drift")


def validate_hashes(sources: dict[Path, tuple[str, str]]) -> None:
    for relative, (text, _code) in sources.items():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != EXPECTED_SHA256[relative]:
            fail(f"entropy reviewed source hash drift: {relative}")


def validate(root: Path) -> None:
    sources = load_sources(root)
    validate_structure(sources)
    validate_isolation(root)
    validate_hashes(sources)
