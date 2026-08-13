#!/usr/bin/env python3
"""Validate the reviewed v0.20.0 bounded DER-reader boundary."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path


LIB = Path("crates/brynja-pki/src/lib.rs")
DER = Path("crates/brynja-pki/src/der.rs")
ERROR = Path("crates/brynja-pki/src/der/error.rs")
LIMITS = Path("crates/brynja-pki/src/der/limits.rs")
READER = Path("crates/brynja-pki/src/der/reader.rs")
TAG = Path("crates/brynja-pki/src/der/tag.rs")
MANIFEST = Path("crates/brynja-pki/Cargo.toml")
PACKAGE_POLICY = Path("package-policy.toml")
SOURCES = (LIB, DER, ERROR, LIMITS, READER, TAG)
EXPECTED_SHA256 = {
    LIB: "ed8f9b415a574f28cb785a99362ada70a8c015827ca828c6ba090e1eeba298ea",
    DER: "9cdbade4dc46c56a0cb82e185b74f3991a53a8a817ef242e7ddbcbb2f0399c5a",
    ERROR: "e5a46237a5c3ad984ed9295b0f26da3bd8bee13d3488cf3b57f59413bfc566b9",
    LIMITS: "3f096993234a72694cddea3fce988bd68029a8fd1d4fd34e20e56c7dc3215827",
    READER: "b5e06c2e09816ba61a553b42d2fd4208c505f9a041160fec3e425960ba1a4aff",
    TAG: "44639647920a1a75bd5150a9d322b163828999d26024551fd4319b5f4fdfa0e4",
}


class DerReaderPolicyError(RuntimeError):
    """The reviewed DER-reader boundary differs from policy."""


def fail(message: str) -> None:
    raise DerReaderPolicyError(message)


def code_without_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def require(code: str, token: str, label: str) -> None:
    if token not in code:
        fail(f"{label} drift: {token}")


def load_sources(root: Path) -> dict[Path, tuple[str, str]]:
    loaded = {}
    for relative in SOURCES:
        source = root / relative
        if not source.is_file() or source.is_symlink():
            fail(f"DER source must be a regular file: {relative}")
        text = source.read_text(encoding="utf-8")
        if len(text.splitlines()) > 500:
            fail(f"DER source exceeds 500 lines: {relative}")
        loaded[relative] = (text, code_without_comments(text))
    return loaded


def validate_structure(sources: dict[Path, tuple[str, str]]) -> None:
    all_code = "\n".join(code for _text, code in sources.values())
    for forbidden in (
        "unsafe",
        'extern "C"',
        "std::",
        "alloc::",
        "Vec<",
        "String",
        "Box<",
        "HashMap",
        "Provider",
        "Socket",
        "TcpStream",
        "UdpSocket",
        "decrypt(",
        "verify_signature",
        "static mut",
        "Atomic",
        "thread_local",
    ):
        if forbidden in all_code:
            fail(f"DER reader crossed forbidden boundary: {forbidden}")

    library = sources[LIB][1]
    for token in (
        "#![no_std]",
        "pub const BOUNDED_DER_READER_IMPLEMENTED: bool = true;",
        "pub const IMPLEMENTED: bool = false;",
    ):
        require(library, token, "PKI package")

    limits = sources[LIMITS][1]
    for token in (
        "pub struct DerLimits",
        "input_bytes: usize",
        "depth: usize",
        "nodes: usize",
        "children: usize",
        "identifier_octets: usize",
        "length_octets: usize",
        "value_bytes: usize",
        "work: usize",
        "pub struct DerLimitsBuilder",
        "Duplicate(DerLimit)",
        "Incomplete(DerLimit)",
    ):
        require(limits, token, "DER limits")
    if re.search(r"pub\s+(input_bytes|depth|nodes|children|work):", limits):
        fail("DER limits became caller-mutable")

    reader = sources[READER][1]
    for token in (
        "pub struct Reader<'input, const STACK: usize>",
        "frames: [Frame; STACK]",
        "pub fn new(input: &'input [u8], limits: DerLimits)",
        "pub fn next_event(&mut self)",
        "checked_add(length)",
        "DerError::IndefiniteLength",
        "DerError::NonMinimalLength",
        "DerError::NonMinimalTag",
        "DerError::BoundaryViolation",
        "DerError::DepthLimit",
        "DerError::NodeLimit",
        "DerError::ChildLimit",
        "DerError::WorkLimit",
        "count > limit",
        "count > core::mem::size_of::<usize>()",
        "length < 128",
    ):
        require(reader, token, "DER traversal")
    if reader.count("next_event(") != 1:
        fail("DER traversal introduced recursion or an alternate event path")

    errors = sources[ERROR][1]
    require(errors, "pub enum DerError", "DER errors")
    if re.search(r"^\s+[A-Z][A-Za-z0-9_]*\s*\{", errors, re.MULTILINE):
        fail("DER errors gained payload fields")

    tag = sources[TAG][1]
    for token in (
        "pub enum TagClass",
        "Universal",
        "Application",
        "ContextSpecific",
        "Private",
        "pub struct Tag",
        "class: TagClass",
        "constructed: bool",
        "number: u64",
    ):
        require(tag, token, "DER tag")


def validate_package(root: Path) -> None:
    manifest = tomllib.loads((root / MANIFEST).read_text(encoding="utf-8"))
    if set(manifest.get("dependencies", {})) != {"brynja-core"}:
        fail("brynja-pki must depend only on brynja-core")
    if manifest.get("features") != {"default": []}:
        fail("brynja-pki features changed")
    policy = tomllib.loads((root / PACKAGE_POLICY).read_text(encoding="utf-8"))
    expected = {
        "class": "modern-shared",
        "publish": "crates-io",
        "required": ["brynja-core"],
        "optional": {},
    }
    if policy["packages"].get("brynja-pki") != expected:
        fail("brynja-pki package classification changed")


def validate_hashes(sources: dict[Path, tuple[str, str]]) -> None:
    for relative, (text, _code) in sources.items():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != EXPECTED_SHA256[relative]:
            fail(f"DER reviewed source hash drift: {relative}")


def validate(root: Path) -> None:
    sources = load_sources(root)
    validate_structure(sources)
    validate_package(root)
    validate_hashes(sources)
