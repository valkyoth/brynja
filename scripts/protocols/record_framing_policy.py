#!/usr/bin/env python3
"""Validate the reviewed v0.19.0 TLS and DTLS record-framing boundary."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path


LIB = Path("crates/brynja-protocol/src/lib.rs")
TLS = Path("crates/brynja-protocol/src/tls.rs")
CONTENT = Path("crates/brynja-protocol/src/tls/content_type.rs")
ERROR = Path("crates/brynja-protocol/src/tls/error.rs")
RECORD = Path("crates/brynja-protocol/src/tls/record.rs")
DTLS = Path("crates/brynja-protocol/src/tls/dtls.rs")
DTLS12 = Path("crates/brynja-protocol/src/tls/dtls12_ciphertext.rs")
MANIFEST = Path("crates/brynja-protocol/Cargo.toml")
POLICY = Path("package-policy.toml")
SOURCES = (LIB, TLS, CONTENT, ERROR, RECORD, DTLS, DTLS12)
EXPECTED_SHA256 = {
    LIB: "80791d0e9fb05193522810c3bb7d64a1177daf2a7c1985fa20f0b6baecbeda66",
    TLS: "5f3e727c9eabac8d0d77809479c213559d2123bae402bbf1b6106df193f965ff",
    CONTENT: "d0b78e5828c49e104a3193d0dfb1c0433d11abb4e20cc044943c26a050aa8081",
    ERROR: "b7d0f6b85e6787db39d062c107b835d30ee42fc927b7e6a6ab7fd586a4cdda63",
    RECORD: "20c9a167380e1562916eb75c3ba9c3325641afeae75d31bc1d87b1747458a2c5",
    DTLS: "751ca4e00fd71dfdcef8495ec99bee411713d3fb1e0c4bc0c5a437a26efd2fa1",
    DTLS12: "8d0320531605e263451c0ba4e089ec80fddd42ae850f869d43dc59a903414aab",
}


class RecordFramingPolicyError(RuntimeError):
    """The reviewed record-framing boundary differs from policy."""


def fail(message: str) -> None:
    raise RecordFramingPolicyError(message)


def code_without_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def load_sources(root: Path) -> dict[Path, tuple[str, str]]:
    loaded = {}
    for relative in SOURCES:
        source = root / relative
        if not source.is_file() or source.is_symlink():
            fail(f"record-framing source must be a regular file: {relative}")
        text = source.read_text(encoding="utf-8")
        if len(text.splitlines()) > 500:
            fail(f"record-framing source exceeds 500 lines: {relative}")
        loaded[relative] = (text, code_without_comments(text))
    return loaded


def require(code: str, token: str, label: str) -> None:
    if token not in code:
        fail(f"{label} drift: {token}")


def validate_structure(root: Path, sources: dict[Path, tuple[str, str]]) -> None:
    all_code = "\n".join(code for _text, code in sources.values())
    for forbidden in (
        "unsafe",
        'extern "C"',
        "std::",
        "alloc::",
        "String",
        "Vec<",
        "Box<",
        "Provider",
        "SecurityAuthority",
        "SecurityResolution",
        "Secret",
        "Socket",
        "TcpStream",
        "UdpSocket",
        "fallback",
        "decrypt(",
        "encrypt(",
        "static mut",
        "Atomic",
        "thread_local",
    ):
        if forbidden in all_code:
            fail(f"record framing crossed forbidden boundary: {forbidden}")

    library = sources[LIB][1]
    for required in (
        "#![no_std]",
        "pub mod tls;",
        "pub const TLS_DTLS_RECORD_FRAMING_IMPLEMENTED: bool = true;",
    ):
        require(library, required, "protocol package")

    content = sources[CONTENT][1]
    for required in (
        "pub enum ContentType",
        "Heartbeat,",
        "Tls12Cid,",
        "Ack,",
        "pub struct ContentTypeCode(u8);",
        "pub const fn classify(code: u8)",
        "ContentTypeClass::Unassigned",
        "pub struct WirePolicy",
        "version: ProtocolVersion",
        "pub const fn for_version(version: ProtocolVersion)",
        "HEARTBEAT_EXTENSION_TYPE: u16 = 15",
        "pub const fn reject_heartbeat_negotiation",
        "Err(RecordError::HeartbeatRejected)",
        "return Err(RecordError::UnprotectedApplicationData);",
        "RecordError::InvalidCiphertextType",
        "pub fn admit_inner_content_type",
    ):
        require(content, required, "wire policy")
    if re.search(r"pub\s+version:\s*ProtocolVersion", content):
        fail("wire policy selected version became caller-mutable")

    record = sources[RECORD][1]
    for required in (
        "pub struct LegacyRecordVersion([u8; 2]);",
        "pub struct TlsPlaintext<'input>",
        "pub struct TlsCiphertext<'input>",
        "pub fn parse(",
        "policy: WirePolicy",
        "MAX_PLAINTEXT_LENGTH",
        "MAX_TLS12_CIPHERTEXT_LENGTH",
        "MAX_TLS13_CIPHERTEXT_LENGTH",
        "RecordError::InvalidCiphertextVersion",
        "WriteCursor::new(output)",
        ".write_parts(",
    ):
        require(record, required, "TLS record framing")
    if "ProtocolVersion::Tls13" not in record:
        fail("TLS 1.3 constants are not enforced after typed selection")

    dtls = sources[DTLS][1]
    for required in (
        "pub struct DtlsPlaintext<'input>",
        "pub struct Dtls13CiphertextConfig",
        "pub enum Dtls13Sequence",
        "pub struct Dtls13CiphertextHeader<'cid>",
        "pub struct Dtls13Ciphertext<'input>",
        "UNIFIED_FIXED_BITS: u8 = 0x20",
        "RecordError::ConnectionIdMismatch",
        "RecordError::InvalidPlaintextEpoch",
        "cursor.remaining_len()",
        "pub fn encode_dtls13_ciphertext",
    ):
        require(dtls, required, "DTLS 1.3 framing")

    dtls12 = sources[DTLS12][1]
    for required in (
        "pub struct Dtls12Ciphertext<'input>",
        "ProtocolVersion::Dtls12",
        "MAX_TLS12_CIPHERTEXT_LENGTH",
        "pub fn parse(",
        "pub fn encode(",
    ):
        require(dtls12, required, "DTLS 1.2 ciphertext framing")

    error = sources[ERROR][1]
    for required in (
        "pub enum RecordError",
        "HeartbeatRejected,",
        "UnprotectedApplicationData,",
        "RecordOverflow,",
        "InvalidUnifiedHeader,",
        "InsufficientOutput,",
    ):
        require(error, required, "closed framing errors")
    if re.search(r"^\s+[A-Z][A-Za-z0-9_]*\s*\{", error, re.MULTILINE):
        fail("record errors gained payload fields")


def validate_package(root: Path) -> None:
    manifest = tomllib.loads((root / MANIFEST).read_text(encoding="utf-8"))
    dependencies = manifest.get("dependencies", {})
    if set(dependencies) != {"brynja-core"}:
        fail("brynja-protocol must depend only on brynja-core")
    if manifest.get("features") != {"default": []}:
        fail("brynja-protocol features changed")
    policy = tomllib.loads((root / POLICY).read_text(encoding="utf-8"))
    package = policy["packages"].get("brynja-protocol")
    expected = {
        "class": "modern-shared",
        "publish": "crates-io",
        "required": ["brynja-core"],
        "optional": {},
    }
    if package != expected:
        fail("brynja-protocol package classification changed")
    for engine in ("brynja-tls12", "brynja-tls13", "brynja-dtls"):
        if "brynja-protocol" not in policy["packages"][engine]["required"]:
            fail(f"{engine} lost the shared record-framing dependency")


def validate_hashes(sources: dict[Path, tuple[str, str]]) -> None:
    for relative, (text, _code) in sources.items():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != EXPECTED_SHA256[relative]:
            fail(f"record-framing reviewed source hash drift: {relative}")


def validate(root: Path) -> None:
    sources = load_sources(root)
    validate_structure(root, sources)
    validate_package(root)
    validate_hashes(sources)
