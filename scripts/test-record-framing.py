#!/usr/bin/env python3
"""Broken-fixture tests for the v0.19.0 record-framing policy."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import record_framing_policy as policy


ROOT = Path(__file__).resolve().parents[1]


def replace(root: Path, relative: Path, old: str, new: str) -> None:
    path = root / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"fixture token missing: {old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def reject(label: str, mutation) -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-record-framing-") as temporary:
        root = Path(temporary)
        for relative in (*policy.SOURCES, policy.MANIFEST, policy.POLICY):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        mutation(root)
        try:
            policy.validate(root)
        except policy.RecordFramingPolicyError:
            return
        raise AssertionError(f"record-framing fixture accepted: {label}")


def main() -> int:
    reject("unsafe", lambda root: replace(root, policy.RECORD, "pub fn parse", "pub unsafe fn parse"))
    reject("ffi", lambda root: replace(root, policy.TLS, "mod record;", 'extern "C" {}\nmod record;'))
    reject("std", lambda root: replace(root, policy.ERROR, "pub enum", "use std::vec::Vec;\npub enum"))
    reject("alloc", lambda root: replace(root, policy.ERROR, "pub enum", "use alloc::vec::Vec;\npub enum"))
    reject("dynamic bytes", lambda root: replace(root, policy.ERROR, "pub enum", "type Dynamic = Vec<u8>;\npub enum"))
    reject("provider", lambda root: replace(root, policy.ERROR, "pub enum", "struct Provider;\npub enum"))
    reject("secret", lambda root: replace(root, policy.ERROR, "pub enum", "struct Secret;\npub enum"))
    reject("socket", lambda root: replace(root, policy.ERROR, "pub enum", "struct Socket;\npub enum"))
    reject("decrypt", lambda root: replace(root, policy.ERROR, "pub enum", "fn decrypt() {}\npub enum"))
    reject("fallback", lambda root: replace(root, policy.ERROR, "pub enum", "fn fallback() {}\npub enum"))
    reject("public wire version", lambda root: replace(root, policy.CONTENT, "version: ProtocolVersion", "pub version: ProtocolVersion"))
    reject("heartbeat content", lambda root: replace(root, policy.CONTENT, "Heartbeat,", "HeartbeatRemoved,"))
    reject("heartbeat extension", lambda root: replace(root, policy.CONTENT, "HEARTBEAT_EXTENSION_TYPE: u16 = 15", "HEARTBEAT_EXTENSION_TYPE: u16 = 16"))
    reject("heartbeat rejection", lambda root: replace(root, policy.CONTENT, "Err(RecordError::HeartbeatRejected)", "Err(RecordError::UnsupportedContentType)"))
    reject(
        "TLS 1.3 cleartext application data",
        lambda root: replace(
            root,
            policy.CONTENT,
            "return Err(RecordError::UnprotectedApplicationData);",
            "return Ok(content_type);",
        ),
    )
    reject("unknown coercion", lambda root: replace(root, policy.CONTENT, "ContentTypeClass::Unassigned", "ContentTypeClass::Assigned(ContentType::Alert)"))
    reject("TLS plaintext bound", lambda root: replace(root, policy.RECORD, "MAX_PLAINTEXT_LENGTH", "MAX_TLS12_CIPHERTEXT_LENGTH"))
    reject("TLS 1.2 ciphertext bound", lambda root: replace(root, policy.RECORD, "MAX_TLS12_CIPHERTEXT_LENGTH", "MAX_TLS13_CIPHERTEXT_LENGTH"))
    reject("TLS 1.3 ciphertext bound", lambda root: replace(root, policy.RECORD, "MAX_TLS13_CIPHERTEXT_LENGTH", "MAX_TLS12_CIPHERTEXT_LENGTH"))
    reject("DTLS fixed bits", lambda root: replace(root, policy.DTLS, "UNIFIED_FIXED_BITS: u8 = 0x20", "UNIFIED_FIXED_BITS: u8 = 0x40"))
    reject("CID mismatch", lambda root: replace(root, policy.DTLS, "RecordError::ConnectionIdMismatch", "RecordError::Truncated"))
    reject("DTLS plaintext epoch", lambda root: replace(root, policy.DTLS, "RecordError::InvalidPlaintextEpoch", "RecordError::Truncated"))
    reject("DTLS 1.2 profile", lambda root: replace(root, policy.DTLS12, "ProtocolVersion::Dtls12", "ProtocolVersion::Dtls13"))
    reject("record error payload", lambda root: replace(root, policy.ERROR, "Truncated,", "Truncated { offset: usize },"))
    reject("protocol dependency", lambda root: replace(root, policy.MANIFEST, "brynja-core = { workspace = true }", "brynja-core = { workspace = true }\nbrynja-crypto = { workspace = true }"))
    reject("package class", lambda root: replace(root, policy.POLICY, '[packages.brynja-protocol]\nclass = "modern-shared"', '[packages.brynja-protocol]\nclass = "modern-engine"'))
    reject(
        "engine dependency",
        lambda root: replace(
            root,
            policy.POLICY,
            'required = ["brynja-core", "brynja-crypto", "brynja-pki", "brynja-protocol"]',
            'required = ["brynja-core", "brynja-crypto", "brynja-pki"]',
        ),
    )
    reject("oversized source", lambda root: (root / policy.DTLS).write_text((root / policy.DTLS).read_text(encoding="utf-8") + "\n" * 501, encoding="utf-8"))
    reject("reviewed hash", lambda root: replace(root, policy.RECORD, "TLS stream record framing", "TLS record framing"))
    reject("implementation claim", lambda root: replace(root, policy.LIB, "TLS_DTLS_RECORD_FRAMING_IMPLEMENTED: bool = true", "TLS_DTLS_RECORD_FRAMING_IMPLEMENTED: bool = false"))
    print("record-framing policy rejects thirty profile, cleartext, heartbeat, bound, package, size, and hash regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
