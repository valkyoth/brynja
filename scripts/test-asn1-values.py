#!/usr/bin/env python3
"""Broken-fixture tests for the v0.21.0 ASN.1 value policy."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import asn1_value_policy as policy


ROOT = Path(__file__).resolve().parents[1]


def replace(root: Path, relative: Path, old: str, new: str) -> None:
    path = root / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"fixture token missing: {old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def reject(label: str, mutation) -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-asn1-values-") as temporary:
        root = Path(temporary)
        copied = (*policy.SOURCES, policy.TEST, policy.MANIFEST, policy.PACKAGE_POLICY)
        for relative in copied:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        mutation(root)
        try:
            policy.validate(root)
        except policy.Asn1ValuePolicyError:
            return
        raise AssertionError(f"ASN.1 fixture accepted: {label}")


def main() -> int:
    reject("unsafe", lambda root: replace(root, policy.INTEGER, "pub fn decode", "pub unsafe fn decode"))
    reject("ffi", lambda root: replace(root, policy.ASN1, "mod value;", 'extern "C" {}\nmod value;'))
    reject("std", lambda root: replace(root, policy.ERROR, "pub enum", "use std::vec::Vec;\npub enum"))
    reject("alloc", lambda root: replace(root, policy.ERROR, "pub enum", "use alloc::vec::Vec;\npub enum"))
    reject("dynamic storage", lambda root: replace(root, policy.ERROR, "pub enum", "type Dynamic = Vec<u8>;\npub enum"))
    reject("provider", lambda root: replace(root, policy.ERROR, "pub enum", "struct Provider;\npub enum"))
    reject("crypto", lambda root: replace(root, policy.ERROR, "pub enum", "fn decrypt() {}\npub enum"))
    reject("socket", lambda root: replace(root, policy.ERROR, "pub enum", "struct Socket;\npub enum"))
    reject("global state", lambda root: replace(root, policy.ERROR, "pub enum", "static mut STATE: u8 = 0;\npub enum"))
    reject("claim", lambda root: replace(root, policy.LIB, "CANONICAL_ASN1_PRIMITIVES_IMPLEMENTED: bool = true", "CANONICAL_ASN1_PRIMITIVES_IMPLEMENTED: bool = false"))
    reject("integer positive padding", lambda root: replace(root, policy.INTEGER, "first == 0 && second & 0x80 == 0", "first == 1 && second & 0x80 == 0"))
    reject("integer negative padding", lambda root: replace(root, policy.INTEGER, "first == 0xff && second & 0x80 != 0", "first == 0xfe && second & 0x80 != 0"))
    reject("integer bounds", lambda root: replace(root, policy.INTEGER, "checked_sub(input.len())", "wrapping_sub(input.len())"))
    reject("bit count", lambda root: replace(root, policy.BIT_STRING, "unused_bits > 7", "unused_bits > 8"))
    reject("bit padding", lambda root: replace(root, policy.BIT_STRING, "last & mask != 0", "last & mask == 0"))
    reject("bit length", lambda root: replace(root, policy.BIT_STRING, "checked_mul(8)", "wrapping_mul(8)"))
    reject("OID minimal", lambda root: replace(root, policy.OID, "if first == 0x80", "if first == 0x81"))
    reject("OID overflow", lambda root: replace(root, policy.OID, "checked_mul(128)", "wrapping_mul(128)"))
    reject("OID termination", lambda root: replace(root, policy.OID, "octet & 0x80 == 0", "octet & 0x80 != 0"))
    reject("UTF-8", lambda root: replace(root, policy.STRING, "core::str::from_utf8(bytes).is_ok()", "true"))
    reject("numeric", lambda root: replace(root, policy.STRING, "octet.is_ascii_digit()", "octet.is_ascii()"))
    reject("printable", lambda root: replace(root, policy.STRING, "octet.is_ascii_alphanumeric()", "octet.is_ascii()"))
    reject("IA5", lambda root: replace(root, policy.STRING, "bytes.iter().all(u8::is_ascii)", "true"))
    reject("BMP", lambda root: replace(root, policy.STRING, "!(0xd800..=0xdfff).contains(&scalar)", "true"))
    reject("UniversalString", lambda root: replace(root, policy.STRING, "char::from_u32(u32::from_be_bytes(array)).is_some()", "true"))
    reject("UTC width", lambda root: replace(root, policy.TIME, "encoded.len() != 13", "encoded.len() != 12"))
    reject("UTC marker", lambda root: replace(root, policy.TIME, "encoded.last().copied() != Some(b'Z')", "false"))
    reject("fraction marker", lambda root: replace(root, policy.TIME, "encoded.get(14).copied() != Some(b'.')", "false"))
    reject("fraction zero", lambda root: replace(root, policy.TIME, "digits.last().copied() == Some(b'0')", "false"))
    reject("calendar", lambda root: replace(root, policy.TIME, "day > days_in_month(year, month)", "day > 31"))
    reject("hour", lambda root: replace(root, policy.TIME, "hour > 23", "hour > 24"))
    reject("set order", lambda root: replace(root, policy.CONSTRUCTED, "prior >= key", "prior > key"))
    reject("set-of order", lambda root: replace(root, policy.CONSTRUCTED, "== Ordering::Greater", "== Ordering::Less"))
    reject("nested DER", lambda root: replace(root, policy.CONSTRUCTED, "Reader::<STACK>::new", "Reader::<1>::new"))
    reject("payload error", lambda root: replace(root, policy.ERROR, "InvalidBoolean,", "InvalidBoolean { value: u8 },"))
    reject("dependency", lambda root: replace(root, policy.MANIFEST, "brynja-core = { workspace = true }", "brynja-core = { workspace = true }\nbrynja-crypto = { workspace = true }"))
    reject("package class", lambda root: replace(root, policy.PACKAGE_POLICY, '[packages.brynja-pki]\nclass = "modern-shared"', '[packages.brynja-pki]\nclass = "modern-engine"'))
    reject("test corpus", lambda root: replace(root, policy.TEST, "fn exhaustive_boolean_bit_padding_and_two_octet_oid_corpora", "fn removed_exhaustive_corpus"))
    reject("oversized", lambda root: (root / policy.TIME).write_text((root / policy.TIME).read_text(encoding="utf-8") + "\n" * 501, encoding="utf-8"))
    reject("reviewed hash", lambda root: replace(root, policy.VALUE, "Closed dispatch", "Dispatch"))
    print("ASN.1 value policy rejects forty allocation, canonicality, overflow, ordering, package, size, test, and hash regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
