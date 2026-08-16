#!/usr/bin/env python3
"""Validate the reviewed v0.21.0 canonical ASN.1 value boundary."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path


LIB = Path("crates/brynja-pki/src/lib.rs")
ASN1 = Path("crates/brynja-pki/src/asn1.rs")
BIT_STRING = Path("crates/brynja-pki/src/asn1/bit_string.rs")
CONSTRUCTED = Path("crates/brynja-pki/src/asn1/constructed.rs")
ERROR = Path("crates/brynja-pki/src/asn1/error.rs")
INTEGER = Path("crates/brynja-pki/src/asn1/integer.rs")
OID = Path("crates/brynja-pki/src/asn1/object_identifier.rs")
STRING = Path("crates/brynja-pki/src/asn1/string.rs")
TIME = Path("crates/brynja-pki/src/asn1/time.rs")
VALUE = Path("crates/brynja-pki/src/asn1/value.rs")
TEST = Path("crates/brynja-pki/tests/asn1.rs")
MANIFEST = Path("crates/brynja-pki/Cargo.toml")
PACKAGE_POLICY = Path("package-policy.toml")
SOURCES = (
    LIB,
    ASN1,
    BIT_STRING,
    CONSTRUCTED,
    ERROR,
    INTEGER,
    OID,
    STRING,
    TIME,
    VALUE,
)
EXPECTED_SHA256 = {
    LIB: "e20139511f8eaacd172318451582f46634aff0bb619e39dc4091b9dd18279855",
    ASN1: "a24b4cecbba09c814b1aa90e1158f47cabb188f2ae6986d7c60b48f116e18d0c",
    BIT_STRING: "e8494a9c6462f0931da878f7c05060fb99a258ffef3684f4c9a3440f75dd6b09",
    CONSTRUCTED: "f8b65c3a8b8f6f8201af9ed0540cc765da9f090f37023ac7b371a307dd7904f8",
    ERROR: "56b02505428ff9dc17f6adb468ceaac037727b439f0f89ef63b0bfd88f9469b6",
    INTEGER: "a34f8b0a80b02b72d8ec1c96a30b3965d7ac8fc471baf6ccc982a0c1710cdb31",
    OID: "ca6dc69c89f84be0a329f438ab9bbc8ede09dc3ce2c7aea5068ba3f129e71d4b",
    STRING: "786311f63fb4888db1d3e868c04d3f76115a7694c24552a9c8946e213ffcb380",
    TIME: "3c6771201841718b92f9af5c92711ad0d524aab467276705220cfeb7214a9ac5",
    VALUE: "2493facd71dded437313bee152292c641601a1e309018af67824d8f184c46467",
}


class Asn1ValuePolicyError(RuntimeError):
    """The reviewed ASN.1 value boundary differs from policy."""


def fail(message: str) -> None:
    raise Asn1ValuePolicyError(message)


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
            fail(f"ASN.1 source must be a regular file: {relative}")
        text = source.read_text(encoding="utf-8")
        if len(text.splitlines()) > 500:
            fail(f"ASN.1 source exceeds 500 lines: {relative}")
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
        "Box<",
        "HashMap",
        "Provider",
        "Socket",
        "TcpStream",
        "UdpSocket",
        "decrypt(",
        "encrypt(",
        "verify_signature",
        "static mut",
        "Atomic",
        "thread_local",
    ):
        if forbidden in all_code:
            fail(f"ASN.1 values crossed forbidden boundary: {forbidden}")
    if re.search(r"\bString\b", all_code):
        fail("ASN.1 values crossed forbidden boundary: String")

    library = sources[LIB][1]
    for token in (
        "#![no_std]",
        "pub const BOUNDED_DER_READER_IMPLEMENTED: bool = true;",
        "pub const CANONICAL_ASN1_PRIMITIVES_IMPLEMENTED: bool = true;",
        "pub const IMPLEMENTED: bool = false;",
    ):
        require(library, token, "PKI package")

    integer = sources[INTEGER][1]
    for token in (
        "pub struct CanonicalInteger<'input>",
        "bytes.split_first()",
        "first == 0 && second & 0x80 == 0",
        "first == 0xff && second & 0x80 != 0",
        "checked_sub(input.len())",
        "IntegerValueError::Negative",
        "IntegerValueError::Overflow",
    ):
        require(integer, token, "INTEGER")

    bit_string = sources[BIT_STRING][1]
    for token in (
        "pub struct BitString<'input>",
        "unused_bits > 7",
        "last & mask != 0",
        "checked_mul(8)",
        "pub struct OctetString<'input>",
    ):
        require(bit_string, token, "string octets")

    oid = sources[OID][1]
    for token in (
        "pub struct ObjectIdentifier<'input>",
        "if first == 0x80",
        "checked_mul(128)",
        "octet & 0x80 == 0",
        "pub struct ObjectIdentifierArcs<'input>",
    ):
        require(oid, token, "OBJECT IDENTIFIER")

    string = sources[STRING][1]
    for token in (
        "pub enum CharacterStringKind",
        "core::str::from_utf8(bytes).is_ok()",
        "octet.is_ascii_digit()",
        "octet.is_ascii_alphanumeric()",
        "bytes.iter().all(u8::is_ascii)",
        "char::from_u32(u32::from_be_bytes(array)).is_some()",
        "!(0xd800..=0xdfff).contains(&scalar)",
    ):
        require(string, token, "character strings")

    time = sources[TIME][1]
    for token in (
        "encoded.len() != 13",
        "encoded.last().copied() != Some(b'Z')",
        "encoded.get(14).copied() != Some(b'.')",
        "digits.last().copied() == Some(b'0')",
        "day > days_in_month(year, month)",
        "hour > 23",
        "minute > 59",
        "second > 59",
        "is_leap_year(year)",
    ):
        require(time, token, "time values")

    constructed = sources[CONSTRUCTED][1]
    for token in (
        "pub struct CanonicalSequence<'input>",
        "pub struct CanonicalSet<'input>",
        "pub struct CanonicalSetOf<'input>",
        "prior >= key",
        "padded_compare(prior, child.encoded()) == Ordering::Greater",
        "Reader::<STACK>::new",
        "element.depth() == 0",
    ):
        require(constructed, token, "constructed values")

    value = sources[VALUE][1]
    for token in (
        "pub enum CanonicalValue<'input>",
        "pub fn decode_primitive",
        "[0] => Ok(false)",
        "[0xff] => Ok(true)",
        "Err(Asn1Error::UnsupportedType)",
    ):
        require(value, token, "canonical dispatch")

    errors = sources[ERROR][1]
    require(errors, "pub enum Asn1Error", "closed errors")
    if re.search(r"^\s+[A-Z][A-Za-z0-9_]*\s*\{", errors, re.MULTILINE):
        fail("ASN.1 errors gained payload fields")


def validate_tests(root: Path) -> None:
    path = root / TEST
    if not path.is_file() or path.is_symlink():
        fail("ASN.1 tests must be a regular file")
    text = path.read_text(encoding="utf-8")
    if len(text.splitlines()) > 500:
        fail("ASN.1 tests exceed 500 lines")
    for token in (
        "fn canonical_booleans_are_exact",
        "fn integers_are_minimal_and_checked_before_conversion",
        "fn bit_and_octet_strings_preserve_exact_borrows",
        "fn object_identifiers_are_minimal_terminated_and_bounded",
        "fn admitted_character_strings_validate_complete_repertoires",
        "fn utc_and_generalized_times_enforce_calendar_and_der_forms",
        "fn sequence_set_and_set_of_are_distinct_canonical_boundaries",
        "fn exhaustive_boolean_bit_padding_and_two_octet_oid_corpora",
    ):
        require(text, token, "ASN.1 tests")


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
            fail(f"ASN.1 reviewed source hash drift: {relative}")


def validate(root: Path) -> None:
    sources = load_sources(root)
    validate_structure(sources)
    validate_tests(root)
    validate_package(root)
    validate_hashes(sources)
