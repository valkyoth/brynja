#!/usr/bin/env python3
"""Validate the narrow v0.13.0 provider-contract source boundary."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


SOURCE_ROOT = Path("crates/brynja-core/src")
SOURCES = (
    Path("provider.rs"),
    Path("provider_capability.rs"),
    Path("provider_contract.rs"),
    Path("provider_request.rs"),
)
EXPECTED_SHA256 = {
    Path("provider.rs"): "487abd5036e98c64bc67bf93e571ccded0e6b937c4a91eab77df513a4b9e2575",
    Path("provider_capability.rs"): "588ebe84cafe0e7928c8784ca938f2475eebede80a62a28cf1a37f2e02afef0a",
    Path("provider_contract.rs"): "59ea3fada9c7f8bd5a3ee25842b36bb235a37ddad241b60fdf44bf2298f4bb43",
    Path("provider_request.rs"): "28ec8d61126287aa8e7e7d65c014f1f3a942070f0736812928494f69e3278381",
}
OPERATIONS = (
    "Hash",
    "MacGenerate",
    "MacVerify",
    "KeyDerivation",
    "KeyAgreement",
    "Sign",
    "Verify",
    "KemEncapsulate",
    "KemDecapsulate",
    "AeadSeal",
    "AeadOpen",
    "Entropy",
    "WallClock",
    "MonotonicClock",
    "CertificatePath",
    "StorageRead",
    "StorageWrite",
    "PendingPoll",
    "PendingCancel",
)


class ProviderContractPolicyError(RuntimeError):
    """The reviewed provider-contract source boundary drifted."""


def fail(message: str) -> None:
    raise ProviderContractPolicyError(message)


def load_sources(root: Path) -> dict[Path, str]:
    directory = root / SOURCE_ROOT
    loaded: dict[Path, str] = {}
    for relative in SOURCES:
        path = directory / relative
        if not path.is_file() or path.is_symlink():
            fail(f"provider source must be a regular file: {relative}")
        text = path.read_text(encoding="utf-8")
        if len(text.splitlines()) > 500:
            fail(f"provider source exceeds 500 lines: {relative}")
        loaded[relative] = text
    return loaded


def validate_operations(provider: str) -> None:
    match = re.search(
        r"pub enum ProviderOperation \{(?P<body>.*?)\n\}", provider, re.DOTALL
    )
    if match is None:
        fail("provider operation enum missing")
    variants = tuple(re.findall(r"^    ([A-Z][A-Za-z0-9]+),$", match["body"], re.MULTILINE))
    if variants != OPERATIONS:
        fail("provider exact-operation inventory drift")
    if "pub const ALL: [Self; 19]" not in provider:
        fail("provider operation enumeration length drift")
    if len(re.findall(r"Self::[A-Z][A-Za-z0-9]+ =>", provider)) != len(OPERATIONS):
        fail("provider operation mask coverage drift")
    masks = tuple(
        int(value.replace("_", ""))
        for value in re.findall(r"Self::[A-Z][A-Za-z0-9]+ => ([0-9_]+),", provider)
    )
    if masks != tuple(1 << index for index in range(len(OPERATIONS))):
        fail("provider operation masks are not unique powers of two")


def validate_structure(sources: dict[Path, str]) -> None:
    combined = "\n".join(sources.values())
    for forbidden in (
        "std::",
        "alloc::",
        "unsafe ",
        "ProtocolVersion",
        "brynja_platform",
        "target_arch",
        "extern \"",
    ):
        if forbidden in combined:
            fail(f"provider boundary contains forbidden dependency: {forbidden}")

    validate_operations(sources[Path("provider.rs")])

    capability = sources[Path("provider_capability.rs")]
    for required in (
        "if self.bits & mask != 0",
        "if self.bits == 0",
        "self.bits & operation.mask() != 0",
    ):
        if capability.count(required) != 1:
            fail("provider capability single-assignment structure drift")

    contract = sources[Path("provider_contract.rs")]
    for type_name in ("ProviderHandle", "ProviderAuthorization"):
        if re.search(
            rf"#\[derive\([^]]*(?:Clone|Copy|Debug)[^]]*\)\]\s*pub struct {type_name}",
            contract,
        ):
            fail(f"opaque provider token gained duplication or formatting: {type_name}")
    if contract.count("if self.provider.capabilities.contains(operation)") != 1:
        fail("exact-operation authorization check drift")
    if contract.count("core::ptr::eq(self.provider, provider)") != 1:
        fail("exact installed-provider identity check drift")
    if any(token in contract for token in (".or_else(", "fallback_provider", "ProviderRegistry")):
        fail("provider boundary introduced implicit fallback")
    if contract.count("if destruction_targets.is_empty()") != 1:
        fail("mandatory destruction-target check drift")
    installed = re.search(
        r"pub struct InstalledProvider \{(?P<body>.*?)\n\}", contract, re.DOTALL
    )
    if installed is None:
        fail("installed provider contract missing")
    for field in (
        "capabilities: ProviderCapabilities",
        "resources: ResourceBudget",
        "work: WorkBudget",
        "destruction_targets: DestructionTargets",
    ):
        if installed["body"].count(field) != 1:
            fail(f"installed provider frozen field drift: {field}")

    request = sources[Path("provider_request.rs")]
    if re.search(r"&(?:'[A-Za-z_][A-Za-z0-9_]*\s+)?mut\s*\[u8\]", request):
        fail("provider request gained a mutable effect buffer")
    if request.count("checked_add(self.context.len())") != 1:
        fail("provider frame aggregate-length check drift")
    if "provider: &'provider InstalledProvider" not in request:
        fail("prepared request lost its exact installed-provider binding")
    if "resources: &'provider ResourceBudget" in request:
        fail("prepared request retained only a detachable resource budget")
    if "work_units" in request:
        fail("provider request accepts a caller-supplied work claim")
    if request.count("self.remaining_work.checked_sub(units)") != 1:
        fail("provider-owned monotonic work meter drift")
    if request.count("operation.forbids_byte_output()") != 1:
        fail("typed verification output prohibition drift")
    for domain in ("InputBytes", "OutputBytes", "ProviderOperations"):
        if request.count(f"ResourceDomain::{domain}") != 1:
            fail(f"provider request resource check drift: {domain}")
    if re.search(r"pub(?:\s+const)?\s+fn\s+(?:complete|fail)\s*\(", request):
        fail("request holder can manufacture a provider result")
    if re.search(
        r"#\[derive\([^]]*(?:Clone|Copy|Debug)[^]]*\)\]\s*pub struct ProviderRequest",
        request,
    ):
        fail("provider request gained duplication or formatting")


def validate_hashes(sources: dict[Path, str]) -> None:
    for relative, text in sources.items():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != EXPECTED_SHA256[relative]:
            fail(f"provider reviewed source hash drift: {relative}")


def validate(root: Path) -> None:
    sources = load_sources(root)
    validate_structure(sources)
    validate_hashes(sources)
