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
    Path("provider.rs"): "22ed09e373bafe0efcb55f749d77d808acb3b35aca40d6afc890acbd5788566b",
    Path("provider_capability.rs"): "588ebe84cafe0e7928c8784ca938f2475eebede80a62a28cf1a37f2e02afef0a",
    Path("provider_contract.rs"): "2c451df74da52aee32957fb91fa6127493732c593622721b51476cf96e7c3f3e",
    Path("provider_request.rs"): "36f1a9a4f59e7e566d20bd6d810c4fb8455e3bc5753a1b593575b2f3648f9484",
}
OPERATIONS = (
    "Hash",
    "Mac",
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
    if "pub const ALL: [Self; 18]" not in provider:
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
    for domain in ("InputBytes", "OutputBytes", "ProviderOperations"):
        if request.count(f"ResourceDomain::{domain}") != 1:
            fail(f"provider request resource check drift: {domain}")
    if request.count("work.check(work_units, ExhaustionPhase::Provider)") != 1:
        fail("provider request work check drift")
    for required in (
        "operation: self.operation",
        "ProviderRequestOutcome::Complete(ProviderRequestComplete",
        "ProviderRequestOutcome::Failed(ProviderRequestFailure",
    ):
        if required not in request:
            fail("provider terminal result binding drift")
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
