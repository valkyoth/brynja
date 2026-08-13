#!/usr/bin/env python3
"""Validate the reviewed v0.18.0 security-outcome authority contract."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


SOURCES = (
    Path("crates/brynja-core/src/security_outcome.rs"),
    Path("crates/brynja-core/src/security_outcome/domain.rs"),
    Path("crates/brynja-core/src/security_outcome/state.rs"),
    Path("crates/brynja-core/src/security_outcome/external_key.rs"),
)
EXPECTED_SHA256 = {
    SOURCES[0]: "0823e1e7f60e3f8aed32a0a7c764223fa9d2181efbd426d117b11aa64dbbd5ac",
    SOURCES[1]: "4a8f5229187076ce664487aa595cd9bbe13928073f9b4bded0e03330563a19c4",
    SOURCES[2]: "16dbaa923f79ea35d2151be4d799b14913ed44369b9eebea8729b9ae55a8d17e",
    SOURCES[3]: "e963cbcb1f00e08b487e114e7b4b283a0f4c821bb816fbfee3fbabc30def1a53",
}


class SecurityOutcomePolicyError(RuntimeError):
    """The reviewed authority contract differs from policy."""


def fail(message: str) -> None:
    raise SecurityOutcomePolicyError(message)


def code_without_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def load_sources(root: Path) -> dict[Path, tuple[str, str]]:
    loaded = {}
    for relative in SOURCES:
        source = root / relative
        if not source.is_file() or source.is_symlink():
            fail(f"security-outcome source must be a regular file: {relative}")
        text = source.read_text(encoding="utf-8")
        if len(text.splitlines()) > 500:
            fail(f"security-outcome source exceeds 500 lines: {relative}")
        loaded[relative] = (text, code_without_comments(text))
    return loaded


def require_once(code: str, token: str, label: str) -> None:
    if code.count(token) != 1:
        fail(f"{label} drift: {token}")


def validate_structure(sources: dict[Path, tuple[str, str]]) -> None:
    all_code = "\n".join(code for _text, code in sources.values())
    for forbidden in (
        "unsafe",
        'extern "C"',
        "std::",
        "alloc::",
        "panic!",
        "unwrap(",
        "expect(",
        "SecurityEvent",
        "Alert",
        "BackendDispatch",
        "PendingProvider",
        "static mut",
        "Atomic",
    ):
        if forbidden in all_code:
            fail(f"security-outcome contract crossed forbidden boundary: {forbidden}")

    domain = sources[SOURCES[1]][1]
    for required in (
        "pub enum SecurityDecisionKind",
        "pub trait SecurityDecision: sealed::Sealed",
        "SelfTestDecision",
        "ServiceApprovalDecision",
        "ProtocolSelectionDecision",
        "ProfileSelectionDecision",
        "AuthenticationDecision",
        "TicketDecision",
        "ResumptionDecision",
        "PskDecision",
        "EarlyDataDecision",
        "AntiReplayDecision",
        "AmplificationDecision",
        "ExhaustionDecision",
        "ProviderDecision",
        "KeyLifecycleDecision",
        "EchDecision",
        "PolicyDecision",
        "TerminalTransitionDecision",
    ):
        if required not in domain:
            fail(f"security decision-domain drift: {required}")

    state = sources[SOURCES[2]][1]
    for required in (
        "pub enum SecurityAuthorityState",
        "Ready,",
        "Pending(SecurityDecisionKind)",
        "Terminal,",
        "pub enum SecurityResolution",
        "Approved,",
        "NonApproved,",
        "Rejected(SecurityRejection)",
        "Canceled,",
        "Failed(SecurityFailureKind)",
        "Terminal(SecurityTerminal)",
        "record: Cell<AuthorityRecord>",
        "pub fn begin<D: SecurityDecision>",
        "record.generation.checked_add(1)",
        "D::KIND != ServiceApprovalDecision::KIND",
        "D::KIND == ServiceApprovalDecision::KIND",
        "D::KIND == SecurityDecisionKind::TerminalTransition",
        "!rejection_matches_domain(D::KIND, reason)",
        "!failure_matches_domain(D::KIND, reason)",
        "pub struct SecurityPending",
        "pub fn resolve(self, resolution: SecurityResolution)",
        "pub enum SecurityOutcome",
        "PhantomData<*mut ()>",
    ):
        if required not in state:
            fail(f"authoritative state or result drift: {required}")
    for variant in (
        "\n    Accepted(SecurityReceipt",
        "\n    Approved(SecurityReceipt",
        "\n    NonApproved(SecurityReceipt",
        "\n    Rejected(SecurityReceipt",
        "\n    Pending(SecurityPending",
        "\n    Canceled(SecurityReceipt",
        "\n    Failed(SecurityReceipt",
        "\n    Terminal(SecurityReceipt",
    ):
        require_once(state, variant, "mandatory outcome")
    if re.search(
        r"#\[derive\([^]]*(?:Clone|Copy|Debug)[^]]*\)\]\s*pub struct SecurityPending",
        state,
    ):
        fail("pending security authority gained duplication or formatting")
    if re.search(r"pub\s+(?:record|authority|generation):", state):
        fail("authoritative security state exposed construction fields")

    external = sources[SOURCES[3]][1]
    for required in (
        "pub struct ExternalKeyDestructionToken",
        "DestructionTarget::ExternalStore",
        "pub const fn complete(self)",
        "pub const fn fail(",
        "pub struct ExternalKeyDestroyed",
        "pub enum ExternalKeyDestructionOutcome",
        "pub struct ExternalKeyDestruction",
        "pending: Option<SecurityPending",
        "token_issued: bool",
        "ExternalKeyDestructionError::TokenAlreadyIssued",
        "core::ptr::eq(proof.authority, pending.authority())",
        "proof.generation == pending.generation()",
        "ExternalKeyDestructionOutcome::Complete(_) =>",
        "pending.resolve(SecurityResolution::Accepted)",
        "SecurityTerminal::ExternalKeyDestruction",
        "pub fn abort(mut self)",
        "impl Drop for ExternalKeyDestruction",
        "if let Some(pending) = self.pending.take()",
    ):
        if required not in external:
            fail(f"external-key mandatory transition drift: {required}")
    if re.search(
        r"#\[derive\([^]]*(?:Clone|Copy|Debug)[^]]*\)\]\s*pub struct (?:ExternalKeyDestructionToken|ExternalKeyDestroyed)",
        external,
    ):
        fail("external-key authority gained duplication or formatting")
    for forbidden in (
        "pub const fn new(",
        "pub fn new(",
        "impl Clone for ExternalKey",
        "impl Copy for ExternalKey",
    ):
        if forbidden in external:
            fail(f"external-key proof became forgeable: {forbidden}")


def validate_hashes(sources: dict[Path, tuple[str, str]]) -> None:
    for relative, (text, _code) in sources.items():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != EXPECTED_SHA256[relative]:
            fail(f"security-outcome reviewed source hash drift: {relative}")


def validate(root: Path) -> None:
    sources = load_sources(root)
    validate_structure(sources)
    validate_hashes(sources)
