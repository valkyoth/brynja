#!/usr/bin/env python3
"""Validate the reviewed v0.18.0 security-outcome authority contract."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


MODULE = Path("crates/brynja-core/src/security_outcome.rs")
DOMAIN = Path("crates/brynja-core/src/security_outcome/domain.rs")
RESOLUTION = Path("crates/brynja-core/src/security_outcome/resolution.rs")
STATE = Path("crates/brynja-core/src/security_outcome/state.rs")
OUTCOME = Path("crates/brynja-core/src/security_outcome/outcome.rs")
EXTERNAL_KEY = Path("crates/brynja-core/src/security_outcome/external_key.rs")
SOURCES = (MODULE, DOMAIN, RESOLUTION, STATE, OUTCOME, EXTERNAL_KEY)
EXPECTED_SHA256 = {
    MODULE: "fc7284cbd1cc8c0b2344a5fd79d1a21e04a6e554aaf7679bb35ae02f8db0dc06",
    DOMAIN: "4a8f5229187076ce664487aa595cd9bbe13928073f9b4bded0e03330563a19c4",
    RESOLUTION: "993ec40e9864cdcbf1b0c56670f320e038db274811b26a6b7f00d80cea0dd4d3",
    STATE: "f8d5a0c146c84c8f5a2527852d1c9c083842865b33ecaa54bcc74910b9617a61",
    OUTCOME: "1533eac2c54cfdd7fd23c188fa0233ce64111792a4589f4ea8537563bba8bb1c",
    EXTERNAL_KEY: "7cf4b61affa120becd63a7ea4112df3a0e30f8305555c6a7956cd32251c47202",
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

    domain = sources[DOMAIN][1]
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

    resolution = sources[RESOLUTION][1]
    for required in (
        "pub enum SecurityResolution",
        "pub enum SecurityDisposition",
        "Approved,",
        "NonApproved,",
        "Rejected(SecurityRejection)",
        "Canceled,",
        "Failed(SecurityFailureKind)",
        "Terminal(SecurityTerminal)",
        "DecisionAbandoned,",
        "OutcomeAbandoned,",
        "failure_matches_domain",
        "rejection_matches_domain",
    ):
        if required not in resolution:
            fail(f"security resolution-domain drift: {required}")

    state = sources[STATE][1]
    for required in (
        "pub enum SecurityAuthorityState",
        "Ready,",
        "Pending(SecurityDecisionKind)",
        "AwaitingCommit {",
        "disposition: SecurityDisposition",
        "Terminal,",
        "record: Cell<AuthorityRecord>",
        "pub fn begin<D: SecurityDecision>",
        "record.generation.checked_add(1)",
        "matches!(resolution, SecurityResolution::Approved)",
        "SecurityResolution::Accepted) && !positive_authorized",
        "matches!(resolution, SecurityResolution::NonApproved)",
        "D::KIND == ServiceApprovalDecision::KIND",
        "D::KIND == SecurityDecisionKind::TerminalTransition",
        "D::KIND == SecurityDecisionKind::SelfTest",
        "SecurityResolution::Failed(SecurityFailureKind::SelfTest)",
        "self.fail_terminal(SecurityTerminal::Integrity)",
        "!rejection_matches_domain(D::KIND, reason)",
        "!failure_matches_domain(D::KIND, reason)",
        "pub struct SecurityPending",
        "pub fn resolve(",
        "resolve_verified_accepted",
        "impl<D: SecurityDecision> Drop for SecurityPending",
        "SecurityTerminal::DecisionAbandoned",
        "pub(super) fn commit<D: SecurityDecision>",
        "disposition: SecurityDisposition",
        "decision: D::KIND",
        "PhantomData<*mut ()>",
    ):
        if required not in state:
            fail(f"authoritative state or result drift: {required}")
    if state.count("disposition: SecurityDisposition") != 2:
        fail("authoritative state or result drift: disposition")
    if re.search(
        r"#\[derive\([^]]*(?:Clone|Copy|Debug)[^]]*\)\]\s*pub struct SecurityPending",
        state,
    ):
        fail("pending security authority gained duplication or formatting")
    if re.search(r"pub\s+(?:record|authority|generation|armed):", state):
        fail("authoritative security state exposed construction fields")

    outcome = sources[OUTCOME][1]
    for required in (
        "struct Completion",
        "disposition: SecurityDisposition",
        ".commit::<D>(self.generation, self.disposition)",
        "impl<D: SecurityDecision> Drop for Completion",
        "SecurityTerminal::OutcomeAbandoned",
        "pub struct SecurityAccepted",
        "pub struct SecurityApproved",
        "pub struct SecurityNonApproved",
        "pub struct SecurityRejected",
        "pub struct SecurityCanceled",
        "pub struct SecurityFailed",
        "reason: SecurityRejection",
        "reason: SecurityFailureKind",
        "pub enum SecurityOutcome",
    ):
        if required not in outcome:
            fail(f"disposition-bound outcome drift: {required}")
    for variant in (
        "\n    Accepted(SecurityAccepted",
        "\n    Approved(SecurityApproved",
        "\n    NonApproved(SecurityNonApproved",
        "\n    Rejected(SecurityRejected",
        "\n    Pending(SecurityPending",
        "\n    Canceled(SecurityCanceled",
        "\n    Failed(SecurityFailed",
        "\n    Terminal(SecurityReceipt",
    ):
        require_once(outcome, variant, "mandatory disposition-bound outcome")
    if re.search(
        r"#\[derive\([^]]*(?:Clone|Copy|Debug)[^]]*\)\]\s*(?:pub )?struct (?:Completion|SecurityAccepted|SecurityApproved|SecurityNonApproved|SecurityRejected|SecurityCanceled|SecurityFailed)",
        outcome,
    ):
        fail("security outcome gained duplication or formatting")
    if re.search(r"pub\s+(?:completion|reason|authority|generation|disposition|armed):", outcome):
        fail("security outcome exposed construction or relabeling fields")
    if "impl<'authority, D: SecurityDecision> SecurityApproved" not in outcome:
        fail("approved outcome boundary drift")
    approved_impl = outcome.split(
        "impl<'authority, D: SecurityDecision> SecurityApproved", 1
    )[1].split("pub struct SecurityRejected", 1)[0]
    if "fn new(" in approved_impl:
        fail("approved outcome gained a constructor before exact proof admission")

    external = sources[EXTERNAL_KEY][1]
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
        "pending.resolve_verified_accepted()",
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
