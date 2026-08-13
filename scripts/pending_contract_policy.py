#!/usr/bin/env python3
"""Validate the reviewed v0.16.0 pending-operation lifecycle."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


SOURCES = (
    Path("crates/brynja-core/src/pending.rs"),
    Path("crates/brynja-core/src/pending/request.rs"),
    Path("crates/brynja-core/src/pending/effect.rs"),
    Path("crates/brynja-core/src/pending/lifecycle.rs"),
)
EXPECTED_SHA256 = {
    SOURCES[0]: "78d22ca8e73ab58b24c4e759c13f50265e07d785960056dc58b147a8714d8167",
    SOURCES[1]: "70530c74014d8b434930ed55d10e65be63e73ce03fcd983165e80fe683b812dc",
    SOURCES[2]: "fd9b6e779a183d3afa1857e391fd61c01b2606754a7bc2beec926006a33176e8",
    SOURCES[3]: "fbdbfc7052f08f442c9f0dad4e8bafeaab89dfab4d75b1004a9a9cc2606465be",
}


class PendingContractPolicyError(RuntimeError):
    """The reviewed pending-operation boundary differs from policy."""


def fail(message: str) -> None:
    raise PendingContractPolicyError(message)


def code_without_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def load_sources(root: Path) -> dict[Path, tuple[str, str]]:
    loaded = {}
    for relative in SOURCES:
        source = root / relative
        if not source.is_file() or source.is_symlink():
            fail(f"pending source must be a regular file: {relative}")
        text = source.read_text(encoding="utf-8")
        if len(text.splitlines()) > 500:
            fail(f"pending source exceeds 500 lines: {relative}")
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
        "mem::forget",
        "thread::",
        "target_arch",
        "brynja_platform",
    ):
        if forbidden in all_code:
            fail(f"pending implementation crossed forbidden boundary: {forbidden}")

    request = sources[SOURCES[1]][1]
    for required in (
        "pub struct PendingLimits",
        "pub struct PendingRequest",
        "PendingRequestKind::Certificate => operation == ProviderOperation::CertificatePath",
        "PendingRequestKind::Signature => operation == ProviderOperation::Sign",
        "PendingRequestKind::Accelerator => operation.is_acceleratable()",
        "ProviderOperation::PendingPoll",
        "ProviderOperation::PendingCancel",
        "PendingResource::ExternalKey => Some(DestructionTarget::ExternalStore)",
        "PendingResource::AcceleratorHandle => Some(DestructionTarget::Accelerator)",
        "next > self.limits.effect_attempts()",
        "next > self.limits.backpressure_responses()",
    ):
        require_once(request, required, "pending request admission")
    if re.search(
        r"#\[derive\([^]]*(?:Clone|Copy|Debug)[^]]*\)\]\s*pub struct PendingRequest",
        request,
    ):
        fail("pending request gained duplication or formatting")

    effect = sources[SOURCES[2]][1]
    for required in (
        "pub struct PendingEffectRequest",
        "pub enum PendingBegin<State>",
        "pub enum PendingStep<State>",
        "pub enum PendingCancelStep<State>",
        "pub struct PendingDestructionToken",
        "pub trait PendingProvider",
        "pub const fn complete(self)",
        "pub const fn fail(self, kind: PendingDestructionFailureKind)",
        "fn handle_drop_failure(&mut self, failure: PendingDestructionFailure);",
    ):
        require_once(effect, required, "pending provider effect")
    for variant in (
        "Complete(State)",
        "Active(State)",
        "Retry(State, PendingRetryReason)",
        "Backpressure(State, PendingBackpressure)",
        "Failed(State, ProviderFailureKind)",
    ):
        if effect.count(variant) < 1:
            fail(f"pending state ownership drift: {variant}")
    if re.search(
        r"#\[derive\([^]]*(?:Clone|Copy|Debug)[^]]*\)\]\s*pub struct PendingDestructionToken",
        effect,
    ):
        fail("pending destruction token gained duplication or formatting")

    lifecycle = sources[SOURCES[3]][1]
    for required in (
        "pub struct PendingOperation",
        "if !request.begin_attempt()",
        "if !self.begin_attempt()",
        "self.record_backpressure(reason)",
        "self.destroy(PendingDestructionCause::Completion)",
        "self.destroy(PendingDestructionCause::Cancellation)",
        "self.destroy(PendingDestructionCause::Drop)",
        "self.effect.handle_drop_failure(failure);",
        "let Some(state) = self.state.take()",
        "PendingDestructionToken::new(",
    ):
        if lifecycle.count(required) < 1:
            fail(f"pending lifecycle transition drift: {required}")
    if re.search(
        r"#\[derive\([^]]*(?:Clone|Copy|Debug)[^]]*\)\]\s*pub struct PendingOperation",
        lifecycle,
    ):
        fail("pending operation gained duplication or formatting")
    if "pub state:" in lifecycle or "pub effect:" in lifecycle:
        fail("pending operation exposed provider state")


def validate_hashes(sources: dict[Path, tuple[str, str]]) -> None:
    for relative, (text, _code) in sources.items():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != EXPECTED_SHA256[relative]:
            fail(f"pending reviewed source hash drift: {relative}")


def validate(root: Path) -> None:
    sources = load_sources(root)
    validate_structure(sources)
    validate_hashes(sources)
