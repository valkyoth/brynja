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
    Path("crates/brynja-core/src/pending/outcome.rs"),
    Path("crates/brynja-core/src/pending/lifecycle.rs"),
    Path("crates/brynja-core/src/provider_request.rs"),
)
EXPECTED_SHA256 = {
    SOURCES[0]: "46657f8dce1da5563d80510ad3d0dc9f0fa3f9205bb86c8f251ae365c6619223",
    SOURCES[1]: "cd770f4d2af3bd02b321f7ad8bde2976804b81c56df1909ac546222b18669836",
    SOURCES[2]: "2b98ab88bde482ca6b82db1eee7d6ecb825c13750af4244ad6fcf0693b7f13be",
    SOURCES[3]: "0aef23d94769122abff337e7da7ac2c73a3706cc2a4d7bcf02b031b7453bc0ce",
    SOURCES[4]: "0c316190aada645c92c4d01835402fb864055dc51145a9470a02bd96af6291df",
    SOURCES[5]: "28ec8d61126287aa8e7e7d65c014f1f3a942070f0736812928494f69e3278381",
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
        "pub struct PendingWorkPermit",
        "pub enum PendingBeginStep",
        "pub enum PendingStep",
        "pub enum PendingCancelStep",
        "pub struct PendingDestructionToken",
        "pub trait PendingProvider",
        "fn provider_handle(&self) -> ProviderHandle<'_>;",
        "fn prepare_state(",
        "fn begin_cost(",
        "fn resume_cost(",
        "fn cancel_cost(",
        "pub const fn complete(self)",
        "pub const fn fail(self, kind: PendingDestructionFailureKind)",
        "fn handle_drop_failure(&mut self, failure: PendingDestructionFailure);",
    ):
        require_once(effect, required, "pending provider effect")
    if effect.count("state: &mut Self::State") != 4:
        fail("pending provider state must remain borrowed across four effects")
    if effect.count("permit: PendingWorkPermit") != 3:
        fail("pending effect methods must consume three lifecycle work permits")
    if "pub enum PendingBegin<State>" in effect:
        fail("pending begin may not return unguarded provider state")
    transition_code = effect.split("pub enum PendingStep", 1)[1].split(
        "/// Why pending", 1
    )[0]
    for forbidden in (
        "Complete(State)",
        "Active(State)",
        "Retry(State, PendingRetryReason)",
        "Backpressure(State, PendingBackpressure)",
        "state: Self::State",
    ):
        if forbidden in transition_code:
            fail(f"pending state escaped lifecycle ownership: {forbidden}")
    if re.search(
        r"#\[derive\([^]]*(?:Clone|Copy|Debug)[^]]*\)\]\s*pub struct PendingDestructionToken",
        effect,
    ):
        fail("pending destruction token gained duplication or formatting")

    outcome = sources[SOURCES[3]][1]
    for required in (
        "ProviderMismatch",
        "WorkExhausted",
        "InvalidWorkCharge",
    ):
        require_once(outcome, required, "pending failure outcome")

    lifecycle = sources[SOURCES[4]][1]
    for required in (
        "pub struct PendingOperation",
        "request: Option<PendingRequest<'provider, 'data>>",
        "request.is_bound_to(&effect.provider_handle())",
        "effect.begin_cost(&cost_request)",
        "effect.prepare_state(&prepare_request)",
        "let mut operation = Self",
        "request: Some(request)",
        "state: Some(state)",
        "self.effect.resume_cost(state, &cost_request)",
        "self.effect.cancel_cost(state, &cost_request)",
        "PendingWorkPermit::new(units)",
        "self.request_mut().charge_work(units)",
        "if !request.begin_attempt()",
        "if !self.begin_attempt()",
        "self.record_backpressure(reason)",
        "self.destroy(PendingDestructionCause::Completion)",
        "self.destroy(PendingDestructionCause::Cancellation)",
        "self.destroy(PendingDestructionCause::Drop)",
        "self.effect.handle_drop_failure(failure);",
        "let Some(state) = self.state.as_mut()",
        "PendingDestructionToken::new(",
    ):
        if lifecycle.count(required) < 1:
            fail(f"pending lifecycle transition drift: {required}")
    if lifecycle.count("request.is_bound_to(&effect.provider_handle())") != 2:
        fail("pending provider identity binding drift")
    if lifecycle.count("self.request_mut().charge_work(units)") != 2:
        fail("pending authoritative work charging drift")
    prepare = lifecycle.index("effect.prepare_state(&prepare_request)")
    guarded = lifecycle.index("let mut operation = Self")
    activation = lifecycle.index(".begin(state, effect_request")
    if not prepare < guarded < activation:
        fail("pending activation must follow lifecycle state ownership")
    if re.search(
        r"#\[derive\([^]]*(?:Clone|Copy|Debug)[^]]*\)\]\s*pub struct PendingOperation",
        lifecycle,
    ):
        fail("pending operation gained duplication or formatting")
    if "pub state:" in lifecycle or "pub effect:" in lifecycle:
        fail("pending operation exposed provider state")
    if ".resume(state, request, PendingWorkPermit::new(units))" not in lifecycle:
        fail("pending resume lost lifecycle-owned state")
    if ".cancel(state, request, PendingWorkPermit::new(units))" not in lifecycle:
        fail("pending cancellation lost lifecycle-owned state")

    provider_request = sources[SOURCES[5]][1]
    require_once(
        provider_request,
        "pub(crate) const fn charge_work(&mut self, units: u64)",
        "authoritative work meter",
    )
    if "pub const fn charge_work" in provider_request:
        fail("provider work meter became caller-controlled")


def validate_hashes(sources: dict[Path, tuple[str, str]]) -> None:
    for relative, (text, _code) in sources.items():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != EXPECTED_SHA256[relative]:
            fail(f"pending reviewed source hash drift: {relative}")


def validate(root: Path) -> None:
    sources = load_sources(root)
    validate_structure(sources)
    validate_hashes(sources)
