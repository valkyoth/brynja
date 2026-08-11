#!/usr/bin/env python3
"""Validate the narrow v0.13.1 CPU-backend contract boundary."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


SOURCE_ROOT = Path("crates/brynja-core/src")
SOURCES = (
    Path("backend.rs"),
    Path("backend_session.rs"),
    Path("backend_dispatch.rs"),
    Path("backend_session_tests.rs"),
)
EXPECTED_SHA256 = {
    Path("backend.rs"): "9386988bfd5b32ec39f72dc343e8631dddc582f0417ef66689e84ffdf87f0766",
    Path("backend_session.rs"): "d4c774ae8aaa7b0ec8581687f62c2b7d7aa5e5650ff430c28a10560c1c4f47ce",
    Path("backend_dispatch.rs"): "e1db25d28aefc43792d4757f0bbb97bf52adbd26057982b55e21f6728cde86cb",
    Path("backend_session_tests.rs"): "a4355bb8e02d4d867b5c1b96fd22b18783627b7285fba249baccae13ad1f0eec",
}
IDENTITIES = (
    "Scalar",
    "X86Sha",
    "X86AesGcm",
    "X86Avx2",
    "X86Avx512",
    "Aarch64Sha2",
    "Aarch64AesGcm",
    "RiscVVector",
    "RiscVScalarCrypto",
    "ValidatedModule",
)
FEATURES = (
    "X86Sha",
    "X86Aes",
    "X86Pclmulqdq",
    "X86Avx2",
    "X86Avx512F",
    "Aarch64Neon",
    "Aarch64Sha2",
    "Aarch64Aes",
    "Aarch64Pmull",
    "RiscVVector",
    "RiscVScalarCrypto",
)
POLICIES = (
    "ScalarOnly",
    "Opportunistic",
    "RequiredAccelerated",
    "ValidatedModuleOnly",
)


class BackendContractPolicyError(RuntimeError):
    """The reviewed backend-contract source boundary drifted."""


def fail(message: str) -> None:
    raise BackendContractPolicyError(message)


def load_sources(root: Path) -> dict[Path, str]:
    directory = root / SOURCE_ROOT
    loaded: dict[Path, str] = {}
    for relative in SOURCES:
        path = directory / relative
        if not path.is_file() or path.is_symlink():
            fail(f"backend source must be a regular file: {relative}")
        text = path.read_text(encoding="utf-8")
        if len(text.splitlines()) > 500:
            fail(f"backend source exceeds 500 lines: {relative}")
        loaded[relative] = text
    return loaded


def enum_variants(source: str, name: str) -> tuple[str, ...]:
    match = re.search(rf"pub enum {name} \{{(?P<body>.*?)\n\}}", source, re.DOTALL)
    if match is None:
        fail(f"backend enum missing: {name}")
    return tuple(
        re.findall(r"^    ([A-Z][A-Za-z0-9]+)(?:\([^\n]+\))?,$", match["body"], re.MULTILINE)
    )


def validate_inventory(backend: str) -> None:
    if enum_variants(backend, "BackendIdentity") != IDENTITIES:
        fail("sealed backend identity inventory drift")
    if enum_variants(backend, "BackendFeature") != FEATURES:
        fail("exact backend feature inventory drift")
    if enum_variants(backend, "BackendPolicy") != POLICIES:
        fail("backend policy inventory drift")
    masks = tuple(
        int(value.replace("_", ""))
        for value in re.findall(r"Self::[A-Za-z0-9]+ => ([0-9_]+),", backend)
        if int(value.replace("_", "")) != 0
    )
    if masks != tuple(1 << index for index in range(len(FEATURES))):
        fail("backend feature masks are not unique powers of two")
    if "if features.bits != identity.required_features().bits" not in backend:
        fail("exact feature-bundle binding drift")


def validate_structure(sources: dict[Path, str]) -> None:
    backend = sources[Path("backend.rs")]
    session = sources[Path("backend_session.rs")]
    dispatch = sources[Path("backend_dispatch.rs")]
    tests = sources[Path("backend_session_tests.rs")]
    combined = "\n".join((backend, session, dispatch))
    combined = combined.replace("std::thread::spawn", "compile_fail_thread_spawn")
    for forbidden in (
        "std::",
        "alloc::",
        "unsafe ",
        "Atomic",
        "target_arch",
        "target_feature",
        "core::arch",
        "asm!",
        "extern \"",
        "BackendRegistry",
        "fallback_provider",
    ):
        if forbidden in combined:
            fail(f"backend contract contains forbidden execution dependency: {forbidden}")

    validate_inventory(backend)
    if combined.count("PhantomData<*mut ()>") != 6:
        fail("thread-bound backend token marker drift")
    for token in (
        "BackendCandidate",
        "BackendFeatureEvidence",
        "BackendKatPass",
        "BackendKatFailure",
        "BackendInitialization",
        "ActiveBackend",
        "BackendDispatch",
    ):
        if re.search(
            rf"#\[derive\([^]]*(?:Clone|Copy|Debug)[^]]*\)\]\s*pub struct {token}",
            combined,
        ):
            fail(f"backend authority token gained duplication or formatting: {token}")

    if "pub const fn from_evidence(evidence: BackendFeatureEvidence)" not in backend:
        fail("candidate activation no longer requires opaque feature evidence")
    for evidence in ("BackendFeatureEvidence", "BackendKatPass", "BackendKatFailure"):
        block = re.search(rf"impl {evidence} \{{(?P<body>.*?)\n\}}", combined, re.DOTALL)
        if block is None:
            fail(f"opaque evidence implementation missing: {evidence}")
        if re.search(r"pub\s+(?:const\s+)?fn\s+(?:new|for_test|from_)", block["body"]):
            fail(f"opaque evidence gained a public constructor: {evidence}")

    if "health: Cell<HealthRecord>" not in session:
        fail("caller-owned no-atomics health state drift")
    if "self.quarantine(BackendFault::ReentrantInitialization)" not in session:
        fail("recursive initialization no longer quarantines")
    if "BackendFault::InitializationInterrupted" not in session:
        fail("dropped KAT guard no longer quarantines")
    if session.count("if matches!(record.state, BackendHealthState::Quarantined)") != 2:
        fail("permanent quarantine guard drift")
    if session.count("record.generation.checked_add(1)") < 3:
        fail("monotonic backend health generation drift")
    if "failure.testing_generation != record.generation" not in session:
        fail("opaque KAT failure lost exact generation binding")
    if "pass.testing_generation != record.generation" not in session:
        fail("opaque KAT pass lost exact generation binding")

    for required in (
        "BackendPolicy::ScalarOnly =>",
        "BackendPolicy::Opportunistic =>",
        "BackendPolicy::RequiredAccelerated =>",
        "BackendPolicy::ValidatedModuleOnly =>",
        "snapshot.generation() != health_generation",
        "snapshot.runtime_generation() != current_runtime",
        "session.profile().operations().contains(operation)",
        "BackendServiceApproval::Approved",
    ):
        if required not in dispatch:
            fail(f"backend dispatch invariant drift: {required}")
    if dispatch.count("BackendSelectionReason::ScalarFallback") != 1:
        fail("scalar fallback is not confined to explicit opportunistic selection")
    if ".or_else(" in dispatch or "select_backend(" in dispatch.split("fn authorize_scalar", 1)[1]:
        fail("scalar fallback can recurse into backend selection")

    test_names = tuple(
        re.findall(r"^#\[test\]\nfn ([a-z0-9_]+)\(\)", tests, re.MULTILINE)
    )
    if len(test_names) != 9:
        fail("backend behavior test inventory drift")
    for required_test in (
        "recursion_quarantines_and_cannot_be_completed_by_outer_guard",
        "mismatched_evidence_and_approval_fail_closed",
        "quarantine_and_runtime_changes_invalidate_existing_authority",
        "policies_are_exact_and_only_opportunistic_mode_falls_back",
    ):
        if required_test not in test_names:
            fail(f"backend behavior coverage missing: {required_test}")


def validate_hashes(sources: dict[Path, str]) -> None:
    for relative, text in sources.items():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != EXPECTED_SHA256[relative]:
            fail(f"backend reviewed source hash drift: {relative}")


def validate(root: Path) -> None:
    sources = load_sources(root)
    validate_structure(sources)
    validate_hashes(sources)
