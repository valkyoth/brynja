#!/usr/bin/env python3
"""Validate the reviewed v0.17.0 FIPS-aware provider architecture."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


SOURCES = (
    Path("crates/brynja-core/src/fips.rs"),
    Path("crates/brynja-core/src/fips_build.rs"),
    Path("crates/brynja-core/src/fips_service.rs"),
    Path("crates/brynja-core/src/fips_session.rs"),
)
EXPECTED_SHA256 = {
    SOURCES[0]: "373da59ccd03bbc928f21061c2eba9b2a6c7947c3a3ffc213e9c61554ac01a88",
    SOURCES[1]: "e5816bf17e8346c9e79c698b7865c629adeccaec284f6f5c11b10b06d7254ce9",
    SOURCES[2]: "11c1011eb321ac52c391742d14254d114cbdb7832e2a263596806d1eb25d5a7f",
    SOURCES[3]: "3ba9d21fe6db400fb059f16cda9cc40a285b94f9569dada7b0f10aeb5bcc4890",
}


class FipsArchitecturePolicyError(RuntimeError):
    """The reviewed FIPS-aware boundary differs from policy."""


def fail(message: str) -> None:
    raise FipsArchitecturePolicyError(message)


def code_without_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def load_sources(root: Path) -> dict[Path, tuple[str, str]]:
    loaded = {}
    for relative in SOURCES:
        source = root / relative
        if not source.is_file() or source.is_symlink():
            fail(f"FIPS architecture source must be a regular file: {relative}")
        text = source.read_text(encoding="utf-8")
        if len(text.splitlines()) > 500:
            fail(f"FIPS architecture source exceeds 500 lines: {relative}")
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
        "BackendPolicy",
        "BackendDispatch",
        "brynja_crypto_cpu_std",
        "target_feature",
        "is_x86_feature_detected",
        "Atomic",
        "static mut",
        "thread_local",
    ):
        if forbidden in all_code:
            fail(f"FIPS architecture crossed forbidden boundary: {forbidden}")

    architecture = sources[SOURCES[0]][1]
    for required in (
        "pub enum FipsServiceDisposition",
        "Approved,",
        "NonApproved,",
        "pub enum FipsBackendOwner",
        "ModuleScalar,",
        "ModuleAccelerated,",
        "BackendIdentity::ValidatedModule",
        "FipsEnvironmentError::SealedProviderExcluded",
        "features != backend.required_features()",
        "pub enum FipsSspFlow",
        "destruction_targets.is_empty()",
        "pub struct FipsModuleConfig",
        "approved: FipsServiceSet",
        "non_approved: FipsServiceSet",
        "for operation in ProviderOperation::ALL",
        "ServiceOverlap(operation)",
        "ServiceUnclassified(operation)",
        "ServiceUnsupported(operation)",
        "self_tests: FipsSelfTestPlan::mandatory()",
        "pub const fn require_conditional_self_tests",
        "self.self_tests = self.self_tests.require(FipsSelfTest::Conditional)",
    ):
        if required not in architecture:
            fail(f"FIPS configuration boundary drift: {required}")
    if re.search(r"pub\s+(?:approved|non_approved|provider|build|environment|ssp):", architecture):
        fail("FIPS configuration exposed mutable construction fields")

    build = sources[SOURCES[1]][1]
    for required in (
        "pub struct FipsBuildExpectations",
        "source: [u8; 32]",
        "toolchain: [u8; 32]",
        "flags: [u8; 32]",
        "dependencies: [u8; 32]",
        ".contains(&[0; 32])",
    ):
        if required not in build:
            fail(f"FIPS deterministic-build boundary drift: {required}")

    service = sources[SOURCES[2]][1]
    for required in (
        "pub struct FipsServiceSetBuilder",
        "Err(FipsServiceSetError::Duplicate(operation))",
        "pub const fn freeze(self) -> FipsServiceSet",
        "pub const fn empty() -> Self",
        "pub const fn contains(self, operation: ProviderOperation) -> bool",
    ):
        require_once(service, required, "FIPS service-set boundary")
    if "Err(FipsServiceSetError::Empty" in service:
        fail("FIPS service classification may not reject an intentionally empty side")

    session = sources[SOURCES[3]][1]
    for required in (
        "pub enum FipsModuleState",
        "Uninitialized,",
        "SelfTesting,",
        "Operational,",
        "Failed,",
        "pub trait FipsSelfTestRunner",
        "fn run(&mut self, plan: FipsSelfTestPlan) -> FipsSelfTestResult;",
        "pub fn run_self_tests",
        "let guard = self.begin_self_tests()?;",
        "let result = runner.run(guard.plan());",
        "guard.complete(result)",
        "self.fail_permanently(FipsModuleFault::ReentrantSelfTest)",
        ".fail_permanently(FipsModuleFault::SelfTestFailed)",
        "self.fail_permanently(FipsModuleFault::CatastrophicFailure)",
        ".fail_permanently(FipsModuleFault::SelfTestInterrupted)",
        "pub struct FipsServiceAuthorization",
        "generation: record.generation",
        "snapshot.generation() == self.generation",
        "PhantomData<*mut ()>",
    ):
        if required not in session:
            fail(f"FIPS permanent-failure boundary drift: {required}")
    for forbidden in (
        "pub fn begin_self_tests",
        "pub struct FipsSelfTestGuard",
        "pub const fn provider_handle",
        "impl Clone for FipsServiceAuthorization",
        "impl Copy for FipsServiceAuthorization",
    ):
        if forbidden in session:
            fail(f"FIPS authorization boundary became forgeable: {forbidden}")
    if re.search(
        r"#\[derive\([^]]*(?:Clone|Copy|Debug)[^]]*\)\]\s*pub struct FipsServiceAuthorization",
        session,
    ):
        fail("FIPS service authorization gained duplication or formatting")


def validate_hashes(sources: dict[Path, tuple[str, str]]) -> None:
    for relative, (text, _code) in sources.items():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != EXPECTED_SHA256[relative]:
            fail(f"FIPS reviewed source hash drift: {relative}")


def validate(root: Path) -> None:
    sources = load_sources(root)
    validate_structure(sources)
    validate_hashes(sources)
