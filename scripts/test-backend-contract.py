#!/usr/bin/env python3
"""Broken-fixture tests for the CPU-backend contract source policy."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import backend_contract_policy


def copy_fixture(root: Path) -> None:
    target = root / backend_contract_policy.SOURCE_ROOT
    target.mkdir(parents=True)
    for relative in backend_contract_policy.SOURCES:
        shutil.copyfile(
            backend_contract_policy.SOURCE_ROOT / relative,
            target / relative,
        )


def replace(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"fixture marker missing: {old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def require_rejection(root: Path, message: str) -> None:
    try:
        backend_contract_policy.validate(root)
    except backend_contract_policy.BackendContractPolicyError as error:
        if message not in str(error):
            raise AssertionError(f"unexpected rejection: {error}") from error
    else:
        raise AssertionError("broken backend fixture was accepted")


def reset(root: Path) -> None:
    shutil.rmtree(root / backend_contract_policy.SOURCE_ROOT)
    copy_fixture(root)


def test() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        copy_fixture(root)
        source = root / backend_contract_policy.SOURCE_ROOT

        backend = source / "backend.rs"
        backend.write_text(
            backend.read_text(encoding="utf-8") + "\nunsafe fn probe() {}\n",
            encoding="utf-8",
        )
        require_rejection(root, "unsafe")
        reset(root)

        session = source / "backend_session.rs"
        session.write_text(
            session.read_text(encoding="utf-8") + "\nuse core::sync::atomic::AtomicUsize;\n",
            encoding="utf-8",
        )
        require_rejection(root, "Atomic")
        reset(root)

        backend = source / "backend.rs"
        replace(backend, "PhantomData<*mut ()>", "PhantomData<()>")
        require_rejection(root, "thread-bound")
        reset(root)

        backend = source / "backend.rs"
        replace(backend, "pub(crate) const fn for_test", "pub const fn for_test")
        require_rejection(root, "public constructor")
        reset(root)

        backend = source / "backend.rs"
        replace(
            backend,
            "from_evidence(evidence: BackendFeatureEvidence)",
            "from_evidence(evidence: BackendProfile)",
        )
        require_rejection(root, "opaque feature evidence")
        reset(root)

        session = source / "backend_session.rs"
        replace(
            session,
            "pass.testing_generation != record.generation",
            "false",
        )
        require_rejection(root, "KAT pass")
        reset(root)

        session = source / "backend_session.rs"
        replace(
            session,
            "failure.testing_generation != record.generation",
            "false",
        )
        require_rejection(root, "KAT failure")
        reset(root)

        session = source / "backend_session.rs"
        replace(
            session,
            "if matches!(record.state, BackendHealthState::Quarantined)",
            "if false",
        )
        require_rejection(root, "permanent quarantine")
        reset(root)

        dispatch = source / "backend_dispatch.rs"
        replace(
            dispatch,
            "snapshot.runtime_generation() != current_runtime",
            "false",
        )
        require_rejection(root, "runtime_generation")
        reset(root)

        dispatch = source / "backend_dispatch.rs"
        replace(
            dispatch,
            "session.profile().operations().contains(operation)",
            "true",
        )
        require_rejection(root, "operations().contains")
        reset(root)

        dispatch = source / "backend_dispatch.rs"
        dispatch.write_text(
            dispatch.read_text(encoding="utf-8") + "\nstruct BackendRegistry;\n",
            encoding="utf-8",
        )
        require_rejection(root, "BackendRegistry")
        reset(root)

        dispatch = source / "backend_dispatch.rs"
        replace(
            dispatch,
            "BackendServiceApproval::Approved",
            "BackendServiceApproval::Unavailable",
        )
        require_rejection(root, "BackendServiceApproval::Approved")
        reset(root)

        backend = source / "backend.rs"
        backend.write_text(
            backend.read_text(encoding="utf-8") + "\n// unreviewed drift\n",
            encoding="utf-8",
        )
        require_rejection(root, "source hash drift")


if __name__ == "__main__":
    test()
    print(
        "backend policy rejects thirteen execution, evidence, thread, generation, "
        "quarantine, operation, approval, registry, and hash regressions"
    )
