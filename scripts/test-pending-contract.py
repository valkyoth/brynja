#!/usr/bin/env python3
"""Exercise fail-closed v0.16.0 pending-lifecycle fixtures."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pending_contract_policy


ROOT = Path(__file__).resolve().parents[1]


def copy_fixture(root: Path) -> None:
    for relative in pending_contract_policy.SOURCES:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


def replace(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"fixture source missing {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def reject(root: Path, expected: str) -> None:
    try:
        pending_contract_policy.validate(root)
    except pending_contract_policy.PendingContractPolicyError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"pending fixture accepted {expected}")


def test() -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-pending-") as temporary:
        root = Path(temporary)
        copy_fixture(root)
        pending_contract_policy.validate(root)

        request = root / pending_contract_policy.SOURCES[1]
        replace(request, "ProviderOperation::PendingCancel,", "ProviderOperation::PendingPoll,")
        reject(root, "pending request admission drift")
        copy_fixture(root)

        request = root / pending_contract_policy.SOURCES[1]
        replace(
            request,
            "PendingResource::ExternalKey => Some(DestructionTarget::ExternalStore)",
            "PendingResource::ExternalKey => None",
        )
        reject(root, "pending request admission drift")
        copy_fixture(root)

        request = root / pending_contract_policy.SOURCES[1]
        replace(request, "next > self.limits.effect_attempts()", "false")
        reject(root, "pending request admission drift")
        copy_fixture(root)

        effect = root / pending_contract_policy.SOURCES[2]
        replace(effect, "pub const fn complete(self)", "pub const fn complete(&self)")
        reject(root, "pending provider effect drift")
        copy_fixture(root)

        effect = root / pending_contract_policy.SOURCES[2]
        replace(
            effect,
            "pub struct PendingDestructionToken {",
            "#[derive(Clone)]\npub struct PendingDestructionToken {",
        )
        reject(root, "destruction token gained duplication")
        copy_fixture(root)

        lifecycle = root / pending_contract_policy.SOURCES[4]
        replace(
            lifecycle,
            "self.destroy(PendingDestructionCause::Drop)",
            "Ok(())",
        )
        reject(root, "pending lifecycle transition drift")
        copy_fixture(root)

        lifecycle = root / pending_contract_policy.SOURCES[4]
        replace(
            lifecycle,
            "self.effect.handle_drop_failure(failure);",
            "let _ = failure;",
        )
        reject(root, "pending lifecycle transition drift")
        copy_fixture(root)

        lifecycle = root / pending_contract_policy.SOURCES[4]
        replace(
            lifecycle,
            "pub struct PendingOperation",
            "#[derive(Clone)]\npub struct PendingOperation",
        )
        reject(root, "pending operation gained duplication")
        copy_fixture(root)

        request = root / pending_contract_policy.SOURCES[1]
        request.write_text(request.read_text(encoding="utf-8") + "\nfn native() { unsafe {} }\n", encoding="utf-8")
        reject(root, "forbidden boundary")
        copy_fixture(root)

        lifecycle = root / pending_contract_policy.SOURCES[4]
        lifecycle.write_text(lifecycle.read_text(encoding="utf-8") + "\n" * 100, encoding="utf-8")
        reject(root, "exceeds 500 lines")
        copy_fixture(root)

        lifecycle = root / pending_contract_policy.SOURCES[4]
        replace(
            lifecycle,
            "request.is_bound_to(&effect.provider_handle())",
            "true",
        )
        reject(root, "provider identity binding drift")
        copy_fixture(root)

        effect = root / pending_contract_policy.SOURCES[2]
        replace(effect, "state: &mut Self::State", "state: Self::State")
        reject(root, "state must remain borrowed")
        copy_fixture(root)

        effect = root / pending_contract_policy.SOURCES[2]
        replace(effect, "fn resume_cost(", "fn omitted_resume_cost(")
        reject(root, "pending provider effect drift")
        copy_fixture(root)

        lifecycle = root / pending_contract_policy.SOURCES[4]
        replace(
            lifecycle,
            "self.request_mut().charge_work(units)",
            "Ok::<(), ()>(())",
        )
        reject(root, "authoritative work charging drift")
        copy_fixture(root)

        provider_request = root / pending_contract_policy.SOURCES[5]
        replace(
            provider_request,
            "pub(crate) const fn charge_work",
            "pub const fn charge_work",
        )
        reject(root, "authoritative work meter drift")
        copy_fixture(root)

        effect = root / pending_contract_policy.SOURCES[2]
        replace(effect, "fn prepare_state(", "fn omitted_prepare_state(")
        reject(root, "pending provider effect drift")
        copy_fixture(root)

        effect = root / pending_contract_policy.SOURCES[2]
        replace(effect, "pub enum PendingBeginStep", "pub enum PendingBegin<State>")
        reject(root, "pending provider effect drift")
        copy_fixture(root)

        lifecycle = root / pending_contract_policy.SOURCES[4]
        replace(lifecycle, "state: Some(state)", "state: None")
        reject(root, "pending lifecycle transition drift")
        copy_fixture(root)

        lifecycle = root / pending_contract_policy.SOURCES[4]
        replace(lifecycle, "let mut operation = Self", "let mut operation = fake")
        reject(root, "pending lifecycle transition drift")
        copy_fixture(root)

        lifecycle = root / pending_contract_policy.SOURCES[4]
        replace(
            lifecycle,
            "if !operation.identity_matches()",
            "if false",
        )
        reject(root, "identity must be rechecked after guarded preparation")
        copy_fixture(root)

        module = root / pending_contract_policy.SOURCES[0]
        module.write_text(module.read_text(encoding="utf-8") + "\n// review drift\n", encoding="utf-8")
        reject(root, "reviewed source hash drift")


if __name__ == "__main__":
    test()
    print("pending policy rejects twenty-one admission, identity, work, begin/unwind, cleanup, low-level, size, and hash regressions")
