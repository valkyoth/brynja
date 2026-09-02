#!/usr/bin/env python3
"""Adversarial source-policy tests for hardened SHA-2."""

import shutil
import tempfile
from pathlib import Path

import sha2_hardened as policy


def reject(relative: Path, old: str, new: str) -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-hardened-sha2-") as directory:
        root = Path(directory)
        for source in policy.FILES:
            destination = root / source
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(policy.ROOT / source, destination)
        target = root / relative
        text = target.read_text(encoding="utf-8")
        if old not in text:
            raise AssertionError(f"mutation token absent: {old}")
        target.write_text(text.replace(old, new), encoding="utf-8")
        try:
            policy.validate(root)
        except policy.HardenedPolicyError:
            return
        raise AssertionError(f"hardened SHA-2 policy accepted mutation: {relative}")


def main() -> int:
    policy.validate()
    reject(policy.OWNER, "clear_owned_region(&mut self.chaining_state)", "self.chaining_state.fill(0)")
    reject(policy.API, "pub trait HardenedSha2State: sealed::Registered", "pub trait HardenedSha2State")
    reject(policy.API, "pub fn finalize_secret<'output>(", "fn missing_secret_output(")
    reject(policy.API, "mod compress32;", "unsafe fn injected() {}\nmod compress32;")
    reject(policy.API, "HardenedSha512_256", "MissingSha512_256")
    reject(policy.OUTPUT, "clear_failed_secret_output", "forgot_failed_secret_output")
    reject(policy.TEST, "recoverable_unwind_clears_typed_secret_destination", "missing_unwind_test")
    reject(policy.CHECKS, "scripts/sha2/check-sha2-hardened-codegen.sh", "true # removed codegen")
    print("hardened SHA-2 policy rejects eight cleanup, capability, API, unsafe, identity, failure, unwind, and codegen regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
