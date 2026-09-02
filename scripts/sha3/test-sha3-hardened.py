#!/usr/bin/env python3
"""Adversarial source-policy tests for hardened FIPS 202."""

import shutil
import tempfile
from pathlib import Path

import sha3_hardened as policy


def reject(relative: Path, old: str, new: str) -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-hardened-sha3-") as directory:
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
        raise AssertionError(f"hardened FIPS 202 policy accepted mutation: {relative}")


def main() -> int:
    policy.validate()
    reject(policy.OWNER, "clear_owned_region(&mut self.sponge_lanes)", "self.sponge_lanes.fill(0)")
    reject(policy.API, "pub trait HardenedFips202State: sealed::Registered", "pub trait HardenedFips202State")
    reject(policy.FIXED, "pub fn finalize_secret<'output>(", "fn missing_secret_output(")
    reject(policy.XOF, "pub fn squeeze_secret<'output>(", "fn missing_secret_squeeze(")
    reject(policy.PERMUTATION, "use super::owner::HardenedFips202Owner;", "unsafe fn injected() {}")
    reject(policy.TEST, "recoverable_unwind_clears_typed_secret_destination", "missing_unwind_test")
    reject(policy.TEST, "fixed_output_failure_is_atomic_by_classification", "missing_failure_test")
    reject(policy.CHECKS, "scripts/sha3/check-sha3-hardened-codegen.sh", "true # removed codegen")
    print("hardened FIPS 202 policy rejects eight cleanup, capability, API, unsafe, failure, unwind, and codegen regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
