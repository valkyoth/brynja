#!/usr/bin/env python3
"""Adversarial source-policy tests for hardened SHA-2."""

import shutil
import tempfile
import subprocess
from pathlib import Path

import sha2_hardened as policy


def compiled_length_regressions():
    """Each test must fail at runtime when its local check/cleanup is removed."""
    with tempfile.TemporaryDirectory(prefix="brynja-sha2-length-") as directory:
        root = Path(directory)
        shutil.copytree(policy.ROOT / "crates/brynja-hash-sha2/src", root / "src")
        dependencies = "\n".join(
            f'{name} = {{ path = "{(policy.ROOT / "crates" / name).as_posix()}" }}'
            for name in ("brynja-core", "brynja-hash-core"))
        (root / "Cargo.toml").write_text(
            '[workspace]\n[package]\nname="brynja-hash-sha2"\nversion="0.0.0"\nedition="2024"\n'
            '[features]\ndefault=[]\ncpu=[]\ngeneral-sha512-t=[]\n[dependencies]\n' + dependencies + '\n', encoding="utf-8")
        target = root / "src/hardened/mod.rs"
        original = target.read_text()
        marker = ".checked_mul(8)"
        sites = [i for i in range(len(original)) if original.startswith(marker, i)]
        if len(sites) != 4:
            raise AssertionError("expected four byte finalization sites")
        mutants = [original[:i] + ".wrapping_mul(8).checked_add(0)" + original[i + len(marker):] for i in sites]
        # Removing only destination cleanup must also be caught (32/64 paths).
        before = '''return Err(clear_failed_secret_output(
                            destination,
                            HardenedSha2Error::MessageTooLong,
                        ));'''
        for block in original.split("None => {")[1:]:
            if not block.lstrip().startswith(before):
                continue
            index = original.index(block)
            changed = block.replace(before, "return Err(HardenedSha2Error::MessageTooLong);", 1)
            mutants.append(original[:index] + changed + original[index + len(block):])
        if len(mutants) != 6:
            raise AssertionError("expected four arithmetic and two cleanup mutants")
        try:
            for mode in ([], ["--release"]):
                command = ["cargo", "test", "--offline", *mode, "--lib", "hardened::tests::checked_length_"]
                target.write_text(original, encoding="utf-8")
                positive = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=180)
                if positive.returncode != 0 or "6 passed" not in positive.stdout:
                    raise AssertionError(f"length positive control failed: {positive.stderr}")
                for mutated in mutants:
                    target.write_text(mutated, encoding="utf-8")
                    result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=180)
                    if result.returncode == 0 or "test result: FAILED" not in result.stdout:
                        raise AssertionError(f"length mutant was not detected by real assertions: {result.stderr}")
        finally:
            target.write_text(original, encoding="utf-8")
    print("named SHA-2 finalizers reject twelve compiled arithmetic/cleanup mutations")


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
    reject(policy.API, ".checked_mul(8)", ".wrapping_mul(8).into()")
    reject(policy.LENGTH_TEST, "checked_length_sha384", "missing_sha384_case")
    reject(policy.API, "mod tests;", "mod missing_tests;")
    reject(policy.MIRI, "--lib hardened::tests::checked_length_", "--lib missing_test")
    compiled_length_regressions()
    print("hardened SHA-2 policy rejects twelve cleanup, capability, API, arithmetic, test-coverage and codegen regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
