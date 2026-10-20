#!/usr/bin/env python3
"""Compile actual HMAC scratch probes; no full HMAC cleanup claim."""
import argparse
from pathlib import Path

import hmac_cleanup_codegen as codegen
import hmac_verifiers as verifier

ROOT = verifier.ROOT
FIXTURE = ROOT / "assurance/hmac-cleanup/Cargo.toml"


def emit(directory, toolchain, target, panic, fixture=FIXTURE):
    env = verifier.environment(directory)
    env["CARGO_PROFILE_RELEASE_PANIC"] = panic
    verifier.run(["cargo", "+" + toolchain, "rustc", "--manifest-path", str(fixture),
                  "--locked", "--offline", "--release", "--lib", "--target", target,
                  "--", "--emit=mir,llvm-ir,asm"], env)
    artifacts = []
    for extension in ("mir", "ll", "s"):
        files = list((directory / "target" / target / "release/deps").glob(
            "brynja_hmac_cleanup-*." + extension))
        codegen.require(len(files) == 1, "ambiguous compiler artifacts")
        artifacts.append(files[0].read_text())
    return artifacts


def collect(directory, toolchain, target, panic):
    artifacts = emit(directory, toolchain, target, panic)
    codegen.check(*artifacts, panic)
    print(f"HMAC scratch cleanup: PASS; {toolchain}; {target}; panic={panic}; "
          "5 probes; not whole-composition qualification", flush=True)
    return artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", action="append")
    parser.add_argument("--target", default="x86_64-unknown-linux-gnu",
                        choices=("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"))
    args = parser.parse_args()
    for compiler in args.toolchain or ["1.90.0", "1.99.1"]:
        for panic in ("abort", "unwind"):
            with verifier.cargo_environment.private_directory(ROOT) as path:
                collect(Path(path), compiler, args.target, panic)


if __name__ == "__main__":
    main()
