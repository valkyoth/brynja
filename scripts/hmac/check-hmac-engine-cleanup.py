#!/usr/bin/env python3
"""Check cancellation and local scratch clear dispatch, not full HMAC erasure."""
import argparse
from pathlib import Path

import hmac_engine_codegen as codegen
import hmac_engine_scratch as scratch
import hmac_verifiers as verifier

ROOT = verifier.ROOT
FIXTURE = ROOT / "assurance/hmac-engine-cleanup/Cargo.toml"


def emit(directory, compiler, target, panic, fixture=FIXTURE):
    env = verifier.environment(directory)
    env["CARGO_PROFILE_RELEASE_PANIC"] = panic
    verifier.run(["cargo", "+" + compiler, "rustc", "--manifest-path", str(fixture),
                  "--locked", "--offline", "--release", "--lib", "--target", target,
                  "--", "--emit=mir,llvm-ir,asm"], env)
    outputs = []
    for extension in ("mir", "ll", "s"):
        files = list((directory / "target" / target / "release/deps").glob(
            "brynja_hmac_engine_cleanup-*." + extension))
        codegen.require(len(files) == 1, "ambiguous engine artifact population")
        outputs.append(files[0].read_text())
    return outputs


def validate(llvm):
    functions = codegen.check(llvm)
    for identity in codegen.IDENTITIES:
        for operation in scratch.SCRATCH:
            scratch.check(functions[identity, operation], operation)


def collect(directory, compiler, target, panic):
    artifacts = emit(directory, compiler, target, panic)
    validate(artifacts[1])
    print(f"HMAC caller cleanup dispatch: PASS; {compiler}; {target}; panic={panic}; "
          "12 cancellations, 48 scratch consumers; full owner/frame qualification pending", flush=True)
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
