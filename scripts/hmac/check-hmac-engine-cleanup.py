#!/usr/bin/env python3
"""Emit 72 real HMAC consumers; qualify only their 12 cancellation dispatches."""
import argparse
from pathlib import Path

import hmac_engine_codegen as codegen
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


def collect(directory, compiler, target, panic):
    artifacts = emit(directory, compiler, target, panic)
    codegen.check(artifacts[1])
    print(f"HMAC engine cancellation dispatch: PASS; {compiler}; {target}; panic={panic}; "
          "12 identities; other 60 consumers emitted, NOT qualified", flush=True)
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
