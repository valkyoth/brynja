#!/usr/bin/env python3
"""Check portable caller scratch/owner dispatch, not whole-frame erasure."""
import argparse
from pathlib import Path

import hmac_engine_codegen as codegen
import hmac_engine_final as final
import hmac_engine_scratch as scratch
import hmac_engine_update as update
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


def validate(llvm, panic="unwind"):
    functions = codegen.check(llvm)
    definitions, aliases = codegen.definitions_and_aliases(llvm)
    for identity in codegen.IDENTITIES:
        update.check(functions[identity, "update_cancel"], identity, definitions, aliases, panic)
        for operation in scratch.SCRATCH:
            body = scratch.consumer(functions[identity, operation], operation, definitions, aliases)
            scratch.check(body, operation)
            if operation in final.OPERATIONS:
                final.check(body, identity, definitions, aliases, panic)


def collect(directory, compiler, target, panic):
    artifacts = emit(directory, compiler, target, panic)
    validate(artifacts[1], panic)
    print(f"HMAC caller cleanup dispatch: PASS; {compiler}; {target}; panic={panic}; "
          "12 cancellations, 12 update/error consumers, 84 byte/bit scratch consumers, "
          "72 consuming-finalizer owner graphs; "
          "constructor/accelerated/hosted qualification pending; no whole-frame erasure claim",
          flush=True)
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
