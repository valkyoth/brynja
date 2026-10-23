#!/usr/bin/env python3
"""Inspect actual portable legacy-HMAC caller ownership; not frame erasure."""
import argparse
from pathlib import Path
import legacy_hmac_engine_codegen as codegen
import legacy_hmac_engine_scratch as scratch
import legacy_hmac_engine_final as final
import legacy_hmac_engine_construct as construct
import legacy_hmac_timing_runner as runner

ROOT = runner.ROOT
FIXTURE = ROOT / "assurance/legacy-hmac-engine-cleanup/Cargo.toml"


def emit(directory, compiler, target, panic, fixture=FIXTURE):
    env = runner.environment(directory)
    env["CARGO_PROFILE_RELEASE_PANIC"] = panic
    runner.run(["cargo", "+" + compiler, "rustc", "--manifest-path", str(fixture),
                "--locked", "--offline", "--release", "--lib", "--target", target,
                "--", "--emit=mir,llvm-ir,asm"], env)
    artifacts = []
    for extension in ("mir", "ll", "s"):
        files = list((directory / "target" / target / "release/deps").glob("brynja_legacy_hmac_engine_cleanup-*." + extension))
        codegen.require(len(files) == 1, "ambiguous legacy caller artifacts")
        artifacts.append(files[0].read_text())
    return artifacts


def validate(llvm, panic):
    functions, definitions, aliases = codegen.emitted(llvm)
    for identity in codegen.IDENTITIES:
        codegen.lifecycle(functions[identity, "cancel"], identity, definitions, aliases, panic)
        codegen.lifecycle(functions[identity, "update_cancel"], identity, definitions, aliases, panic, updating=True)
        for operation in scratch.flow.SCRATCH:
            body = scratch.consumer(functions[identity, operation], identity, operation, definitions, aliases)
            scratch.check(body, operation)
            if operation != "construct":
                final.check(body, identity, definitions, aliases, panic)
            else:
                construct.check(body, identity, panic)


def collect(directory, compiler, target, panic):
    artifacts = emit(directory, compiler, target, panic)
    validate(artifacts[1], panic)
    print(f"Legacy HMAC caller dispatch: PASS; {compiler}; {target}; panic={panic}; "
          "two cancellations, two update/error/unwind consumers, fourteen scratch consumers, "
          "twelve finalizer and two constructor owner graphs; accelerated/hosted paths separate", flush=True)
    return artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", action="append")
    parser.add_argument("--target", default="x86_64-unknown-linux-gnu",
                        choices=("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "aarch64-apple-darwin"))
    args = parser.parse_args()
    for compiler in args.toolchain or ["1.90.0", "1.99.1"]:
        for panic in ("abort", "unwind"):
            with runner.cargo_environment.private_directory(ROOT) as raw:
                collect(Path(raw), compiler, args.target, panic)


if __name__ == "__main__":
    main()
