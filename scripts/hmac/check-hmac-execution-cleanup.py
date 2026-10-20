#!/usr/bin/env python3
"""Inspect accelerated cancellation/update owners; not whole-frame erasure."""
import argparse
from pathlib import Path
import re

import hmac_engine_codegen as common
import hmac_execution_drop as cleanup
import hmac_execution_update as update
import hmac_verifiers as verifier

ROOT = verifier.ROOT
FIXTURE = ROOT / "assurance/hmac-execution-cleanup/Cargo.toml"


def emit(directory, compiler, target, panic, fixture=FIXTURE):
    env = verifier.environment(directory)
    env["CARGO_PROFILE_RELEASE_PANIC"] = panic
    verifier.run(["cargo", "+" + compiler, "rustc", "--manifest-path", str(fixture),
                  "--locked", "--offline", "--release", "--lib", "--target", target,
                  "--", "--emit=mir,llvm-ir,asm"], env)
    result = []
    for suffix in ("mir", "ll", "s"):
        files = list((directory / "target" / target / "release/deps").glob(
            "brynja_hmac_execution_cleanup-*." + suffix))
        common.require(len(files) == 1, "ambiguous accelerated compiler artifacts")
        result.append(files[0].read_text())
    return result


def emitted(llvm):
    definitions, aliases = common.definitions_and_aliases(llvm)
    functions = {}
    for identity in common.IDENTITIES:
        for operation in ("cancel", "update_cancel"):
            suffix = ("29brynja_hmac_execution_cleanup" + str(len(identity)) + identity
                      + str(len(operation)) + operation)
            names = [name for name in (*definitions, *aliases)
                     if re.search(suffix + r"(?:17h\w+E)?$", name)]
            common.require(len(names) == 1, "missing/ambiguous accelerated consumer")
            functions[identity, operation] = common.resolve(names[0], definitions, aliases)[1]
    return functions, definitions, aliases


def validate(llvm, compiler="1.99.1", panic="unwind"):
    common.require(compiler in ("1.90.0", "1.99.1") and panic in ("abort", "unwind"),
                   "unreviewed accelerated compiler/panic profile")
    functions, definitions, aliases = emitted(llvm)
    for identity in common.IDENTITIES:
        cleanup.cancellation(functions[identity, "cancel"], identity, definitions, aliases, compiler, panic)
        update.check(functions[identity, "update_cancel"], identity, definitions, aliases,
                     compiler, panic)


def collect(directory, compiler, target, panic):
    artifacts = emit(directory, compiler, target, panic)
    validate(artifacts[1], compiler, panic)
    print(f"HMAC accelerated owner dispatch: PASS; {compiler}; {target}; "
          f"panic={panic}; 12 cancellation and 12 update/error/unwind consumers, "
          "static/runtime and retained/empty; "
          "actual hash-core and CPU-scratch helper graphs; not whole-frame erasure", flush=True)
    return artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", action="append")
    parser.add_argument("--target", default="x86_64-unknown-linux-gnu",
                        choices=("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
                                 "aarch64-apple-darwin"))
    args = parser.parse_args()
    for compiler in args.toolchain or ["1.90.0", "1.99.1"]:
        for panic in ("abort", "unwind"):
            with verifier.cargo_environment.private_directory(ROOT) as directory:
                collect(Path(directory), compiler, args.target, panic)


if __name__ == "__main__":
    main()
