#!/usr/bin/env python3
"""Inspect accelerated cancellation/update owners and construction/final scratch."""
import argparse
from pathlib import Path
import re

import hmac_engine_codegen as common
import hmac_execution_drop as cleanup
import hmac_execution_update as update
import hmac_execution_scratch as scratch
import hmac_execution_final as final
import hmac_execution_wrapper as wrapper
import hmac_execution_admission as admission
import hmac_execution_construct as construct
import hmac_execution_profiles as profiles
import hmac_verifiers as verifier

ROOT = verifier.ROOT
FIXTURE = ROOT / "assurance/hmac-execution-cleanup/Cargo.toml"


def emit(directory, compiler, target, panic, fixture=FIXTURE, profile="runtime"):
    common.require(profile in ("runtime", "static"), "unknown compiler feature profile")
    profiles.validate(verifier, fixture, directory, compiler, target, profile)
    env = verifier.environment(directory)
    env["CARGO_PROFILE_RELEASE_PANIC"] = panic
    features = [] if profile == "runtime" else ["--no-default-features"]
    verifier.run(["cargo", "+" + compiler, "rustc", "--manifest-path", str(fixture),
                  "--locked", "--offline", "--release", "--lib", "--target", target,
                  *features, "--", "--emit=mir,llvm-ir,asm"], env)
    result = []
    for suffix in ("mir", "ll", "s"):
        files = list((directory / "target" / target / "release/deps").glob(
            "brynja_hmac_execution_cleanup-*." + suffix))
        common.require(len(files) == 1, "ambiguous accelerated compiler artifacts")
        result.append(files[0].read_text())
    return result


def emitted(llvm, operations=("cancel", "update_cancel")):
    definitions, aliases = common.definitions_and_aliases(llvm)
    functions = {}
    for identity in common.IDENTITIES:
        for operation in operations:
            suffix = ("29brynja_hmac_execution_cleanup" + str(len(identity)) + identity
                      + str(len(operation)) + operation)
            names = [name for name in (*definitions, *aliases)
                     if re.search(suffix + r"(?:17h\w+E)?$", name)]
            common.require(len(names) == 1, "missing/ambiguous accelerated consumer")
            functions[identity, operation] = common.resolve(names[0], definitions, aliases)[1]
    return functions, definitions, aliases


def validate_retained(llvm, compiler="1.99.1", panic="unwind", profile="runtime"):
    common.require(compiler in ("1.90.0", "1.99.1") and panic in ("abort", "unwind"),
                   "unreviewed accelerated compiler/panic profile")
    functions, definitions, aliases = emitted(llvm)
    for identity in common.IDENTITIES:
        cleanup.cancellation(functions[identity, "cancel"], identity, definitions, aliases,
                             compiler, panic, profile)
        update.check(functions[identity, "update_cancel"], identity, definitions, aliases,
                     compiler, panic, profile)


def validate(llvm, compiler="1.99.1", panic="unwind"):
    validate_retained(llvm, compiler, panic)
    functions, definitions, aliases = emitted(llvm, scratch.OPERATIONS)
    checked_finalizers = set()
    checked_admissions = set()
    for (identity, operation), body in functions.items():
        resolved = scratch.check(body, operation, definitions, aliases)
        if operation.startswith("construct_") and (identity, resolved) not in checked_admissions:
            for route in (0, 1):
                for long_key in (False, True):
                    construct.check(resolved, identity, definitions, aliases, compiler,
                                    panic, route, long_key, construct.iterator.array_types(llvm))
            checked_admissions.add((identity, resolved))
        if operation in final.syntax.OPERATIONS:
            for route, present in ((0, True), (1, True), (0, False)):
                wrapper.check(body, identity, operation, definitions, aliases,
                              compiler, route, present)
        key = identity, resolved
        if operation in final.syntax.OPERATIONS and key not in checked_finalizers:
            for route in (0, 1):
                final.check(resolved, identity, definitions, aliases, panic, route=route)
            # Byte/final-bit wrappers often call the same actual Engine body.
            # Reuse only within this artifact after both routes passed.
            checked_finalizers.add(key)


def collect(directory, compiler, target, panic):
    artifacts = emit(directory, compiler, target, panic)
    validate(artifacts[1], compiler, panic)
    print(f"HMAC accelerated owner dispatch: PASS; {compiler}; {target}; "
          f"panic={panic}; 12 cancellation and 12 update/error/unwind consumers, "
          "static/runtime and retained/empty; "
          "actual hash-core and CPU-scratch helper graphs; not whole-frame erasure", flush=True)
    print("Accelerated HMAC scratch dispatch: PASS; 24 static/runtime constructors and "
          "72 consuming finalizers; local pad/digest/tag/comparison storage only", flush=True)
    print("Accelerated HMAC finalizer owner dispatch: PASS; 72 Engine consumers; "
          "actual adapter/closure bodies and core/CPU-scratch destruction; "
          "hash finalizers remain separate callee contracts", flush=True)
    print("Accelerated HMAC public wrapper handoff: PASS; 72 consumers; "
          "split-copy/scalar Engine provenance and empty-state secret rejection", flush=True)
    print("Accelerated HMAC constructor admission: PASS; 24 constructor consumers; "
          "pre-key state-pool handoff and earlier-owner failure cleanup; "
          "typed factory callee contracts", flush=True)
    print("Accelerated HMAC constructor transfers: PASS; iterator consumption, "
          "normalization/inner/outer ownership, actual iterator destruction and "
          "returned HMAC fields; source-bound non-unwinding clear premise", flush=True)
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
