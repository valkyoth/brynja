#!/usr/bin/env python3
"""Static-only retained owners and public finalizer handoffs; not constructors."""
import argparse
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "hmac_execution_cleanup", Path(__file__).with_name("check-hmac-execution-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def validate(llvm, compiler="1.99.1", panic="unwind"):
    driver.validate_retained(llvm, compiler, panic, profile="static")
    functions, definitions, aliases = driver.emitted(llvm, driver.final.syntax.OPERATIONS)
    # Reject a runtime-enabled fixture even if a future coincidental layout
    # permits its retained checks. The real resolved graph is also checked.
    for identity in driver.common.IDENTITIES:
        suffix = "29brynja_hmac_execution_cleanup" + str(len(identity)) + identity + "17construct_runtime"
        driver.common.require(not any(suffix in name for name in (*definitions, *aliases)),
                              "runtime constructor in static-only artifact")
    for (identity, operation), body in functions.items():
        driver.scratch.check(body, operation, definitions, aliases)
        for health, present in ((0, True), (1, True), (0, False)):
            driver.wrapper.check(body, identity, operation, definitions, aliases,
                                 compiler, health, present, profile="static")


def collect(directory, compiler, target, panic):
    artifacts = driver.emit(directory, compiler, target, panic, profile="static")
    validate(artifacts[1], compiler, panic)
    print(f"HMAC static-only retained/wrapper cleanup: PASS; {compiler}; {target}; "
          f"panic={panic}; 24 cancellation/update and 72 finalizer scratch/handoff consumers; "
          "constructors and consuming Engine transfers pending; not whole-frame erasure", flush=True)
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
            with driver.verifier.cargo_environment.private_directory(driver.ROOT) as directory:
                collect(Path(directory), compiler, args.target, panic)


if __name__ == "__main__":
    main()
