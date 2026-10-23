#!/usr/bin/env python3
"""Qualify accelerated SHA-1 retained cancellation/update; other paths pending."""
import argparse
from pathlib import Path

import legacy_hmac_execution_graph as graph
import legacy_hmac_timing_runner as runner

ROOT = runner.ROOT
FIXTURE = ROOT / "assurance/legacy-hmac-execution-cleanup/Cargo.toml"


def emit(directory, compiler, target, panic, fixture=FIXTURE):
    env = runner.environment(directory)
    env["CARGO_PROFILE_RELEASE_PANIC"] = panic
    command = ["cargo", "+" + compiler, "rustc", "--manifest-path", str(fixture),
               "--locked", "--offline", "--release", "--lib", "--target", target]
    for package in ([], ["-p", "brynja-legacy-hmac"]):
        runner.run(command + package + ["--", "--emit=mir,llvm-ir,asm"], env)
    result = []
    for crate in ("brynja_legacy_hmac_execution_cleanup", "brynja_legacy_hmac"):
        artifacts = []
        for extension in ("mir", "ll", "s"):
            files = list((directory / "target" / target / "release/deps").glob(crate + "-*." + extension))
            graph.require(len(files) == 1, "ambiguous accelerated artifact: " + crate)
            artifacts.append(files[0].read_text())
        result.append(artifacts)
    return result


def validate(artifacts, compiler, panic):
    graph.Graph(artifacts[0][1], artifacts[1][1], compiler, panic).check()


def collect(directory, compiler, target, panic):
    artifacts = emit(directory, compiler, target, panic)
    validate(artifacts, compiler, panic)
    print(f"Legacy SHA-1 HMAC retained caller graphs: PASS; {compiler}; {target}; panic={panic}; "
          "cancellation, atomic rejection, fatal update, unwind and caller observer; "
          "constructor/finalizer/MD5/hosted qualification separate", flush=True)
    return artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", action="append", choices=("1.90.0", "1.99.1"))
    parser.add_argument("--target", default="x86_64-unknown-linux-gnu",
                        choices=("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "aarch64-apple-darwin"))
    args = parser.parse_args()
    for compiler in args.toolchain or ["1.90.0", "1.99.1"]:
        for panic in ("abort", "unwind"):
            with runner.cargo_environment.private_directory(ROOT) as raw:
                collect(Path(raw), compiler, args.target, panic)


if __name__ == "__main__":
    main()
