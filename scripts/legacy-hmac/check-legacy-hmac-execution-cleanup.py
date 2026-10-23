#!/usr/bin/env python3
"""Qualify retained SHA-1 callers, finalizers and pre-key constructor admission."""
import argparse
from pathlib import Path

import legacy_hmac_execution_graph as graph
import legacy_hmac_execution_final as final
import legacy_hmac_execution_handoff as handoff
import legacy_hmac_execution_admission as admission
import legacy_hmac_execution_iterator as iterator
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
    final.check(artifacts[1][1], panic)
    handoff.validate(artifacts[1][1], panic, artifacts[0][1])
    admission.validate(artifacts[1][1], artifacts[0][1], panic)
    definitions, aliases = graph.flow.definitions_and_aliases(artifacts[1][1])
    target, (_, body) = final.method(definitions, aliases, "with_tag_length")
    return iterator.check(body, artifacts[1][1], definitions, aliases, panic,
                          admission.contracts.validate(artifacts[0][1], target))


def collect(directory, compiler, target, panic):
    artifacts = emit(directory, compiler, target, panic)
    outlined = validate(artifacts, compiler, panic)
    print(f"Legacy SHA-1 HMAC retained caller graphs: PASS; {compiler}; {target}; panic={panic}; "
          "cancellation, atomic rejection, fatal update, unwind and caller observer; "
          "three finalizer scratch graphs and two finalizer-core owner graphs; "
          "six public finalizer handoffs and secret-owner graph; "
          f"pre-key admission and constructor scratch; outlined_iterator={outlined}; "
          "post-admission normalization/return/inlined iterator, MD5 and hosted qualification separate", flush=True)
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
