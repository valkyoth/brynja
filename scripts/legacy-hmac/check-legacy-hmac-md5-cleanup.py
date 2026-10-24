#!/usr/bin/env python3
"""Inspect actual MD5 HMAC row cleanup; no native execution or release approval."""
import argparse
from pathlib import Path
import re

import legacy_hmac_md5_rows as rows
import legacy_hmac_md5_admission as admission
import legacy_hmac_md5_handoff as handoff
import legacy_hmac_md5_phases as phases
import legacy_hmac_md5_results as results
import legacy_hmac_md5_descriptors as descriptors
import legacy_hmac_md5_pads as pads
import legacy_hmac_md5_normalization as normalization
import legacy_hmac_md5_keys as keys
import legacy_hmac_md5_setup as setup
import legacy_hmac_md5_reports as reports
import legacy_hmac_md5_outer as outer
import legacy_hmac_md5_inner_owner as inner_owner
import legacy_hmac_md5_inner_report as inner_report
import legacy_hmac_md5_outer_result as outer_result
import legacy_hmac_md5_truncation as truncation
import legacy_hmac_md5_report_return as report_return
import legacy_hmac_md5_normalization_return as normalization_return
import legacy_hmac_md5_return_header as return_header
import legacy_hmac_md5_return_paths as return_paths
import legacy_hmac_md5_output_views as output_views
import legacy_hmac_md5_consumer_return as consumer_return
import legacy_hmac_md5_secret_consumer as secret_consumer
import legacy_hmac_md5_comparison as comparison
import legacy_hmac_md5_initialization as initialization
import legacy_hmac_md5_candidates as candidates
import legacy_hmac_md5_teardown as teardown
import legacy_hmac_md5_quarantine as quarantine
import legacy_hmac_timing_runner as runner

ROOT = runner.ROOT
FIXTURE = ROOT / "assurance/legacy-hmac-md5-cleanup/Cargo.toml"
TARGETS = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "aarch64-apple-darwin")


def emit(directory, compiler, target, panic, simd=False, fixture=FIXTURE):
    env = runner.environment(directory)
    env["CARGO_PROFILE_RELEASE_PANIC"] = panic
    if simd:
        env["RUSTFLAGS"] = "-C target-feature=" + ("+avx2" if target.startswith("x86_64") else "+neon")
    command = ["cargo", "+" + compiler, "rustc", "--manifest-path", str(fixture),
               "--locked", "--offline", "--release", "--lib", "--target", target]
    for package in ([], ["-p", "brynja-legacy-hmac"]):
        runner.run(command + package + ["--", "--emit=mir,llvm-ir,asm"], env)
    artifacts = []
    for crate in ("brynja_legacy_hmac_md5_cleanup", "brynja_legacy_hmac"):
        result = []
        for extension in ("mir", "ll", "s"):
            files = list((directory / "target" / target / "release/deps").glob(crate + "-*." + extension))
            rows.require(len(files) == 1, "ambiguous MD5 compiler artifact: " + crate)
            result.append(files[0].read_text())
        artifacts.append(result)
    return artifacts


def consumers(fixture, llvm):
    definitions, aliases = rows.flow.definitions_and_aliases(llvm)
    consumer_defs, consumer_aliases = rows.flow.definitions_and_aliases(fixture)
    for name, method in (("public", "authenticate"), ("secret", "authenticate_secret"), ("verify", "verify")):
        matches = [symbol for symbol in (*consumer_defs, *consumer_aliases)
                   if re.search("30brynja_legacy_hmac_md5_cleanup" + str(len(name)) + name + r"(?:17h\w+E)?$", symbol)]
        rows.require(len(matches) == 1, "missing MD5 downstream consumer")
        _, body = rows.flow.resolve(matches[0], consumer_defs, consumer_aliases)
        target, _ = rows.method(definitions, aliases, method)
        calls = [(line, rows.syntax.call(line)) for line in body.splitlines()
                 if re.search(r'@"?' + re.escape(target) + r'"?\(', line)]
        rows.require(len(calls) == 1, "consumer does not call actual MD5 operation once")
        line, (_, args) = calls[0]
        rows.require(len(args) == 5 and [rows.syntax.operand(arg) for arg in args[1:]] ==
                     ["%selection", "%inputs", "%candidates" if name == "verify" else "%output", "%control"],
                     "MD5 consumer arguments changed")
        first = next(iter(rows.flow.blocks(body).values()))
        rows.require(line.strip() in first, "consumer dispatch no longer dominates entry")
        rows.require(not any(item.startswith(("br ", "ret ", "switch ")) for item in first[:first.index(line.strip())]),
                     "consumer bypasses MD5 dispatch")


def validate(artifacts, panic):
    consumers(artifacts[0][1], artifacts[1][1])
    admission.validate(artifacts[0][1], artifacts[1][1])
    handoff.validate(artifacts[0][1], artifacts[1][1], panic)
    phases.validate(artifacts[1][1])
    results.validate(artifacts[0][1], artifacts[1][1], panic)
    descriptors.validate(artifacts[0][1], artifacts[1][1])
    pads.validate(artifacts[0][1], artifacts[1][1])
    normalization.validate(artifacts[0][1], artifacts[1][1])
    keys.validate(artifacts[0][1], artifacts[1][1])
    setup.validate(artifacts[0][1], artifacts[1][1], panic)
    reports.validate(artifacts[0][1], artifacts[1][1])
    outer.validate(artifacts[0][1], artifacts[1][1])
    inner_owner.validate(artifacts[0][1], artifacts[1][1])
    inner_report.validate(artifacts[0][1], artifacts[1][1])
    outer_result.validate(artifacts[0][1], artifacts[1][1])
    truncation.validate(artifacts[0][1], artifacts[1][1])
    report_return.validate(artifacts[0][1], artifacts[1][1])
    normalization_return.validate(artifacts[0][1], artifacts[1][1])
    return_header.validate(artifacts[0][1], artifacts[1][1])
    return_paths.validate(artifacts[0][1], artifacts[1][1])
    output_views.validate(artifacts[0][1], artifacts[1][1])
    consumer_return.validate(artifacts[0][1], artifacts[1][1])
    secret_consumer.validate(artifacts[0][1], artifacts[1][1], panic)
    comparison.validate(artifacts[1][1], panic)
    initialization.validate(artifacts[0][1], artifacts[1][1])
    candidates.validate(artifacts[0][1], artifacts[1][1])
    teardown.validate(artifacts[0][1], artifacts[1][1], panic)
    quarantine.validate(artifacts[0][1], artifacts[1][1], panic)
    return rows.validate(artifacts[1][1], panic)


def collect(directory, compiler, target, panic, simd=False):
    artifacts = emit(directory, compiler, target, panic, simd)
    population = validate(artifacts, panic)
    print(f"Legacy HMAC-MD5 row cleanup: PASS; {compiler}; {target}; panic={panic}; simd={simd}; "
          f"{population} actual row/normalization/comparison bodies; pre-workspace tag/authority admission; workspace helper lane dispatch; phase argument transport; final readiness/handoff; "
          "inner error-path exclusion; 256-mask inner descriptor provenance; conditional ipad construction; normalization-result owner transport; "
          "key descriptor/shape-route scenarios; normalization initialization/readiness and report guard/transport scenarios; "
          "conditional outer-pad conversion and lane-descriptor scenarios; "
          "inner-result pointer/length transport and failure exclusion; "
          "inner report admission against selection and activity; "
          "outer nested-result owner/admission; lane truncation to final readiness; accepted inner/outer return counters; "
          "normalization return-copy lifetimes; selected return-report backend/width; every-normal-success report coverage; "
          "consumer result gating/transport; public destination isolation; tag-view and returned metadata scenarios; "
          "secret consumer write/finish/error/unwind ownership; complete lane-byte comparison traces and scratch clearing; "
          "caller initialization creation/moves/early-exit ownership; symbolic eight-lane candidate presence/length admission; "
          "closed nonthrowing success teardown; returned-error-bound classification and escaping-unwind quarantine; "
          "no whole-caller, hosted-worker, kernel or register-erasure qualification", flush=True)
    return artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", action="append", choices=("1.90.0", "1.99.1"))
    parser.add_argument("--target", choices=TARGETS, default=TARGETS[0])
    parser.add_argument("--simd", action="store_true")
    args = parser.parse_args()
    for compiler in args.toolchain or ("1.90.0", "1.99.1"):
        for panic in ("abort", "unwind"):
            with runner.cargo_environment.private_directory(ROOT) as raw:
                collect(Path(raw), compiler, args.target, panic, args.simd)


if __name__ == "__main__":
    main()
