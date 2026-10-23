#!/usr/bin/env python3
"""Emit and check real legacy Scratch ownership; not whole-composition cleanup."""
import argparse
from pathlib import Path

import legacy_hmac_cleanup_codegen as codegen
# Same bounded, config-free Cargo process setup as the legacy timing fixture.
import legacy_hmac_timing_runner as runner

ROOT = runner.ROOT
FIXTURE = ROOT / "assurance/legacy-hmac-cleanup/Cargo.toml"


def emit(directory, compiler, target, panic, fixture=FIXTURE):
    env = runner.environment(directory)
    env["CARGO_PROFILE_RELEASE_PANIC"] = panic
    runner.run(["cargo", "+" + compiler, "rustc", "--manifest-path", str(fixture),
                "--locked", "--offline", "--release", "--lib", "--target", target,
                "--", "--emit=mir,llvm-ir,asm"], env)
    artifacts = []
    for extension in ("mir", "ll", "s"):
        files = list((directory / "target" / target / "release/deps").glob(
            "brynja_legacy_hmac_cleanup-*." + extension))
        codegen.require(len(files) == 1, "ambiguous legacy compiler artifacts")
        artifacts.append(files[0].read_text())
    return artifacts


def collect(directory, compiler, target, panic):
    artifacts = emit(directory, compiler, target, panic)
    codegen.check(*artifacts, panic)
    print(f"Legacy HMAC Scratch cleanup: PASS; {compiler}; {target}; panic={panic}; "
          "five probes; caller/MD5-row/worker qualification separate", flush=True)
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
