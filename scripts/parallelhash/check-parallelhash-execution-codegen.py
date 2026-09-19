#!/usr/bin/env python3
"""Emit and inspect the new ParallelHash source-owned destruction boundaries."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

import parallelhash_cleanup as cleanup

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", choices=("1.90.0", "1.98.1"), default="1.98.1")
    parser.add_argument("--target", choices=("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-musl"),
                        default="x86_64-unknown-linux-gnu")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="brynja-parallel-cleanup-") as directory:
        env = dict(os.environ, CARGO_TARGET_DIR=directory, CARGO_PROFILE_RELEASE_PANIC="unwind")
        for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_BUILD_TARGET"):
            env.pop(key, None)
        subprocess.run(["cargo", "+" + args.toolchain, "rustc", "--locked", "--offline",
                        "-p", "brynja-hash-parallel", "--features", "hardened-execution,runtime-execution",
                        "--release", "--lib", "--target", args.target, "--", "--emit=mir,llvm-ir,asm"],
                       cwd=ROOT, env=env, check=True, timeout=180)
        row = {}
        for extension in ("mir", "ll", "s"):
            paths = list(Path(directory).rglob("brynja_hash_parallel-*." + extension))
            cleanup.require(len(paths) == 1, "unique compiler artifact")
            row[extension] = paths[0].read_text()
        cleanup.check(row)
        for extension, before, after in (
            ("mir", "scheduled_core::Count::wipe(", "scheduled_core::Count::omitted("),
            ("ll", "i64 noundef 16)", "i64 noundef 8)"),
            ("s", "CountGuard", "OmittedGuard"),
        ):
            cleanup.require(before in row[extension], "live scheduled counter cleanup mutation target")
            mutant = dict(row, **{extension: row[extension].replace(before, after)})
            try:
                cleanup.check_scoped_scheduled(mutant)
            except (ValueError, cleanup.flow.MirCleanupFlowError):
                continue
            raise ValueError("ParallelHash scheduled emitted cleanup mutant escaped")
        for extension, before, after in (
            ("mir", "Metadata::wipe(", "Metadata::omitted("),
            ("mir", "&mut ((*_1).2: [u8; 64])", "&mut ((*_1).0: [u8; 16])"),
            ("ll", "i64 noundef 64)", "i64 noundef 32)"),
            ("s", "Metadata", "Omitted"),
        ):
            cleanup.require(before in row[extension], "live scoped cleanup mutation target")
            mutant = dict(row, **{extension: row[extension].replace(before, after)})
            try:
                cleanup.check_scoped(mutant)
            except (ValueError, cleanup.flow.MirCleanupFlowError):
                continue
            raise ValueError("ParallelHash scoped emitted cleanup mutant escaped")
        for extension, before, after in (
            ("mir", "clear_owned_region(", "omitted("),
            ("mir", "::cancel(", "::omitted("),
            ("mir", "&mut ((*_1).2: [u8; 16])", "&mut ((*_1).3: [u8; 16])"),
            ("ll", "clear_owned_region", "omitted"),
            ("s", "cancel", "omitted"),
        ):
            cleanup.require(before in row[extension], "live emitted mutation target")
            mutant = dict(row, **{extension: row[extension].replace(before, after)})
            try:
                cleanup.check(mutant)
            except (ValueError, cleanup.flow.MirCleanupFlowError):
                continue
            raise ValueError("ParallelHash emitted cleanup mutant escaped")
        subprocess.run(["cargo", "+" + args.toolchain, "rustc", "--locked", "--offline",
                        "-p", "brynja-hash-parallel-std", "--features", "runtime-execution",
                        "--release", "--lib", "--target", args.target, "--", "--emit=mir,llvm-ir,asm"],
                       cwd=ROOT, env=env, check=True, timeout=180)
        storage = {}
        for extension in ("mir", "ll", "s"):
            paths = list(Path(directory).rglob("brynja_hash_parallel_std-*." + extension))
            cleanup.require(len(paths) == 1, "unique std compiler artifact")
            storage[extension] = paths[0].read_text()
        cleanup.check_storage(storage)
        subprocess.run(["cargo", "+" + args.toolchain, "rustc", "--locked", "--offline",
                        "--manifest-path", "assurance/parallelhash-differential/Cargo.toml",
                        "--features", "execution", "--release", "--bin", "brynja-parallelhash-differential-fixture",
                        "--target", args.target, "--", "--emit=mir,llvm-ir,asm",
                        *(["-C", "linker=rust-lld"] if args.target == "aarch64-unknown-linux-musl" else [])],
                       cwd=ROOT, env=env, check=True, timeout=180)
        fixture = {}
        for extension in ("ll", "s"):
            paths = list(Path(directory).rglob("brynja_parallelhash_differential_fixture-*." + extension))
            cleanup.require(len(paths) == 1, "unique scoped downstream artifact")
            fixture[extension] = paths[0].read_text()
        cleanup.check_scoped_storage(storage, fixture)
        for part, extension, before, after in (
            ("storage", "mir", "Slots::<N>::clear(", "Slots::<N>::omitted("),
            ("fixture", "ll", "i64 noundef 32)", "i64 noundef 16)"),
            ("fixture", "ll", "i64 noundef 64)", "i64 noundef 32)"),
            ("fixture", "s", "Slots", "Omitted"),
        ):
            original = storage if part == "storage" else fixture
            cleanup.require(before in original[extension], "live scoped slot cleanup mutation")
            mutant = dict(original, **{extension: original[extension].replace(before, after)})
            try:
                cleanup.check_scoped_storage(mutant if part == "storage" else storage,
                                             mutant if part == "fixture" else fixture)
            except (ValueError, cleanup.flow.MirCleanupFlowError):
                continue
            raise ValueError("scoped thread slot cleanup mutant escaped")
        for extension, before, after in (
            ("mir", "Storage::clear(", "Storage::omitted("),
            ("ll", "clear_owned_region", "omitted"),
            ("ll", "i64 noundef 64)", "i64 noundef 32)"),
            ("s", "Storage", "omitted"),
        ):
            cleanup.require(before in storage[extension], "live std cleanup mutation target")
            mutant = dict(storage, **{extension: storage[extension].replace(before, after)})
            try:
                cleanup.check_storage(mutant)
            except (ValueError, cleanup.flow.MirCleanupFlowError):
                continue
            raise ValueError("ParallelHash std cleanup mutant escaped")
    print(f"ParallelHash execution MIR/LLVM/assembly cleanup: PASS; {args.toolchain} {args.target}")
    print("Source-owned storage only; not register, compiler-spill or platform erasure")


if __name__ == "__main__":
    main()
