#!/usr/bin/env python3
"""Rebuild the reviewed x86-64 update body or collect one bounded timing screen."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/hmac"))

COMPILERS = ("1.90.0", "1.100.0")
REVIEWED = {
    "1.90.0": "810801580d4590e8516ecb534f4fac8c3b10a8c96bad7905818d638a5f7043f1",
    "1.100.0": "b51e22493ebab5833cb4d50197fdf8a28ffe38c7ef257e07ecb42ba6a0a8a31f",
}
CROSS_REVIEWED = {
    ("1.90.0", "thumbv7em-none-eabi"): "feaec1292ba86c0a4eff1396a7add8ac7c160fdbc81b8477453937b109356922",
    ("1.90.0", "riscv32imac-unknown-none-elf"): "71abce59cb4d2c64b27168968db5cf79bdcf87f234b61a44d28485b762916ccd",
    ("1.90.0", "aarch64-linux-android"): "7c137d9ff3254fb9df0d068e1897cc0da4050250f615ccb017830eb25b0c2d3c",
    ("1.100.0", "thumbv7em-none-eabi"): "101776924585c8e10916757464e08fb599cc057dea086898ec6993b2bc15b337",
    ("1.100.0", "riscv32imac-unknown-none-elf"): "c7ca5500ab8fbadac28ffceba843ecd7e2e16c153906a527221a7585b1ce81fb",
    ("1.100.0", "aarch64-linux-android"): "b7c94c73fc848ecdefaee528b45117c51a556c55a811fb38d9c22b6eef94dd4d",
}
MODES = ("identical", "subkey", "block")
N = 2048


def digest(data):
    return hashlib.sha256(data).hexdigest()


def update_body(assembly):
    # Retain operands, labels, branch destinations and directives. Ignore
    # only the outer function's mangled name and surrounding whitespace.
    matches = re.findall(r"^([^\s.][^:\n]*Ghash6update[^:\n]*):\n(.*?)^\s*\.size\s+\1,",
                         assembly, re.M | re.S)
    if len(matches) != 1:
        raise ValueError("missing or ambiguous Ghash::update assembly")
    return matches[0][1].strip().encode()


def summarize(raw):
    lines = raw.decode("ascii").splitlines()
    if len(lines) != N * len(MODES):
        raise ValueError("incomplete or excessive timing population")
    results = {}
    for i, mode in enumerate(MODES):
        diffs = []
        for line in lines[i*N:(i+1)*N]:
            row = re.fullmatch(rf"{mode} ([1-9][0-9]{{0,18}}) ([1-9][0-9]{{0,18}})", line)
            if not row:
                raise ValueError("unexpected campaign, order or duration")
            diffs.append(int(row[1]) - int(row[2]))
        mean = statistics.mean(diffs)
        sd = statistics.stdev(diffs)
        t = mean / (sd / math.sqrt(N)) if sd else (0 if not mean else None)
        results[mode] = dict(mean_difference_ns=mean, paired_t=t,
                             alarm=t is None or abs(t) >= 4.5)
    return results


def run(mode, output, compiler, tmp, cross_target=None):
    from hmac_verifiers import environment
    env = environment(tmp)
    env.update(CARGO_NET_OFFLINE="true", RUSTUP_AUTO_INSTALL="0")
    def command(*args):
        return subprocess.check_output(args, env=env, cwd=ROOT, timeout=180)
    version = command("rustc", "+" + compiler, "-vV").decode()
    if "host: x86_64-unknown-linux-gnu" not in version:
        raise ValueError("requires native x86_64-unknown-linux-gnu compiler")
    target = Path(env["CARGO_TARGET_DIR"])
    if mode in ("codegen", "cross-codegen"):
        target_args = ["--target", cross_target] if cross_target else []
        command("cargo", "+" + compiler, "rustc", "--locked", "--offline", "--release",
                "--no-default-features", "--features", "hazmat-ghash", "-p", "brynja-crypto",
                *target_args, "--", "--emit=mir,llvm-ir,asm")
        hashes = {}
        for ext in ("mir", "ll", "s"):
            paths = list(target.rglob(f"brynja_crypto-*.{ext}"))
            if len(paths) != 1:
                raise ValueError("ambiguous or missing emitted artifact")
            data = paths[0].read_bytes()
            hashes[ext] = digest(data)
            if ext == "s":
                hashes["update"] = digest(update_body(data.decode()))
        expected = CROSS_REVIEWED[compiler, cross_target] if cross_target else REVIEWED[compiler]
        if hashes["update"] != expected:
            raise ValueError(f"{compiler}: assembly changed; new manual review required")
        print(compiler, cross_target or "host", json.dumps(hashes, sort_keys=True))
        return False

    command("cargo", "+" + compiler, "build", "--locked", "--offline", "--release",
            "--manifest-path", "assurance/ghash-timing/Cargo.toml")
    binary = target / "release/brynja-ghash-timing"
    raw = command(str(binary))
    (output / f"{compiler}.txt").write_bytes(raw)
    results = summarize(raw)
    record = dict(compiler=version, host=platform.platform(), cpu=min(os.sched_getaffinity(0)),
                  binary_sha256=digest(binary.read_bytes()), raw_sha256=digest(raw), results=results)
    (output / f"{compiler}.json").write_text(json.dumps(record, indent=2) + "\n")
    print(compiler, json.dumps(results))
    return any(row["alarm"] for row in results.values())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("codegen", "cross-codegen", "timing"))
    p.add_argument("--output", type=Path, help="new directory required for timing")
    args = p.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        p.error("Linux x86-64 only")
    if (args.mode == "timing") != bool(args.output):
        p.error("supply --output only for timing; existing runs are never overwritten")
    if args.output:
        args.output.mkdir(parents=True, exist_ok=False)
        os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    alarms = []
    builds = (CROSS_REVIEWED if args.mode == "cross-codegen"
              else [(compiler, None) for compiler in COMPILERS])
    for compiler, cross_target in builds:
        with tempfile.TemporaryDirectory() as tmp:
            alarms.append(run(args.mode, args.output, compiler, Path(tmp), cross_target))
    if any(alarms):
        raise SystemExit("Timing alarm retained; investigate separately, do not retry to pass")
    print("GHASH_HOST_" + args.mode.upper() + "_COMPLETE")


if __name__ == "__main__":
    main()
