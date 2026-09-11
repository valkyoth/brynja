#!/usr/bin/env python3
"""Independent TupleHash execution oracle; hardware routes require explicit selection."""
import argparse
import importlib.util
import os
from pathlib import Path
import platform
import re
import subprocess
import tuplehash_execution_policy as policy

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "assurance/tuplehash-execution/Cargo.toml"


def oracle_module():
    spec = importlib.util.spec_from_file_location(
        "tuple_oracle", ROOT / "scripts/tuplehash/check-tuplehash-differential.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def official(oracle):
    text = (ROOT / "crates/brynja-hash-tuple/tests/official_vectors.rs").read_text()
    rows = re.findall(r'check_(xof_)?(128|256)\(\s*(false|true),\s*(false|true),\s*"([A-F0-9]+)",\s*\);', text)
    if len(rows) != 12:
        raise RuntimeError("all twelve official TupleHash examples are required")
    cases = []
    for xof, strength, customized, third, value in rows:
        items = [bytes(range(3)), bytes(range(0x10, 0x16))]
        if third == "true":
            items.append(bytes(range(0x20, 0x29)))
        custom = b"My Tuple App" if customized == "true" else b""
        expected = bytes.fromhex(value)
        actual = oracle.tuple_hash(168 if strength == "128" else 136,
            [oracle.oracle.byte_bits(item) for item in items],
            oracle.oracle.byte_bits(custom), len(expected) * 8, bool(xof))
        if actual != expected:
            raise RuntimeError("independent oracle disagrees with official TupleHash example")
        cases.append(("tuplexof" + strength if xof else "tuple" + strength,
            custom, len(custom)*8, [(item, len(item)*8) for item in items], len(expected)*8, expected))
    return cases


def execute(command, env, request=None, success=True):
    result = subprocess.run(command, cwd=ROOT, env=env, input=request,
                            text=True, capture_output=True, timeout=600, check=False)
    if (result.returncode == 0) != success or "panicked at" in result.stderr:
        raise RuntimeError(f"TupleHash command failed: {command}\n{result.stdout}\n{result.stderr}")
    return result


def campaign(mode, environment=None, target=None, toolchain="1.98.1"):
    env = dict(os.environ if environment is None else environment)
    oracle = oracle_module()
    oracle.verify_oracle()
    cases = official(oracle) + oracle.cases()
    lines = []
    for name, custom, cb, items, ob, _ in cases:
        fields = [name, str(cb), custom.hex() or "-", str(ob), str(len(items))]
        for value, bits in items:
            fields.extend((str(bits), value.hex() or "-"))
        lines.append(" ".join(fields))
    command = ["cargo", "+" + toolchain, "run", "--locked", "--offline", "--quiet", "--release",
               "--manifest-path", MANIFEST]
    if target:
        command += ["--target", target]
    command += ["--", mode]
    result = execute(command, env, "\n".join(lines) + "\n")
    if result.stdout.splitlines() != [value.hex() for *_, value in cases]:
        raise RuntimeError("TupleHash independent arbitrary-bit output mismatch")
    route = "Portable" if mode in ("portable", "prefer-portable") else (
        "X86Keccak" if target is None and platform.machine() in ("x86_64", "AMD64") else "ArmKeccak")
    if "TUPLEHASH_EXECUTION_ROUTE: " not in result.stderr or route not in result.stderr:
        raise RuntimeError("missing TupleHash execution route")
    for invalid in (
        "tuple128 1 80 8 0\n", "tuplexof256 0 - 4096 0\n",
        "unknown 0 - 8 0\n", "tuple128 0 - 8 17\n",
        "tuple128 0 - 8 0 trailing\n", "tuple128 0 - 18446744073709551616 0\n",
        "tuple128 0 - 8 1 1 80\n",
    ):
        if execute(command, env, invalid, False).stdout:
            raise RuntimeError("malformed TupleHash request leaked partial output")
    print(f"TupleHash execution oracle: PASS; mode={mode}; cases={len(cases)}; kernel={route}", flush=True)


def native_environment(arm=False):
    env = dict(os.environ)
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_BUILD_TARGET"):
        if env.get(name):
            raise RuntimeError("unexpected native compilation override: " + name)
    if arm:
        if platform.machine() not in ("aarch64", "arm64"):
            raise RuntimeError("native Arm campaign requires an Arm host")
        campaign("hosted", env)
        features = "+neon,+sha2,+sha3"
    else:
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise RuntimeError("native x86 campaign requires Linux x86_64")
        flags = [line.split(":", 1)[1].split() for line in Path("/proc/cpuinfo").read_text().splitlines()
                 if line.startswith("flags")]
        if not flags or not all("avx2" in row for row in flags):
            raise RuntimeError("AVX2 not available on every reported processor")
        features = "+avx2"
    env["RUSTFLAGS"] = "-C target-feature=" + features
    return env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    native = parser.add_mutually_exclusive_group()
    native.add_argument("--native-x86", action="store_true")
    native.add_argument("--native-arm", action="store_true")
    native.add_argument("--qemu", action="store_true")
    native.add_argument("--asan", action="store_true")
    parser.add_argument("--write-review", action="store_true")
    parser.add_argument("--policy-only", action="store_true")
    args = parser.parse_args()
    policy.validate(write=args.write_review)
    if args.write_review or args.policy_only:
        return
    if args.asan:
        env = native_environment(False)
        env["RUSTFLAGS"] += " -Zsanitizer=address"
        campaign("static", env, toolchain="nightly-2026-09-11")
        return
    campaign("portable")
    campaign("prefer-portable")
    if args.native_x86 or args.native_arm:
        env = native_environment(args.native_arm)
        campaign("static", env)
        campaign("prefer", env)
    if args.qemu:
        env = dict(os.environ, RUSTFLAGS="-C linker=rust-lld",
                   CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER="qemu-aarch64 -cpu max")
        campaign("hosted", env, "aarch64-unknown-linux-musl")
        env["RUSTFLAGS"] += " -C target-feature=+neon,+sha2,+sha3"
        campaign("static", env, "aarch64-unknown-linux-musl")
        campaign("prefer", env, "aarch64-unknown-linux-musl")


if __name__ == "__main__":
    main()
