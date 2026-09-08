#!/usr/bin/env python3
"""Collect exact-source, non-admitting Arm SHA-512/t integration evidence."""
import argparse
import hashlib
import json
import platform
import tempfile
from pathlib import Path

import general_sha512_t_cpu as cpu
import general_sha512_t_policy as policy

LANES = ("apple-m2-aarch64", "aws-aarch64")


def run(command):
    code, output = cpu.execute(command)
    if code:
        raise ValueError(f"{command[0]} failed:\n{output}")
    return output.strip()


def host(lane):
    if lane not in LANES or platform.machine().lower() not in ("aarch64", "arm64"):
        raise ValueError("registered native Arm lane required")
    if lane == "apple-m2-aarch64":
        if platform.system() != "Darwin" or "Apple M2" not in run(["sysctl", "-n", "machdep.cpu.brand_string"]):
            raise ValueError("Apple M2 lane mismatch")
        for feature in ("hw.optional.neon", "hw.optional.arm.FEAT_SHA512", "hw.optional.arm.FEAT_SHA3"):
            if run(["sysctl", "-n", feature]) != "1":
                raise ValueError("missing native feature: " + feature)
        return "aarch64-apple-darwin", "Apple M2; operator-self-attested"
    if platform.system() != "Linux":
        raise ValueError("AWS Arm lane requires Linux")
    with Path("/proc/cpuinfo").open() as stream:
        text = stream.read(2_000_001)
    if len(text) > 2_000_000:
        raise ValueError("CPU description exceeds bound")
    flags = [set(line.split(":", 1)[1].split()) for line in text.splitlines() if line.startswith("Features") and ":" in line]
    if not flags or not all({"asimd", "sha512", "sha3"} <= row for row in flags):
        raise ValueError("every enumerated CPU must expose asimd/sha512/sha3")
    return "aarch64-unknown-linux-gnu", "operator-labelled AWS Arm; provider identity not authenticated"


def fingerprint():
    paths = set(policy.BOUND)
    for name in cpu.CRATES:
        base = cpu.ROOT / "crates" / name
        paths.update(p.relative_to(cpu.ROOT).as_posix() for p in (base / "src").rglob("*.rs"))
        paths.add(f"crates/{name}/Cargo.toml")
    paths.update(("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"))
    return {name: hashlib.sha256(policy.contract.read(cpu.ROOT, name)).hexdigest() for name in sorted(paths)}


def destination(path):
    if any(p.is_symlink() for p in (path, *path.parents)) or path.exists():
        raise ValueError("evidence destination exists or crosses a symlink")


def capture(lane, output):
    policy.validate()
    if run(["git", "status", "--porcelain"]):
        raise ValueError("capture requires a clean committed candidate")
    destination(output)
    commit = run(["git", "rev-parse", "HEAD"])
    before = fingerprint()
    target, identity = host(lane)
    compiler = run(["rustc", "+1.98.1", "-vV"])
    if f"host: {target}" not in compiler:
        raise ValueError("compiler is not native to this lane")
    results = cpu.campaign(target, "-C target-feature=+neon,+sha3", "aarch64-sha512")
    if run(["git", "status", "--porcelain"]) or run(["git", "rev-parse", "HEAD"]) != commit or fingerprint() != before:
        raise ValueError("candidate changed during capture")
    policy.validate()
    document = dict(schema=1, milestone="0.24.29", lane=lane, commit=commit, target=target,
                    compiler=compiler, cpu=identity, source_sha256=before, results=results,
                    native="operator-self-attested", cpu_admitted=False, independent_review=False,
                    fips_validated=False, hardened="portable-only", migration_safety="unproven",
                    side_channel_review="pending", production_rejection=True, quarantine_rejection=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    destination(output)
    # Exclusive destination creation: never overwrite an earlier observation.
    # A failed/partial JSON is not evidence and must not be imported.
    with output.open("x", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(f"Wrote {output}; no hostname; self-attested candidate observation, NOT admission")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("lane", choices=LANES)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    capture(args.lane, args.output)
