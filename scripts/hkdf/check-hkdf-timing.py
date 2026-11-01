#!/usr/bin/env python3
"""Bounded host timing diagnostic; retain alarms, never retry-to-pass."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

import hkdf_timing as timing
import hmac_verifiers as verifier


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("family", choices=("modern", "legacy"))
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("this observation is scoped to Linux x86_64")
    cpu = min(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {cpu})
    manifest = verifier.ROOT / "assurance/hkdf-timing/Cargo.toml"
    with verifier.cargo_environment.private_directory(verifier.ROOT) as temporary:
        env = verifier.environment(Path(temporary))
        env.update(RUSTUP_AUTO_INSTALL="0", CARGO_NET_OFFLINE="true")
        verifier.run(["cargo", "+1.99.1", "build", "--release", "--locked", "--offline",
                      "--no-default-features", "--features", args.family,
                      "--manifest-path", str(manifest)], env)
        binary = Path(env["CARGO_TARGET_DIR"]) / "release/brynja-hkdf-timing"
        print(json.dumps({"kind": "author-operated-HKDF-timing-screen", "family": args.family,
                          "host": platform.platform(), "logical_cpu": cpu,
                          "compiler": verifier.run(["rustc", "+1.99.1", "-vV"], env).strip(),
                          "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                          "samples_per_class": timing.SAMPLES, "repetitions": 4,
                          "alarm_threshold": timing.LIMIT,
                          "claim": "synthetic host observation; not constant-time or release qualification"}), flush=True)
        for phase in ("preflight", "measure"):
            result = subprocess.run([str(binary), phase], cwd=verifier.ROOT, env=env,
                                    capture_output=True, text=True, timeout=300)
            # The runner retains raw preflight and every measurement, including
            # signals. Validation precedes any successful completion marker.
            print(result.stdout, end="", flush=True)
            if result.returncode or result.stderr:
                raise RuntimeError("HKDF timing process failed: " + result.stderr[-4000:])
            if phase == "preflight":
                timing.preflight(result.stdout, args.family)
                print("Independent HKDF timing preflight: PASS", flush=True)
            else:
                rows = timing.parse(result.stdout, args.family)
        signals = sum(row["signal"] for row in rows)
        print(json.dumps({"campaigns": rows, "signals": signals}, allow_nan=False), flush=True)
        if signals:
            raise SystemExit("Timing alarm: investigate retained samples; do not retry-to-pass")
        print(f"HKDF {args.family} timing screen: {len(rows)} campaigns; 512 pairs; 4 repetitions; zero alarms")
        print("Observation only; not constant-time, cache, cross-target or independent qualification")


if __name__ == "__main__":
    main()
