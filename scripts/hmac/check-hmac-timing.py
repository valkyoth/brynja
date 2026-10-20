#!/usr/bin/env python3
"""Run a portable HMAC timing screen. A quiet screen is not side-channel proof."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess

import hmac_timing as timing
import hmac_verifiers as verifier


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path,
                        help="new local JSON observation; never an approved release receipt")
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("refusing to overwrite a timing observation")
    manifest = verifier.ROOT / "assurance/hmac-timing/Cargo.toml"
    with verifier.cargo_environment.private_directory(verifier.ROOT) as temporary:
        env = verifier.environment(Path(temporary))
        verifier.run(["cargo", "+1.99.1", "build", "--release", "--locked", "--offline",
                      "--manifest-path", str(manifest)], env)
        binary = Path(env["CARGO_TARGET_DIR"]) / "release/brynja-hmac-timing"
        result = subprocess.run([str(binary)], env=env, cwd=verifier.ROOT,
                                capture_output=True, text=True, timeout=300)
        if result.returncode or result.stderr:
            raise RuntimeError("HMAC timing process failed: " + result.stderr[-4000:])
        rows = timing.parse(result.stdout)
        signals = sum(row["signal"] for row in rows)
        document = {
            "schema": 1, "kind": "author-operated-portable-timing-screen",
            "claim": "observation only; not constant-time, cache or native-backend qualification",
            "host": platform.platform(), "machine": platform.machine(),
            "compiler": verifier.run(["rustc", "+1.99.1", "-vV"], env).strip(),
            "head": subprocess.check_output(["git", "rev-parse", "HEAD"],
                                            cwd=verifier.ROOT, text=True).strip(),
            "tracked_diff_sha256": hashlib.sha256(subprocess.check_output(
                ["git", "diff", "HEAD", "--"], cwd=verifier.ROOT)).hexdigest(),
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "fixture_sources": {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (manifest, manifest.with_name("Cargo.lock"), manifest.parent / "src/main.rs")},
            "command": [str(binary)], "exit_status": result.returncode,
            "output_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
            "samples_per_class": timing.SAMPLES, "repetitions": 4,
            "alarm_threshold": timing.LIMIT, "signals": signals, "campaigns": rows,
            "raw_output": result.stdout,
        }
        with args.output.open("x") as stream:
            json.dump(document, stream, indent=2, allow_nan=False)
            stream.write("\n")
    print(f"HMAC portable timing screen: 96 campaigns; {signals} signals; observation={args.output}")
    if signals:
        raise SystemExit("Timing signal needs investigation; do not retry until a passing run hides it")


if __name__ == "__main__":
    main()
