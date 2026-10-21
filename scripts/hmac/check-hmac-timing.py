#!/usr/bin/env python3
"""Run an explicit HMAC timing screen. A quiet screen is not side-channel proof."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess

import hmac_timing as timing
import hmac_verifiers as verifier
import hmac_timing_routes as routes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--route", choices=timing.ROUTES, default="portable")
    parser.add_argument("--family", choices=timing.FAMILIES, default="all")
    parser.add_argument("--output", required=True, type=Path,
                        help="new local JSON observation; never an approved release receipt")
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("refusing to overwrite a timing observation")
    manifest = verifier.ROOT / "assurance/hmac-timing/Cargo.toml"
    with verifier.cargo_environment.private_directory(verifier.ROOT) as temporary:
        env = verifier.environment(Path(temporary))
        env, probe = routes.prepare(args.route, args.family, Path(temporary), env)
        verifier.run(["cargo", "+1.99.1", "build", "--release", "--locked", "--offline",
                      "--manifest-path", str(manifest)], env)
        binary = Path(env["CARGO_TARGET_DIR"]) / "release/brynja-hmac-timing"
        command = [str(binary), args.route, args.family]
        result = subprocess.run(command, env=env, cwd=verifier.ROOT,
                                capture_output=True, text=True, timeout=300)
        if result.returncode or result.stderr:
            raise RuntimeError("HMAC timing process failed: " + result.stderr[-4000:])
        rows = timing.parse(result.stdout, args.route, args.family)
        signals = sum(row["signal"] for row in rows)
        document = {
            "schema": 2, "kind": "author-operated-explicit-route-timing-screen",
            "route": args.route, "family": args.family, "generic_host_probe": probe,
            "build_rustflags": env.get("RUSTFLAGS", ""),
            "measurement_scope": "per-request key setup, update, finalization/verification and output cleanup; resource/authority acquisition excluded",
            "claim": "observation only; not constant-time, cache or native-backend qualification",
            "host": platform.platform(), "machine": platform.machine(),
            "compiler": verifier.run(["rustc", "+1.99.1", "-vV"], env).strip(),
            "head": subprocess.check_output(["git", "rev-parse", "HEAD"],
                                            cwd=verifier.ROOT, text=True).strip(),
            "tracked_diff_sha256": hashlib.sha256(subprocess.check_output(
                ["git", "diff", "HEAD", "--"], cwd=verifier.ROOT)).hexdigest(),
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "fixture_sources": {
                str(path.relative_to(verifier.ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (manifest, manifest.with_name("Cargo.lock"), *sorted((manifest.parent / "src").glob("*.rs")),
                             verifier.ROOT / "assurance/hmac-faults/host_probe.rs")},
            "harness_sources": {
                name: hashlib.sha256((verifier.ROOT / name).read_bytes()).hexdigest()
                for name in ("scripts/hmac/check-hmac-timing.py", "scripts/hmac/hmac_timing.py",
                             "scripts/hmac/hmac_timing_routes.py", "scripts/hmac/hmac_adapter_native.py",
                             "scripts/hmac/hmac_verifiers.py", "scripts/repository/facade_cargo_environment.py")},
            "command": command, "exit_status": result.returncode,
            "output_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
            "samples_per_class": timing.SAMPLES, "repetitions": 4,
            "alarm_threshold": timing.LIMIT, "signals": signals, "campaigns": rows,
            "raw_output": result.stdout,
        }
        with args.output.open("x") as stream:
            json.dump(document, stream, indent=2, allow_nan=False)
            stream.write("\n")
    print(f"HMAC {args.route}/{args.family} timing screen: {len(rows)} campaigns; {signals} signals; observation={args.output}")
    if signals:
        raise SystemExit("Timing signal needs investigation; do not retry until a passing run hides it")


if __name__ == "__main__":
    main()
