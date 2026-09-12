#!/usr/bin/env python3
"""Independent bit-oriented oracle against actual ParallelHash execution APIs."""
from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("parallel_oracle", Path(__file__).with_name("check-parallelhash-differential.py"))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", action="store_true", help="also require accelerated roots and every nonempty leaf")
    parser.add_argument("--static", action="store_true", help="require caller-enabled target-specialized roots and workers")
    args = parser.parse_args()
    cases = oracle.cases()
    request = "\n".join(
        f"{algorithm} {cbits} {custom.hex() or '-'} {mbits} {message.hex() or '-'} {block} {obits}"
        for algorithm, custom, cbits, message, mbits, block, obits, _ in cases
    ) + "\n"
    expected = [value.hex() for *_, value in cases]
    modes = ["portable", "scheduled", "prefer", "stream", "stream-prefer", "threads-portable", "threads-prefer"]
    if args.native:
        modes += ["required", "stream-required", "threads-required"]
    if args.static:
        modes += ["static", "stream-static", "threads-static"]
    invalid = (
        "parallel128 0 - 0 - 0 8\n", "unknown 0 - 0 - 1 8\n",
        "parallel128 0 - 0 - 1 4096\n", "parallel128 1 80 0 - 1 8\n",
        "parallel128 0 - 0 - 1 18446744073709551615\n",
        "parallel128 0 - 0 - 1 184467440737095516160\n",
        "parallel128 0 - 0 - 1025 8\n",
    )
    with tempfile.TemporaryDirectory(prefix="brynja-parallel-execution-") as directory:
        environment = dict(os.environ, CARGO_TARGET_DIR=directory)
        for profile in ("debug", "release"):
            subprocess.run(["cargo", "build", "--locked", "--offline", "--manifest-path", str(oracle.MANIFEST),
                            "--features", "execution", *(["--release"] if profile == "release" else [])],
                           cwd=ROOT, env=environment, check=True, timeout=240)
            binary = Path(directory) / profile / ("brynja-parallelhash-differential-fixture.exe" if os.name == "nt" else "brynja-parallelhash-differential-fixture")
            for mode in modes:
                result = subprocess.run([str(binary), mode], input=request, text=True, capture_output=True,
                                        cwd=ROOT, env=environment, timeout=240)
                if result.returncode or result.stdout.splitlines() != expected:
                    raise ValueError(f"ParallelHash oracle mismatch/failure: {profile}/{mode}\n{result.stderr}")
                for malformed in invalid:
                    rejected = subprocess.run([str(binary), mode], input=malformed, text=True,
                                              capture_output=True, cwd=ROOT, env=environment, timeout=30)
                    if rejected.returncode == 0 or rejected.stdout or "panicked" in rejected.stderr:
                        raise ValueError(f"malformed execution request not cleanly rejected: {profile}/{mode}")
                print(f"ParallelHash execution oracle: PASS; profile={profile}; mode={mode}; cases={len(cases)}", flush=True)
    print("Required native routes: " + ("PASS" if args.native else "NOT REQUESTED; preferred routes may be portable"))
    print("Required static routes: " + ("PASS" if args.static else "NOT REQUESTED"))


if __name__ == "__main__":
    main()
