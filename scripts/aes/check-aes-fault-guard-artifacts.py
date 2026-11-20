#!/usr/bin/env python3
"""Replay the core guard leaf on two exact local test ELFs; NOT AES qualification."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


HERE = Path(__file__).resolve().parent
RECORD = HERE.parents[1] / "assurance/aes-fault-guard-artifacts.json"
SPEC = importlib.util.spec_from_file_location(
    "guard_leaf", HERE / "check-aes-fault-guard.py")
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)
PINNED = {
    "81e0e0314777d789bcf308b163ef99c2bc6ccf6d3f7b5049fb3bf46e6822bc05",
    "5d2319bf3bbfa95efec231e079669bb1dcb0bed8bb84e73c0fdf8e6c134cea34",
}


def inspect(path):
    path = path.resolve(strict=True)
    raw = path.read_bytes()
    if raw[:6] != b"\x7fELF\x02\x01" or raw[18:20] != b"\x3e\x00":
        raise ValueError("not an x86-64 little-endian ELF")
    digest = hashlib.sha256(raw).hexdigest()
    if digest not in PINNED:
        raise ValueError("unreviewed guard test ELF")
    return path, digest


def validate_result(result, digest):
    if (type(result) is not dict or result.get("binary_sha256") != digest or
            type(result.get("observations")) is not list or
            len(result["observations"]) != len(GUARD.CASES) or
            {row.get("case") for row in result["observations"]
             if type(row) is dict} != set(GUARD.CASES)):
        raise ValueError("guard case population incomplete")


def check_record():
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate guard record field")
            result[key] = value
        return result

    record = json.loads(RECORD.read_text(encoding="utf-8"),
                        object_pairs_hook=no_duplicates)
    if type(record) is not dict:
        raise ValueError("guard artifact record drift")
    artifacts = record.get("artifacts")
    if (set(record) != {"schema", "status", "qualification", "runner", "test",
                        "artifacts", "limits"} or
            record["schema"] != 1 or
            record["status"] != "core-guard-leaf-development-only" or
            record["qualification"] != "none" or
            record["runner"] != "scripts/aes/check-aes-fault-guard-artifacts.py" or
            record["test"] != GUARD.TEST or
            type(artifacts) is not list or len(artifacts) != 2 or
            any(type(row) is not dict or set(row) != {"binary_sha256", "leaf_cases_passed"}
                for row in artifacts) or
            {row["binary_sha256"] for row in artifacts} != PINNED or
            any(row["leaf_cases_passed"] != len(GUARD.CASES) for row in artifacts) or
            type(record["limits"]) is not list or not record["limits"]):
        raise ValueError("guard artifact record drift")


def replay(paths):
    selected = [inspect(path) for path in paths]
    if {digest for _, digest in selected} != PINNED:
        raise ValueError("both distinct guard artifacts required")
    check_record()
    observations = []
    for path, digest in selected:
        listed = subprocess.run([str(path), "--list"], capture_output=True,
                                text=True, check=True, timeout=30)
        if GUARD.TEST not in listed.stdout:
            raise ValueError("guard fixture absent from pinned artifact")
        run = subprocess.run([sys.executable, str(HERE / "check-aes-fault-guard.py"),
                              "--binary", str(path)], capture_output=True, text=True,
                             check=True, timeout=90)
        lines = run.stdout.splitlines()
        if len(lines) != 2 or lines[1] != (
                "DEVELOPMENT_GUARD_EXPERIMENT_OBSERVED; NOT AES C1/DC1 or release qualification"):
            raise ValueError("guard completion marker missing")
        result = json.loads(lines[0])
        validate_result(result, digest)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("guard artifact changed during replay")
        observations.append(digest)
    return observations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, action="append")
    args = parser.parse_args()
    try:
        if len(args.binary) != 2:
            raise ValueError("exactly two guard test ELFs required")
        replay(args.binary)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Pinned guard replay incomplete; no qualification.", file=sys.stderr)
        return 2
    print("Pinned core guard replay: 14/14 leaf cases passed across two test ELFs.")
    print("LEAF_ONLY; AES caller C1/DC1 and release qualification remain OPEN.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
