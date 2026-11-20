#!/usr/bin/env python3
"""Replay selected native fault workbench scripts on two exact test ELFs.

This is a development regression sweep, NOT full fault-model qualification.
It suppresses subprocess output and prints only bounded status, never fixture bytes.
"""
import argparse
import hashlib
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = Path(__file__).resolve().parent
PINNED = {
    "a11c368e8eccec0e497d336ebe6a9de6381a01dfd3716887c8d69b84efa69c26": "1.90.0",
    "bf61f409964ce7678b2a5694e63a5640d4b0a320c76d76866b25c9e95a307baf": "1.100.0",
}
PATHS = ("public", "encrypt", "decrypt")
OWNERS = ("cached", "ephemeral")
OWNER_PATH_SCRIPTS = (
    "check-aes-fault-cached.py",
    "check-aes-fault-retained.py",
    "check-aes-fault-completion.py",
    "check-aes-fault-round-skip.py",
    "check-aes-fault-primary-output.py",
)
FULL_SCRIPTS = (
    "check-aes-fault-import-use.py",
    "check-aes-fault-copy-store.py",
    "check-aes-fault-lifecycle-complete.py",
)
COMPACT_JOBS = (
    ("check-aes-fault-completion.py", ("--owner", "cached", "--path", "encrypt")),
    ("check-aes-fault-round-skip.py", ("--owner", "ephemeral", "--path", "decrypt")),
    ("check-aes-fault-primary-output.py", ("--owner", "cached", "--path", "public", "--byte", "0")),
    ("check-aes-fault-outer-completion.py", ("--path", "decrypt")),
    ("check-aes-fault-transaction.py", ("--path", "public")),
    ("check-aes-fault-transaction.py", ("--path", "secret")),
    ("check-aes-fault-permit.py", ("--path", "public")),
    ("check-aes-fault-permit.py", ("--path", "secret")),
)
COMPLEMENTARY_JOBS = (
    ("check-aes-fault-cached.py", ("--owner", "ephemeral", "--path", "public")),
    ("check-aes-fault-retained.py", ("--owner", "cached", "--path", "decrypt")),
    ("check-aes-fault-completion.py", ("--owner", "ephemeral", "--path", "decrypt")),
    ("check-aes-fault-round-skip.py", ("--owner", "cached", "--path", "public")),
    ("check-aes-fault-primary-output.py", ("--owner", "ephemeral", "--path", "encrypt", "--byte", "15")),
    ("check-aes-fault-outer-completion.py", ("--path", "public")),
)


def job_label(script, dimensions):
    name = script.removeprefix("check-aes-fault-").removesuffix(".py")
    values = []
    for index in range(0, len(dimensions), 2):
        flag, value = dimensions[index:index + 2]
        if flag == "--byte":
            value = "byte-" + value
        elif value == "ephemeral":
            value = "operation-local"
        values.append(value)
    return "/".join([name, *values])


def jobs(binary, profile):
    if profile == "compact":
        for script, dimensions in COMPACT_JOBS:
            yield script, ("--binary", str(binary), *dimensions)
        return
    if profile == "complementary":
        for script, dimensions in COMPLEMENTARY_JOBS:
            yield script, ("--binary", str(binary), *dimensions)
        return
    if profile == "owner-path-matrix":
        for script in OWNER_PATH_SCRIPTS:
            for owner in OWNERS:
                for path in PATHS:
                    if script == "check-aes-fault-primary-output.py":
                        for byte in (0, 15):
                            yield script, ("--binary", str(binary), "--owner", owner,
                                           "--path", path, "--byte", str(byte))
                    else:
                        yield script, ("--binary", str(binary), "--owner", owner,
                                       "--path", path)
        return
    if profile != "all-existing":
        raise ValueError("unknown sweep profile")
    for script in FULL_SCRIPTS:
        yield script, ("--binary", str(binary))
    for script in OWNER_PATH_SCRIPTS:
        for owner in OWNERS:
            for path in PATHS:
                yield script, ("--binary", str(binary), "--owner", owner, "--path", path)
    for path in PATHS:
        yield "check-aes-fault-outer-completion.py", ("--binary", str(binary), "--path", path)
    for path in ("public", "secret"):
        for script in ("check-aes-fault-transaction.py", "check-aes-fault-permit.py"):
            yield script, ("--binary", str(binary), "--path", path)


def inspect_binary(path):
    path = path.resolve(strict=True)
    raw = path.read_bytes()
    if raw[:6] != b"\x7fELF\x02\x01" or raw[18:20] != b"\x3e\x00":
        raise ValueError("not an x86-64 little-endian ELF")
    digest = hashlib.sha256(raw).hexdigest()
    if digest not in PINNED:
        raise ValueError("unreviewed test ELF")
    return path, digest


def sweep(paths, timeout=180, profile="compact"):
    selected = [inspect_binary(path) for path in paths]
    if {digest for _, digest in selected} != set(PINNED):
        raise ValueError("require both distinct pinned artifacts")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    selected_scripts = (script for script, _ in jobs(selected[0][0], profile))
    for script in selected_scripts:
        if not (SCRIPTS / script).is_file():
            raise ValueError("missing native probe: " + script)
    outcomes = []
    for binary, digest in selected:
        for script, args in jobs(binary, profile):
            run = subprocess.run([sys.executable, str(SCRIPTS / script), *args],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 timeout=timeout, check=False)
            dimensions = tuple(args[index + 1] for index, value in enumerate(args[:-1])
                               if value in ("--owner", "--path"))
            outcomes.append((PINNED[digest], script, dimensions, run.returncode))
    return outcomes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, action="append")
    parser.add_argument("--profile", choices=("compact", "complementary", "owner-path-matrix", "all-existing"), default="compact")
    args = parser.parse_args()
    try:
        if len(args.binary) != 2:
            raise ValueError("exactly two pinned artifacts required")
        outcomes = sweep(args.binary, profile=args.profile)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, ValueError) else type(error).__name__
        print("Native development sweep incomplete: " + detail, file=sys.stderr)
        return 2
    failures = [row for row in outcomes if row[3] != 0]
    print(f"Native development sweep: {len(outcomes) - len(failures)}/{len(outcomes)} script invocations passed.")
    for version, script, dimensions, code in failures[:8]:
        print(f"FAILED: Rust {version}, {script}, {dimensions}, exit {code}.")
    if len(failures) > 8:
        print(f"Additional failures: {len(failures) - 8} (details suppressed).")
    print("DEVELOPMENT_SWEEP_ONLY; no whole-model or release qualification.")
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
