#!/usr/bin/env python3
"""Run one inventory-bound Miri command, with live progress and nonzero coverage.

Build/sysroot caches are per frozen checkout (and hence per detached shard).
Evidence lives outside target/. No Miri safety checks are disabled.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import tomllib

import miri_tasks

TOOLCHAIN = "nightly-2026-09-11"
TARGET = "x86_64-unknown-linux-gnu"
PROGRESS = "-Zmiri-report-progress=10000000"
SUMMARY = re.compile(r"^test result: ok\. (\d+) passed; 0 failed; (\d+) ignored;")


def environment(root: Path) -> dict:
    env = dict(os.environ)
    if any(name.startswith("BRYNJA_MIRI_") and value for name, value in env.items()):
        raise ValueError("clear inherited Miri case/profile selectors")
    for name in ("MIRIFLAGS", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS",
                 "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR", "MIRI_SYSROOT", "MIRI_BE_RUSTC",
                 "MIRI_REPLACE_LIBRS_IF_NOT_TEST", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
        if env.get(name):
            raise ValueError("clear Miri task environment override: " + name)
    # The interpreter's progress count is diagnostic, never a completion proof.
    env["MIRIFLAGS"] = PROGRESS
    env["CARGO_TARGET_DIR"] = str(root / "target/miri-tasks")
    env["XDG_CACHE_HOME"] = str(root / "target/miri-cache")
    env["RUSTUP_AUTO_INSTALL"] = "0"
    return env


def stream(command: list[str], root: Path, env: dict, expected: str | None = None) -> tuple[int, int]:
    passed, pending, markers = 0, b"", 0
    with subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as child:
        try:
            while chunk := child.stdout.read1(65536):
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
                pending += chunk
                lines = pending.split(b"\n")
                pending = lines.pop()
                for line in lines:
                    text = line.decode("utf-8", errors="replace").rstrip("\r")
                    if text == expected:
                        markers += 1
                    match = SUMMARY.match(text)
                    if match:
                        passed += int(match[1])
                if len(pending) > 65536:
                    raise ValueError("oversized Miri output line")
            code = child.wait()
            if expected is not None and (markers != 1 or passed != 1):
                raise ValueError("Miri case coverage marker/test count missing or duplicated")
            return code, passed
        except BaseException:
            child.kill()
            child.wait()
            raise


def case_environment(root: Path, task: dict) -> dict:
    env = environment(root)
    # Cargo-Miri caches the compiler launch environment. Runtime selectors must
    # be explicit interpreter inputs, not option_env! in that cached environment.
    for key, value in task["environment"].items():
        if key not in {"BRYNJA_MIRI_CASE", "BRYNJA_MIRI_PROFILE"} or not re.fullmatch(r"[a-z0-9-]+", value):
            raise ValueError("invalid Miri case environment")
        env["MIRIFLAGS"] += f" -Zmiri-env-set={key}={value}"
    return env


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", required=True, choices=miri_tasks.miri_scope.GROUPS)
    parser.add_argument("--task", required=True, type=int)
    parser.add_argument("--profile", choices=miri_tasks.miri_cases.PROFILES, default="existing-full")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    tools = tomllib.loads((root / "assurance/policy.toml").read_text())["tools"]
    pinned = [tool["execution_toolchain"] for tool in tools if tool["id"] == "miri"]
    if pinned != [TOOLCHAIN]:
        raise ValueError("Miri task compiler differs from assurance policy")
    tasks = miri_tasks.task_inventory(root, args.group, args.profile)
    if not 0 <= args.task < len(tasks):
        raise ValueError("Miri task outside inventory")
    task = tasks[args.task]
    env = case_environment(root, task)
    command = ["cargo", "+" + TOOLCHAIN, "miri", "test", "--locked", "--offline",
               "--target", TARGET, *task["argv"]]
    # The test harness must expose test names/output as work completes.
    if "--" not in command:
        command.append("--")
    command += ["--nocapture"]
    started = time.monotonic()
    print("MIRI_TASK_START " + json.dumps({"group": args.group, "task": args.task,
          "argv": command, "profile": args.profile, "case": task["environment"]}), flush=True)
    code, passed = stream(command, root, env, task["marker"])
    if code != 0 or passed == 0:
        raise ValueError(f"Miri task failed or ran zero tests: exit={code}, passed={passed}")
    print("MIRI_TASK_PASS " + json.dumps({"group": args.group, "task": args.task,
          "passed": passed, "elapsed_seconds": time.monotonic() - started}), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("Miri task rejected: " + str(error), file=sys.stderr)
        raise SystemExit(1)
