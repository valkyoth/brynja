#!/usr/bin/env python3
"""Bounded deterministic raw-stdin mutation and replay runner."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import assurance_policy as assurance
from assurance_process import run_bounded


def mutations(
    seed: bytes,
    maximum_cases: int,
    maximum_input_bytes: int,
) -> list[bytes]:
    if len(seed) > maximum_input_bytes:
        raise RuntimeError("seed exceeds policy input bound")
    cases: list[bytes] = []
    seen: set[bytes] = set()

    def add(case: bytes) -> bool:
        if len(case) > maximum_input_bytes:
            return True
        if case in seen or len(cases) >= maximum_cases:
            return len(cases) < maximum_cases
        seen.add(case)
        cases.append(case)
        return len(cases) < maximum_cases

    add(b"")
    add(seed)
    for end in range(len(seed)):
        if not add(seed[:end]):
            return cases
    for offset in range(len(seed)):
        if not add(seed[:offset] + seed[offset + 1 :]):
            return cases
    for offset, value in enumerate(seed):
        for bit in range(8):
            changed = value ^ (1 << bit)
            if not add(seed[:offset] + bytes([changed]) + seed[offset + 1 :]):
                return cases
    for inserted in (b"\x00", b"\xff"):
        for offset in range(len(seed) + 1):
            if not add(seed[:offset] + inserted + seed[offset:]):
                return cases
    return cases


def run_case(
    command: list[str],
    case: bytes,
    timeout_seconds: float,
    maximum_output: int,
) -> tuple[int, bytes, bytes]:
    result = run_bounded(command, case, timeout_seconds, maximum_output)
    return result.returncode, result.stdout, result.stderr


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", required=True)
    parser.add_argument("--replay-index", type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command:
        raise SystemExit("a target command is required after --")
    command = args.command[1:] if args.command[0] == "--" else args.command
    policy = assurance.read_policy()
    limits = policy["harness"]
    seed = Path(args.seed).read_bytes()
    if len(seed) > limits["maximum_input_bytes"]:
        raise SystemExit("seed exceeds policy input bound")
    cases = mutations(
        seed,
        limits["maximum_cases"],
        limits["maximum_input_bytes"],
    )
    if args.replay_index is not None:
        if args.replay_index < 0 or args.replay_index >= len(cases):
            raise SystemExit("replay index is outside the deterministic corpus")
        selected = [(args.replay_index, cases[args.replay_index])]
    else:
        selected = list(enumerate(cases))
    for index, case in selected:
        returncode, _, _ = run_case(
            command,
            case,
            limits["timeout_milliseconds"] / 1000,
            limits["maximum_output_bytes"],
        )
        if returncode != 0:
            digest = hashlib.sha256(case).hexdigest()
            raise SystemExit(f"mutation failure index={index} sha256={digest}")
    print(
        json.dumps(
            {
                "algorithm": policy["mutation"]["algorithm"],
                "cases": len(selected),
                "seed_sha256": hashlib.sha256(seed).hexdigest(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
