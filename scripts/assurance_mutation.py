#!/usr/bin/env python3
"""Bounded deterministic raw-stdin mutation and replay runner."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Iterator
from pathlib import Path

import assurance_policy as assurance
from assurance_io import read_bounded_regular
from assurance_process import run_bounded
from assurance_process_tree import EXTERNAL_POSIX_CONTAINMENT, WINDOWS_JOB_OBJECT


def mutation_cases(
    seed: bytes,
    maximum_cases: int,
    maximum_input_bytes: int,
) -> Iterator[bytes]:
    if len(seed) > maximum_input_bytes:
        raise RuntimeError("seed exceeds policy input bound")
    if maximum_cases < 1:
        raise RuntimeError("case bound must be positive")
    produced = 0

    def emit(case: bytes) -> bool:
        nonlocal produced
        if len(case) > maximum_input_bytes or produced >= maximum_cases:
            return False
        produced += 1
        return True

    if emit(b""):
        yield b""
    if seed and emit(seed):
        yield seed
    for end in range(1, len(seed)):
        case = seed[:end]
        if not emit(case):
            return
        yield case
    previous_deletion = seed[:-1]
    for offset in range(len(seed)):
        case = seed[:offset] + seed[offset + 1 :]
        if case == seed[:-1] or case == previous_deletion:
            previous_deletion = case
            continue
        previous_deletion = case
        if not emit(case):
            return
        yield case
    for offset, value in enumerate(seed):
        for bit in range(8):
            changed = value ^ (1 << bit)
            case = seed[:offset] + bytes([changed]) + seed[offset + 1 :]
            if not emit(case):
                return
            yield case
    for inserted in (b"\x00", b"\xff"):
        previous_insertion = None
        for offset in range(len(seed) + 1):
            case = seed[:offset] + inserted + seed[offset:]
            if case == previous_insertion:
                continue
            previous_insertion = case
            if len(case) > maximum_input_bytes:
                continue
            if not emit(case):
                return
            yield case


def mutations(
    seed: bytes,
    maximum_cases: int,
    maximum_input_bytes: int,
) -> list[bytes]:
    """Collect cases for focused tests; the command runner streams them."""
    return list(mutation_cases(seed, maximum_cases, maximum_input_bytes))


def run_case(
    command: list[str],
    case: bytes,
    timeout_seconds: float,
    maximum_output: int,
    tree_containment: str | None,
) -> tuple[int, bytes, bytes]:
    result = run_bounded(
        command,
        case,
        timeout_seconds,
        maximum_output,
        tree_containment,
    )
    return result.returncode, result.stdout, result.stderr


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", required=True)
    parser.add_argument("--replay-index", type=int)
    parser.add_argument(
        "--tree-containment",
        choices=sorted((*EXTERNAL_POSIX_CONTAINMENT, WINDOWS_JOB_OBJECT)),
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command:
        raise SystemExit("a target command is required after --")
    command = args.command[1:] if args.command[0] == "--" else args.command
    policy = assurance.read_policy()
    limits = policy["harness"]
    try:
        seed = read_bounded_regular(
            Path(args.seed),
            limits["maximum_input_bytes"],
        )
    except RuntimeError as error:
        raise SystemExit(str(error)) from error
    if args.replay_index is not None and args.replay_index < 0:
        raise SystemExit("replay index is outside the deterministic corpus")
    selected = 0
    replay_found = False
    cases = mutation_cases(
        seed,
        limits["maximum_cases"],
        limits["maximum_input_bytes"],
    )
    for index, case in enumerate(cases):
        if args.replay_index is not None and index != args.replay_index:
            continue
        replay_found = True
        returncode, _, _ = run_case(
            command,
            case,
            limits["timeout_milliseconds"] / 1000,
            limits["maximum_output_bytes"],
            args.tree_containment,
        )
        if returncode != 0:
            digest = hashlib.sha256(case).hexdigest()
            raise SystemExit(f"mutation failure index={index} sha256={digest}")
        selected += 1
        if args.replay_index is not None:
            break
    if args.replay_index is not None and not replay_found:
        raise SystemExit("replay index is outside the deterministic corpus")
    print(
        json.dumps(
            {
                "algorithm": policy["mutation"]["algorithm"],
                "cases": selected,
                "seed_sha256": hashlib.sha256(seed).hexdigest(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
