#!/usr/bin/env python3
"""Bounded external-process differential runner for raw byte cases."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
from collections.abc import Iterable
from pathlib import Path

import assurance_policy as assurance
from assurance_io import iter_bounded_corpus
from assurance_process import run_bounded
from assurance_process_tree import EXTERNAL_POSIX_CONTAINMENT, WINDOWS_JOB_OBJECT


CLASSES = {"accept", "reject", "unsupported"}


def parse_result(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
        value = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("adapter result is not UTF-8 JSON") from error
    if not isinstance(value, dict) or set(value) != {"class", "output"}:
        raise RuntimeError("adapter result fields drifted")
    if value["class"] not in CLASSES:
        raise RuntimeError("adapter result class is invalid")
    output = value["output"]
    if (
        not isinstance(output, str)
        or len(output) % 2 != 0
        or output.lower() != output
        or any(character not in "0123456789abcdef" for character in output)
    ):
        raise RuntimeError("adapter output is not canonical lowercase hex")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if text != canonical:
        raise RuntimeError("adapter result is not canonical JSON")
    return value


def run_adapter(
    command: list[str],
    case: bytes,
    timeout_seconds: float,
    maximum_output: int,
    tree_containment: str | None,
    *,
    allow_test_only_containment: bool = False,
) -> dict[str, str]:
    result = run_bounded(
        command,
        case,
        timeout_seconds,
        maximum_output,
        tree_containment,
        allow_test_only_containment=allow_test_only_containment,
    )
    if result.returncode != 0:
        raise RuntimeError("differential adapter failed")
    return parse_result(result.stdout)


def compare(
    commands: list[list[str]],
    cases: Iterable[bytes],
    timeout_seconds: float,
    maximum_output: int,
    tree_containment: str | None,
    *,
    allow_test_only_containment: bool = False,
) -> int:
    if len(commands) < 2 or len({tuple(command) for command in commands}) < 2:
        raise RuntimeError("differential run requires two distinct adapters")
    compared = 0
    for case in cases:
        results = [
            run_adapter(
                command,
                case,
                timeout_seconds,
                maximum_output,
                tree_containment,
                allow_test_only_containment=allow_test_only_containment,
            )
            for command in commands
        ]
        if any(result != results[0] for result in results[1:]):
            digest = hashlib.sha256(case).hexdigest()
            raise RuntimeError(f"differential mismatch sha256={digest}")
        compared += 1
    if compared == 0:
        raise RuntimeError("differential run requires at least one case")
    return compared


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", required=True)
    parser.add_argument("--adapter", action="append", required=True)
    parser.add_argument(
        "--tree-containment",
        choices=sorted((*EXTERNAL_POSIX_CONTAINMENT, WINDOWS_JOB_OBJECT)),
    )
    args = parser.parse_args()
    policy = assurance.read_policy()
    limits = policy["harness"]
    commands = [shlex.split(command) for command in args.adapter]
    if any(not command for command in commands):
        raise SystemExit("adapter command cannot be empty")
    root = Path(args.cases)
    try:
        cases = iter_bounded_corpus(
            root,
            limits["maximum_cases"],
            limits["maximum_input_bytes"],
        )
        count = compare(
            commands,
            cases,
            limits["timeout_milliseconds"] / 1000,
            limits["maximum_output_bytes"],
            args.tree_containment,
        )
    except RuntimeError as error:
        raise SystemExit(str(error)) from error
    print(
        json.dumps(
            {"adapters": len(commands), "cases": count},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
