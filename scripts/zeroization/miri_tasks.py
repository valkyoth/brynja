"""Expose the existing Miri command coverage as independently schedulable tasks.

The shell inventory supplies the original commands. The case catalog explicitly
decomposes selected matrices for routine/extended profiles. Listing performs no
Cargo execution; unregistered commands retain their original selections.
"""
from __future__ import annotations

import functools
import hashlib
import re
import shlex
from pathlib import Path

import miri_scope
import miri_cases

RUNNER = "scripts/zeroization/run-miri-task.py"


def inventory(root: Path, group: str) -> list[list[str]]:
    digest = hashlib.sha256((root / "scripts/zeroization/check-zeroization-miri.sh").read_bytes()).hexdigest()
    # Return fresh lists: no caller can change another validation's inventory.
    return [list(argv) for argv in _inventory(root, group, digest)]


@functools.lru_cache(maxsize=128)
def _inventory(root: Path, group: str, digest: str) -> tuple[tuple[str, ...], ...]:
    if group not in miri_scope.GROUPS:
        raise ValueError("unknown Miri task group")
    raw = (root / "scripts/zeroization/check-zeroization-miri.sh").read_bytes()
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("oversized or changing Miri command inventory")
    source = raw.decode("utf-8").replace("\r\n", "\n")
    matches = re.findall(r"^full_" + group + r"\(\) \{\n(.*?)^\}\n", source, re.M | re.S)
    if len(matches) != 1:
        raise ValueError("missing or ambiguous Miri group body")
    commands = parse(matches[0])
    if not 1 <= len(commands) <= 256:
        raise ValueError("empty or oversized Miri command inventory")
    for argv in commands:
        if (not isinstance(argv, list) or not argv
                or any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in argv)):
            raise ValueError("invalid Miri task command")
    return tuple(tuple(argv) for argv in commands)


def parse(body: str, variables: dict[str, str] | None = None) -> list[list[str]]:
    """A deliberately small grammar, NOT a permissive shell interpreter.

    Any future conditional, helper, substitution or unknown command must be
    reviewed before tasks can be planned. No shell code is executed to list.
    """
    variables = variables or {}
    lines = [line.strip() for line in body.replace("\\\n", " ").splitlines()]
    commands, index = [], 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if not line or line.startswith("#"):
            continue
        loop = re.fullmatch(r"for ([a-z_][a-z0-9_]*) in ([a-z0-9_ ]+); do", line)
        if loop:
            begin = index
            while index < len(lines) and lines[index] != "done":
                if lines[index].startswith("for "):
                    raise ValueError("nested Miri inventory loop requires review")
                index += 1
            if index == len(lines):
                raise ValueError("unterminated Miri inventory loop")
            for value in loop[2].split():
                commands.extend(parse("\n".join(lines[begin:index]), {**variables, loop[1]: value}))
            index += 1
            continue
        tokens = shlex.split(line, comments=True)
        if not tokens or tokens.pop(0) != "run_miri" or not tokens:
            raise ValueError("unrecognized Miri inventory command")
        argv = [variables.get(token[1:], token) if token.startswith("$") else token for token in tokens]
        if any(any(symbol in token for symbol in ("$", "`", ";", "|", "&", ">", "<", "*", "?", "[", "]", "{", "}", "~", "(", ")")) for token in argv):
            raise ValueError("unreviewed Miri shell expansion or control flow")
        commands.append(argv)
    return commands


def task_inventory(root: Path, group: str, profile: str) -> list[dict]:
    return miri_cases.tasks(group, inventory(root, group), profile)


def commands(root: Path, groups: list[str], profile: str = "existing-full") -> list[list[str]]:
    suffix = [] if profile == "existing-full" else ["--profile", profile]
    return [["python3", RUNNER, "--group", group, "--task", str(index), *suffix]
            for group in groups for index, _ in enumerate(task_inventory(root, group, profile))]
