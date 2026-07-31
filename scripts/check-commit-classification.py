#!/usr/bin/env python3
"""Enforce prospective security commit-subject classification."""

from __future__ import annotations

import re
import subprocess
import sys


TIMEOUT_SECONDS = 30
FIX_SUBJECT = re.compile(r"^fix(?:\([^)]*\))?:", re.IGNORECASE)
PENTEST_REMEDIATION = re.compile(
    r"(?:pentest.*(?:fix|gap|remediat)|(?:fix|close|remediat).*pentest)",
    re.IGNORECASE,
)


class ClassificationError(RuntimeError):
    """A commit subject implies Rust remediation without changing Rust."""


def validate(subject: str, paths: tuple[str, ...]) -> None:
    restricted = FIX_SUBJECT.search(subject) or PENTEST_REMEDIATION.search(subject)
    rust_changed = any(
        path.startswith("crates/") and path.endswith(".rs") for path in paths
    )
    if restricted and not rust_changed:
        raise ClassificationError(
            "fix/pentest-remediation subject requires a crates/**/*.rs change; "
            "use docs:, chore(scope):, or test(scope):"
        )


def git_output(arguments: list[str]) -> str:
    return subprocess.check_output(
        ["git", *arguments],
        text=True,
        timeout=TIMEOUT_SECONDS,
    ).strip()


def main() -> int:
    if len(sys.argv) != 1:
        print("usage: check-commit-classification.py", file=sys.stderr)
        return 2
    try:
        subject = git_output(["show", "-s", "--format=%s", "HEAD"])
        paths = tuple(
            git_output(
                ["diff-tree", "--root", "--no-commit-id", "--name-only", "-r", "HEAD"]
            ).splitlines()
        )
        validate(subject, paths)
    except (ClassificationError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        return 1
    print("security commit classification: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
