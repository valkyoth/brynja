#!/usr/bin/env python3
"""Reject tracked files beneath Cargo target directories."""

from __future__ import annotations

import subprocess
from pathlib import Path, PurePosixPath


class TrackedBuildArtifactError(RuntimeError):
    """The repository tracks generated Cargo build output."""


def validate_paths(paths: list[str]) -> None:
    artifacts = sorted(
        path
        for path in paths
        if "target" in PurePosixPath(path).parts[:-1]
    )
    if artifacts:
        preview = "\n".join(f"- {path}" for path in artifacts[:20])
        remainder = len(artifacts) - 20
        suffix = f"\n- ... and {remainder} more" if remainder > 0 else ""
        raise TrackedBuildArtifactError(
            "tracked Cargo target artifacts are forbidden:\n"
            f"{preview}{suffix}"
        )


def tracked_paths(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    )
    return [
        entry.decode("utf-8", errors="surrogateescape")
        for entry in result.stdout.split(b"\0")
        if entry
    ]


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    try:
        validate_paths(tracked_paths(root))
    except (OSError, subprocess.CalledProcessError, TrackedBuildArtifactError) as error:
        print(error)
        return 1
    print("tracked Cargo build-artifact policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
