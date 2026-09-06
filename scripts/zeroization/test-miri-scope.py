#!/usr/bin/env python3
"""Regression tests for stage-aware Miri scope selection."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import miri_scope


def expect(paths: list[str], *, full: bool, groups: tuple[str, ...]) -> None:
    assert miri_scope.select(paths) == (full, groups)


def run_profile(*arguments: str) -> tuple[int, list[str]]:
    with tempfile.TemporaryDirectory(prefix="brynja-miri-profile-") as temporary:
        root = Path(temporary)
        binary = root / "cargo"
        trace = root / "trace"
        binary.write_text(
            "#!/bin/sh\n"
            "printf '%s\\t%s\\n' \"$CARGO_TARGET_DIR\" \"$*\" "
            '>> \"$BRYNJA_MIRI_TRACE\"\n',
            encoding="utf-8",
        )
        binary.chmod(0o700)
        environment = os.environ.copy()
        environment["PATH"] = f"{root}:{environment['PATH']}"
        environment["BRYNJA_MIRI_TRACE"] = str(trace)
        result = subprocess.run(
            [str(miri_scope.ROOT / "scripts/zeroization/check-zeroization-miri.sh"), *arguments],
            cwd=miri_scope.ROOT,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        lines = trace.read_text(encoding="utf-8").splitlines() if trace.exists() else []
        commands = []
        targets = set()
        for line in lines:
            target, command = line.split("\t", 1)
            assert target
            targets.add(target)
            commands.append(command)
            arguments = command.split()
            if "--" in arguments:
                assert arguments.index("--target") < arguments.index("--")
        assert len(targets) <= 1
        return result.returncode, commands


def main() -> int:
    miri_scope.validate_repository()
    expect(["docs/current-status.md"], full=False, groups=())
    expect(
        ["crates/brynja-hash-sha2/src/lib.rs"],
        full=False,
        groups=("sha2",),
    )
    expect(
        ["crates/brynja-hash-sha3/src/sponge.rs"],
        full=False,
        groups=("sha3", "kmac", "tuplehash", "parallelhash"),
    )
    expect(
        ["crates/brynja-hash-core/src/lib.rs"],
        full=False,
        groups=("md5", "sha1", "sha2", "sha3", "kmac", "tuplehash", "parallelhash", "legacy"),
    )
    expect(
        ["crates/brynja-core/src/secret_memory.rs"],
        full=False,
        groups=miri_scope.GROUPS,
    )
    expect(
        ["crates/brynja-sanitization/src/lib.rs"],
        full=False,
        groups=("sanitization",),
    )
    expect(["crates/brynja-legacy-sha1/src/lib.rs"], full=False, groups=("sha1", "legacy"))
    expect(["crates/brynja-legacy-md5/src/lib.rs"], full=False, groups=("md5", "legacy"))
    expect(["assurance/legacy-hash-public-api/src/lib.rs"], full=False, groups=("legacy",))
    expect(["crates/unknown/src/lib.rs"], full=True, groups=miri_scope.GROUPS)
    expect(["Cargo.lock"], full=True, groups=miri_scope.GROUPS)
    expect(
        ["scripts/zeroization/check-zeroization-miri.sh"],
        full=True,
        groups=miri_scope.GROUPS,
    )
    expect(["../escape"], full=True, groups=miri_scope.GROUPS)

    status, commands = run_profile("--focused")
    assert status == 0 and len(commands) == 10
    assert sum('secret_output_is_cleared_when_ownership_ends' in c for c in commands) == 1
    assert sum('abandoned_or_incomplete_items_fail_closed' in c for c in commands) == 1
    status, commands = run_profile(
        "--focused", "sha3", "kmac", "tuplehash", "parallelhash"
    )
    assert status == 0 and len(commands) == 19
    assert sum("-p brynja-hash-sha3" in command for command in commands) == 9
    assert sum("-p brynja-mac-kmac" in command for command in commands) == 1
    assert sum("-p brynja-hash-tuple" in command for command in commands) == 2
    assert sum("-p brynja-hash-parallel" in command for command in commands) == 1
    status, commands = run_profile("--group", "sha2")
    assert status == 0 and len(commands) == 10
    assert all("brynja-hash-sha2" in command for command in commands)
    status, commands = run_profile("--full")
    assert status == 0 and len(commands) == 30
    status, commands = run_profile("--group", "unknown")
    assert status == 2 and not commands
    print(
        "Miri scope rejects global drift and validates focused, full, and shard execution"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
