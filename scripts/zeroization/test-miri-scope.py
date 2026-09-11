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


def run_profile(*arguments: str, fail_match: str = "") -> tuple[int, list[str]]:
    with tempfile.TemporaryDirectory(prefix="brynja-miri-profile-") as temporary:
        root = Path(temporary)
        binary = root / "cargo"
        trace = root / "trace"
        binary.write_text(
            "#!/bin/sh\n"
            "printf '%s\\t%s\\n' \"$CARGO_TARGET_DIR\" \"$*\" "
            '>> \"$BRYNJA_MIRI_TRACE\"\n'
            'if test -n "$BRYNJA_MIRI_FAIL"; then\n'
            '    case "$*" in *"$BRYNJA_MIRI_FAIL"*) exit 42;; esac\n'
            'fi\n',
            encoding="utf-8",
        )
        binary.chmod(0o700)
        environment = os.environ.copy()
        environment["PATH"] = f"{root}:{environment['PATH']}"
        environment["BRYNJA_MIRI_TRACE"] = str(trace)
        environment["BRYNJA_MIRI_FAIL"] = fail_match
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
    expect(["assurance/general-sha512-t/src/acceptance.rs"], full=False, groups=("sha2",))
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
        groups=tuple(group for group in miri_scope.GROUPS if group not in ("acceleration", "static_cpu")),
    )
    expect(
        ["crates/brynja-sanitization/src/lib.rs"],
        full=False,
        groups=("sanitization",),
    )
    expect(["crates/brynja-legacy-sha1/src/lib.rs"], full=False, groups=("sha1", "legacy"))
    expect(["crates/brynja-legacy-md5/src/lib.rs"], full=False, groups=("md5", "legacy"))
    expect(["assurance/legacy-hash-public-api/src/lib.rs"], full=False, groups=("legacy",))
    expect(["assurance/legacy-hash-final/src/lib.rs"], full=False, groups=("legacy",))
    expect(["assurance/acceleration-contract/src/lib.rs"], full=False, groups=("acceleration",))
    cpu_groups = ("sha2", "sha3", "kmac", "tuplehash", "parallelhash", "static_cpu")
    expect(["assurance/static-cpu-execution/src/lib.rs"], full=False, groups=cpu_groups)
    expect(["crates/brynja-crypto-cpu/src/static_execution/mod.rs"], full=False, groups=cpu_groups)
    expect(["crates/brynja-crypto-cpu/src/x86_sha.rs"], full=False, groups=cpu_groups)
    expect(["crates/unknown/src/lib.rs"], full=True, groups=miri_scope.GROUPS)
    expect(["Cargo.lock"], full=True, groups=miri_scope.GROUPS)
    expect(
        ["scripts/zeroization/check-zeroization-miri.sh"],
        full=True,
        groups=miri_scope.GROUPS,
    )
    expect(["../escape"], full=True, groups=miri_scope.GROUPS)

    status, commands = run_profile("--focused")
    assert status == 0 and len(commands) == 12
    assert sum('public_model_never_activates_current_kernels' in c for c in commands) == 1
    status, focused = run_profile("--focused", "acceleration")
    assert status == 0 and len(focused) == 12
    assert sum(c.endswith('assurance/acceleration-contract/Cargo.toml --lib') for c in focused) == 1
    assert not any('public_model_never_activates_current_kernels' in c for c in focused)
    assert [c for c in commands if 'acceleration-contract' not in c] == [
        c for c in focused if 'acceleration-contract' not in c]
    assert sum('secret_output_is_cleared_when_ownership_ends' in c for c in commands) == 1
    assert sum('abandoned_or_incomplete_items_fail_closed' in c for c in commands) == 1
    status, commands = run_profile(
        "--focused", "sha3", "kmac", "tuplehash", "parallelhash"
    )
    assert status == 0 and len(commands) == 31
    assert sum('hardened_execution::keccak::tests::all_seven_regions_clear' in c for c in commands) == 1
    assert sum('hardened::accelerated::engine::tests::every_memory_region_is_explicitly_cleared' in c for c in commands) == 1
    assert sum('--features sponge-execution --lib sponge::tests::portable_sponge' in c for c in commands) == 1
    assert any('--features static-execution --lib execution' in command for command in commands)
    assert any('--features static-execution --test execution execution_smoke' in command for command in commands)
    assert sum("-p brynja-hash-sha3" in command for command in commands) == 13
    assert sum("-p brynja-mac-kmac" in command for command in commands) == 3
    assert sum('--features hardened-execution --lib execution' in c and 'brynja-mac-kmac' in c for c in commands) == 1
    assert sum('--features hardened-execution --test execution' in c and 'brynja-mac-kmac' in c for c in commands) == 1
    assert sum("-p brynja-hash-tuple" in command for command in commands) == 4
    assert sum('--features hardened-execution --lib execution' in c and 'brynja-hash-tuple' in c for c in commands) == 1
    assert sum('--features hardened-execution --test execution' in c and 'brynja-hash-tuple' in c for c in commands) == 1
    assert sum("-p brynja-hash-parallel" in command for command in commands) == 1
    status, commands = run_profile("--group", "sha2")
    assert status == 0 and len(commands) == 21
    assert sum('buffer_length_rejects_invalid_values_without_mutation' in c for c in commands) == 1
    assert sum('--lib hardened_execution::engine::tests' in c for c in commands) == 1
    assert sum('--lib hardened_execution::tests::output_owner_clears_during_recoverable_unwind' in c for c in commands) == 1
    assert sum('--lib execution_transaction' in c for c in commands) == 1
    assert sum('--test execution bounded_execution_lifecycle_smoke' in c for c in commands) == 1
    assert sum('--lib hardened::tests::checked_length_' in c for c in commands) == 1
    assert sum('--test general_hash --lib dynamic_lifecycle_' in c for c in commands) == 1
    assert sum('--features general-sha512-t --test general bounded_public_api_smoke' in c for c in commands) == 1
    assert sum("assurance/general-sha512-t/Cargo.toml --lib" in c for c in commands) == 1
    assert all("brynja-hash-sha2" in c or "assurance/general-sha512-t/Cargo.toml --lib" in c for c in commands)
    status, selected_commands = run_profile("--selected", "sha2")
    assert status == 0 and selected_commands == commands
    status, selected_commands = run_profile("--selected")
    assert status == 2 and not selected_commands
    status, commands = run_profile("--full")
    assert status == 0 and len(commands) == 62
    assert sum('--features sponge-execution --lib sponge::tests::portable_sponge' in c for c in commands) == 1
    assert sum(c.endswith('--features static-execution --lib static_authority') for c in commands) == 1
    assert sum(c.endswith('assurance/static-cpu-execution/Cargo.toml --lib') for c in commands) == 1
    status, static_commands = run_profile('--group', 'static_cpu')
    assert status == 0 and len(static_commands) == 6
    assert sum('--features hardened-execution --lib hardened_execution' in c for c in static_commands) == 1
    assert sum(c.endswith('assurance/hosted-cpu-execution/Cargo.toml --lib') for c in static_commands) == 1
    assert sum(c.endswith('--features runtime-execution --lib runtime_execution') for c in static_commands) == 1
    assert sum(c.endswith('--features runtime-execution --lib execution') for c in static_commands) == 1
    assert sum(c.endswith('assurance/acceleration-contract/Cargo.toml --lib') for c in commands) == 1
    assert sum('assurance/legacy-hash-final/Cargo.toml --no-default-features --lib dynamic_' in c for c in commands) == 1
    assert sum('quarantined_model_clears_all_regions_without_instructions' in c for c in commands) == 1
    assert sum('--features cpu --test cpu' in c for c in commands) == 2
    status, commands = run_profile("--group", "unknown")
    assert status == 2 and not commands
    for fail_match in ('acceleration-contract/Cargo.toml', 'direct_clear_covers_every_byte'):
        status, commands = run_profile("--focused", "acceleration", fail_match=fail_match)
        assert status == 42 and fail_match in commands[-1]
    print(
        "Miri scope rejects global drift and validates focused, full, and shard execution"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
