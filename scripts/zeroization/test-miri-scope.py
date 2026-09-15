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
    assert status == 0 and len(commands) == 37
    assert sum('batch::tests::bounded_batch_lifecycle' in c for c in commands) == 1
    assert sum('batch::tests::shape_staging_empty_and_scalar_tail_boundaries' in c for c in commands) == 1
    assert not any('batch::tests::request_failures_are_atomic_and_reusable' in c for c in commands)
    assert sum('hardened_execution::keccak::tests::all_seven_regions_clear' in c for c in commands) == 1
    assert sum('hardened::accelerated::engine::tests::every_memory_region_is_explicitly_cleared' in c for c in commands) == 1
    assert sum('--features sponge-execution --lib sponge::tests::portable_sponge' in c for c in commands) == 1
    assert any('--features static-execution --lib execution' in command for command in commands)
    assert any('--features static-execution --test execution execution_smoke' in command for command in commands)
    assert sum("-p brynja-hash-sha3" in command for command in commands) == 15
    assert sum("-p brynja-mac-kmac" in command for command in commands) == 3
    assert sum('--features hardened-execution --lib execution' in c and 'brynja-mac-kmac' in c for c in commands) == 1
    assert sum('--features hardened-execution --test execution' in c and 'brynja-mac-kmac' in c for c in commands) == 1
    assert sum("-p brynja-hash-tuple" in command for command in commands) == 4
    assert sum('--features hardened-execution --lib execution' in c and 'brynja-hash-tuple' in c for c in commands) == 1
    assert sum('--features hardened-execution --test execution' in c and 'brynja-hash-tuple' in c for c in commands) == 1
    parallel = [c.split(" -p ", 1)[1] for c in commands if "-p brynja-hash-parallel" in c]
    assert parallel == [
        "brynja-hash-parallel --features hardened-execution --test execution_stream -- --skip irregular_updates_and_terminal_bits_match_planned_execution",
        "brynja-hash-parallel --tests",
        "brynja-hash-parallel --features hardened-execution --lib execution",
        "brynja-hash-parallel --features hardened-execution --test execution -- --skip all_identities_bits_blocks_and_outputs_match_portable",
        "brynja-hash-parallel-std --features runtime-execution --lib execution",
    ]
    status, selected_parallel = run_profile("--selected", "parallelhash")
    assert status == 0 and [c.split(" -p ", 1)[1] for c in selected_parallel] == parallel
    status, commands = run_profile("--group", "sha2")
    assert status == 0 and len(commands) == 26
    for suffix in ('brynja-hash-sha2 --features batch512-execution --test batch512 bounded_batch_lifecycle_smoke',
                   'brynja-hash-sha2 --features batch512-execution --test batch512 batch512_general::derived_iv_work_is_bounded_and_named_identity_is_distinct',
                   'brynja-crypto-cpu --features sha512-batch --lib sha512_batch::tests::failed_revalidation_and_unwind_revoke_before_instruction_entry'):
        assert sum(suffix in c for c in commands) == 1
    assert sum('buffer_length_rejects_invalid_values_without_mutation' in c for c in commands) == 1
    assert sum('--lib hardened_execution::engine::tests' in c for c in commands) == 1
    assert sum('--lib hardened_execution::tests::output_owner_clears_during_recoverable_unwind' in c for c in commands) == 1
    assert sum('--lib execution_transaction' in c for c in commands) == 1
    assert sum('--test execution bounded_execution_lifecycle_smoke' in c for c in commands) == 1
    assert sum('--lib hardened::tests::checked_length_' in c for c in commands) == 1
    assert sum('--test general_hash --lib dynamic_lifecycle_' in c for c in commands) == 1
    assert sum('--features general-sha512-t --test general bounded_public_api_smoke' in c for c in commands) == 1
    assert sum("assurance/general-sha512-t/Cargo.toml --lib" in c for c in commands) == 1
    assert sum('sha256_batch::tests::failed_revalidation_and_unwind_revoke_before_instruction_entry' in c for c in commands) == 1
    assert sum('--test batch bounded_batch_lifecycle_smoke' in c for c in commands) == 1
    assert all("brynja-hash-sha2" in c or "assurance/general-sha512-t/Cargo.toml --lib" in c or 'sha256_batch::tests::failed_revalidation_and_unwind_revoke_before_instruction_entry' in c or 'sha512_batch::tests::failed_revalidation_and_unwind_revoke_before_instruction_entry' in c for c in commands)
    status, selected_commands = run_profile("--selected", "sha2")
    assert status == 0 and selected_commands == commands
    status, selected_commands = run_profile("--selected")
    assert status == 2 and not selected_commands
    status, commands = run_profile("--full")
    assert status == 0 and len(commands) == 83
    for suffix in ('--lib cpu::scratch::tests', '--lib cpu::secret::tests',
                   '--test hardened_execution bounded_portable_cleanup_smoke'):
        assert sum('brynja-legacy-md5 --features hardened-execution ' + suffix in c for c in commands) == 1
    status, selected_md5 = run_profile('--selected', 'md5')
    assert status == 0 and selected_md5 == [c for c in commands if '-p brynja-legacy-md5 ' in c]
    for suffix in ('--lib batch::execution::tests',
                   '--lib operational_revalidator_unwind_quarantines_without_instructions',
                   '--test execution callback_unwind_is_terminal_and_transactional'):
        assert sum('brynja-legacy-md5 --features execution ' + suffix in c for c in commands) == 1
    for suffix in ('--lib cpu::secret::tests', '--lib hardened_execution::stream::tests',
                   '--test hardened_execution revocation_cancellation_and_output_failures'):
        assert sum('brynja-legacy-sha1 --features hardened-execution ' + suffix in c for c in commands) == 1
    assert sum('--features execution --test execution revocation_empty_updates_capacity_and_finalization_fail_closed' in c for c in commands) == 1
    assert [c.split(" -p ", 1)[1] for c in commands if "-p brynja-hash-parallel" in c] == parallel
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
