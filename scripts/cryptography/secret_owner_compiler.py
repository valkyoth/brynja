#!/usr/bin/env python3
"""Compiler and MIR evidence for current and registered secret-owner contracts."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

import api_profile_contracts as contracts


ROOT = Path(__file__).resolve().parents[2]
TOOLCHAINS = ("1.90.0", "1.98.0")
CONTRACT_TESTS = {
    "brynja-core": {
        "entropy::assurance_contract::raw_entropy_owner_contract_is_compiler_checked",
        "secret::assurance_contract::abstract_secret_owner_contract_is_compiler_checked",
        "secret_memory::assurance_contract::secret_memory_owner_contract_is_compiler_checked",
        "secure_random::assurance_contract::secure_random_owner_contract_is_compiler_checked",
    },
    "brynja-sanitization": {
        "assurance_contract::sanitized_secret_owner_contract_is_compiler_checked",
    },
    "brynja-test-support": {
        "deterministic_random::assurance_contract::deterministic_random_owner_contract_is_compiler_checked",
    },
}
MIR_CALLS = {
    "brynja-core": (
        (("drop(_1: &mut SecretRegionInitialization",), "zeroize_region_volatile("),
        (("clear(_1: OwnedSecretRegion",), "zeroize_region_volatile("),
        (("drop(_1: &mut OwnedSecretRegion",), "zeroize_region_volatile("),
        (("drop(_1: &mut SecretInitialization",), "run_destruction::<D>("),
        (("drop(_1: &mut SecretState",), "run_destruction::<D>("),
        (("drop(_1: &mut SecureRandom",), "<E as SecureRandomEngine>::uninstantiate("),
    ),
    "brynja-sanitization": (
        (("clear(_1: SanitizedSecret",), "SecretBytes::<N>::secure_clear("),
    ),
    "brynja-test-support": (
        (("clear_state(_1: &mut DeterministicRandom",), "clear_owned_region("),
        (("drop(_1: &mut DeterministicRandom",), "clear_owned_region("),
    ),
}

REGISTERED_CONTRACT_KEYS = {"record", "package", "contract_test", "mir_callers"}
REGISTERED_RECORD_KEYS = {
    "capability", "symbol", "fields", "temporaries", "sanitization_symbol",
    "cleanup_callers", "evidence", "storage", "output_classification",
    "partial_failure_policy",
}


class CompilerContractError(RuntimeError):
    """Compiler evidence is absent or ambiguous."""


def fail(message: str) -> None:
    raise CompilerContractError(message)


def compiler_inventory(registered: dict | None = None) -> tuple[dict, dict]:
    tests = {package: set(names) for package, names in CONTRACT_TESTS.items()}
    calls = {package: list(edges) for package, edges in MIR_CALLS.items()}
    registry = contracts.REGISTERED_OWNER_CONTRACTS if registered is None else registered
    for owner_id, contract in registry.items():
        if set(contract) != REGISTERED_CONTRACT_KEYS:
            fail(f"registered compiler contract has invalid keys: {owner_id}")
        record = contract["record"]
        if set(record) != REGISTERED_RECORD_KEYS:
            fail(f"registered compiler contract record has invalid keys: {owner_id}")
        callers = record["cleanup_callers"]
        if set(callers) != set(contract["mir_callers"]):
            fail(f"registered compiler contract MIR coverage differs: {owner_id}")
        package = contract["package"]
        tests.setdefault(package, set()).add(contract["contract_test"])
        package_calls = calls.setdefault(package, [])
        for caller in callers:
            edge = contract["mir_callers"][caller]
            if set(edge) != {"header", "sanitizer"} or not edge["header"]:
                fail(f"registered compiler contract MIR edge is invalid: {owner_id}")
            package_calls.append((tuple(edge["header"]), edge["sanitizer"]))
    return tests, {package: tuple(edges) for package, edges in calls.items()}


def function_sections(mir: str) -> list[str]:
    starts = [match.start() for match in re.finditer(r"(?m)^fn ", mir)]
    sections = []
    for index, start in enumerate(starts):
        stop = starts[index + 1] if index + 1 < len(starts) else len(mir)
        sections.append(mir[start:stop])
    return sections


def require_mir_call(mir: str, header_parts: tuple[str, ...], call: str) -> None:
    matches = [
        section for section in function_sections(mir)
        if all(part in section.splitlines()[0] for part in header_parts)
    ]
    if len(matches) != 1:
        fail(f"MIR caller is absent or ambiguous: {header_parts}")
    if call not in matches[0]:
        fail(f"MIR caller does not resolve the exact cleanup target: {header_parts}")


def command(toolchain: str, arguments: list[str], target: Path) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["CARGO_TARGET_DIR"] = str(target)
    return subprocess.run(
        ["cargo", f"+{toolchain}", *arguments],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )


def check_contract_tests(
    toolchain: str, package: str, expected_tests: set[str], target: Path,
) -> None:
    result = command(
        toolchain,
        ["test", "--locked", "-p", package, "--lib", "--", "--list", "--format", "terse"],
        target,
    )
    if result.returncode != 0:
        fail(f"compiler contract tests failed for {package} under {toolchain}:\n{result.stdout}")
    observed = {
        line.removesuffix(": test") for line in result.stdout.splitlines()
        if line.endswith(": test")
    }
    missing = expected_tests - observed
    if missing:
        fail(f"compiler contract tests are absent for {package}: {sorted(missing)}")


def check_mir(
    toolchain: str, package: str, expected_calls: tuple, target: Path,
) -> None:
    result = command(
        toolchain,
        ["rustc", "--locked", "-p", package, "--lib", "--release", "--", "--emit=mir"],
        target,
    )
    if result.returncode != 0:
        fail(f"MIR generation failed for {package} under {toolchain}:\n{result.stdout}")
    crate_name = package.replace("-", "_")
    candidates = list((target / "release" / "deps").glob(f"{crate_name}-*.mir"))
    if len(candidates) != 1:
        fail(f"MIR artifact is absent or ambiguous for {package} under {toolchain}")
    mir = candidates[0].read_text(encoding="utf-8")
    for header, call in expected_calls:
        require_mir_call(mir, header, call)


def main() -> int:
    contract_tests, mir_calls = compiler_inventory()
    if set(contract_tests) != set(mir_calls):
        fail("compiler contract test and MIR package inventories differ")
    with tempfile.TemporaryDirectory(prefix="brynja-secret-owner-contract-") as directory:
        base = Path(directory)
        for toolchain in TOOLCHAINS:
            for package, expected_tests in contract_tests.items():
                target = base / toolchain / package
                check_contract_tests(toolchain, package, expected_tests, target)
                check_mir(toolchain, package, mir_calls[package], target)
    print(
        "compiler-checked secret-owner shapes and exact MIR cleanup calls pass "
        "under Rust 1.90.0 and 1.98.0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
