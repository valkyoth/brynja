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

REGISTERED_CONTRACT_KEYS = {"record"}
REGISTERED_RECORD_KEYS = {
    "capability", "symbol", "fields", "temporaries", "sanitization_symbol",
    "cleanup_callers", "evidence", "storage", "output_classification",
    "partial_failure_policy",
}


class CompilerContractError(RuntimeError):
    """Compiler evidence is absent or ambiguous."""


def fail(message: str) -> None:
    raise CompilerContractError(message)


def require_nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{label} must be a nonempty string")
    return value


def without_turbofish(value: str) -> str:
    result = []
    index = 0
    while index < len(value):
        if not value.startswith("::<", index):
            result.append(value[index])
            index += 1
            continue
        index += 3
        depth = 1
        while index < len(value) and depth:
            if value[index] == "<":
                depth += 1
            elif value[index] == ">":
                depth -= 1
            index += 1
        if depth:
            fail("registered MIR sanitizer has an unterminated turbofish")
    return "".join(result)


def mir_callable_identity(value: str) -> tuple[list[str], str]:
    if not value.endswith("("):
        fail("registered MIR sanitizer must end at the call boundary")
    callee = without_turbofish(value[:-1])
    owner, separator, leaf = callee.rpartition("::")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", leaf):
        fail("registered MIR sanitizer function is not one identifier")
    owner_tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", owner) if separator else []
    return owner_tokens, leaf


def compiler_inventory(
    registered: dict | None = None,
    owner_tests: dict | None = None,
    caller_headers: dict | None = None,
    sanitizer_identities: dict | None = None,
) -> tuple[dict, dict]:
    tests = {package: set(names) for package, names in CONTRACT_TESTS.items()}
    calls = {package: list(edges) for package, edges in MIR_CALLS.items()}
    registry = contracts.REGISTERED_OWNER_CONTRACTS if registered is None else registered
    test_map = contracts.REGISTERED_OWNER_COMPILER_TESTS if owner_tests is None else owner_tests
    header_map = contracts.REGISTERED_CALLER_MIR_HEADERS if caller_headers is None else caller_headers
    sanitizer_map = (
        contracts.REGISTERED_SANITIZER_MIR_IDENTITIES
        if sanitizer_identities is None else sanitizer_identities
    )
    records = [contract.get("record", {}) for contract in registry.values()]
    symbols = {record.get("symbol") for record in records}
    callers = {caller for record in records for caller in record.get("cleanup_callers", [])}
    sanitizers = {record.get("sanitization_symbol") for record in records}
    if set(test_map) != symbols or set(header_map) != callers or set(sanitizer_map) != sanitizers:
        fail("registered compiler identity coverage differs")
    used_tests = {name for names in CONTRACT_TESTS.values() for name in names}
    for owner_id, contract in registry.items():
        if set(contract) != REGISTERED_CONTRACT_KEYS:
            fail(f"registered compiler contract has invalid keys: {owner_id}")
        record = contract["record"]
        if set(record) != REGISTERED_RECORD_KEYS:
            fail(f"registered compiler contract record has invalid keys: {owner_id}")
        symbol = require_nonempty(record["symbol"], f"registered owner symbol for {owner_id}")
        source, separator, owner = symbol.partition("#")
        if separator != "#" or not source.startswith("crates/") or "/src/" not in source:
            fail(f"registered compiler contract owner symbol is invalid: {owner_id}")
        package = source.split("/", 2)[1]
        identity = test_map[symbol]
        if set(identity) != {"package", "contract_test"} or identity["package"] != package:
            fail(f"registered compiler test identity is invalid: {owner_id}")
        contract_test = require_nonempty(
            identity["contract_test"], f"registered compiler test for {owner_id}",
        )
        expected_suffix = owner_id.replace(".", "_").replace("-", "_")
        expected_suffix += "_owner_contract_is_compiler_checked"
        if not contract_test.endswith(expected_suffix) or contract_test in used_tests:
            fail(f"registered compiler test is reused or misidentified: {owner_id}")
        used_tests.add(contract_test)
        tests.setdefault(package, set()).add(contract_test)
        package_calls = calls.setdefault(package, [])
        sanitizer_symbol = require_nonempty(
            record["sanitization_symbol"], f"registered sanitizer symbol for {owner_id}",
        )
        sanitizer = require_nonempty(
            sanitizer_map[sanitizer_symbol], f"registered MIR sanitizer for {owner_id}",
        )
        declared_identity = sanitizer_symbol.rsplit("#", 1)[-1]
        declared_owner, separator, declared_leaf = declared_identity.rpartition("::")
        declared_owner_tokens = (
            re.findall(r"[A-Za-z_][A-Za-z0-9_]*", declared_owner) if separator else []
        )
        mir_owner_tokens, mir_leaf = mir_callable_identity(sanitizer)
        if (
            mir_leaf != declared_leaf
            or declared_owner_tokens
            and mir_owner_tokens[-len(declared_owner_tokens):] != declared_owner_tokens
        ):
            fail(f"MIR target differs from registered sanitizer: {owner_id}")
        caller_prefix = f"{source}#{owner}::"
        for caller in record["cleanup_callers"]:
            if not isinstance(caller, str) or not caller.startswith(caller_prefix):
                fail(f"registered cleanup caller differs from owner: {owner_id}")
            member = caller.rsplit("::", 1)[-1]
            header = header_map[caller]
            if (
                not isinstance(header, list) or not header
                or any(not isinstance(part, str) or not part.strip() for part in header)
                or not re.search(rf"(?:^|::){re.escape(member)}\(_1:", header[0])
                or not re.search(rf"\b{re.escape(owner)}\b", header[0])
            ):
                fail(f"registered compiler contract header is invalid: {owner_id}")
            package_calls.append((tuple(header), sanitizer))
    return tests, {package: tuple(edges) for package, edges in calls.items()}


def function_sections(mir: str) -> list[str]:
    starts = [match.start() for match in re.finditer(r"(?m)^fn ", mir)]
    sections = []
    for index, start in enumerate(starts):
        stop = starts[index + 1] if index + 1 < len(starts) else len(mir)
        sections.append(mir[start:stop])
    return sections


def require_mir_call(mir: str, header_parts: tuple[str, ...], call: str) -> None:
    require_nonempty(call, "MIR cleanup target")
    if not header_parts or any(not isinstance(part, str) or not part.strip() for part in header_parts):
        fail("MIR caller header must contain nonempty strings")
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
