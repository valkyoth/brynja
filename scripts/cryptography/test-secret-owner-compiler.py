#!/usr/bin/env python3
"""Regression tests for compiler secret-owner evidence parsing."""

import copy

import secret_owner_compiler as compiler


def rejects(mir: str, header: tuple[str, ...], call: str) -> None:
    try:
        compiler.require_mir_call(mir, header, call)
    except compiler.CompilerContractError:
        return
    raise AssertionError("broken MIR fixture unexpectedly passed")


def rejects_inventory(registry: dict, tests: dict, headers: dict, sanitizers: dict) -> None:
    try:
        compiler.compiler_inventory(registry, tests, headers, sanitizers)
    except compiler.CompilerContractError:
        return
    raise AssertionError("broken registered compiler identity unexpectedly passed")


def main() -> int:
    assert compiler.mir_callable_identity("fixture::Owner::<N>::wipe(") == (
        ["fixture", "Owner"], "wipe",
    )
    assert compiler.mir_callable_identity("<E as Owner>::wipe(") == (
        ["E", "as", "Owner"], "wipe",
    )
    valid = """fn owner::drop(_1: &mut Owner) -> () {
    bb0: { _2 = exact_sanitizer(move _1) -> [return: bb1, unwind unreachable]; }
}
"""
    compiler.require_mir_call(valid, ("owner::drop", "&mut Owner"), "exact_sanitizer(")
    rejects(valid.replace("exact_sanitizer", "same_named_method"), ("owner::drop",), "exact_sanitizer(")
    rejects(valid + valid, ("owner::drop",), "exact_sanitizer(")
    rejects(valid, ("missing::drop",), "exact_sanitizer(")
    rejects("const DECOY: &str = \"fn owner::drop\";\n", ("owner::drop",), "exact_sanitizer(")
    rejects(valid, ("owner::drop",), "")
    rejects(valid, ("",), "exact_sanitizer(")
    record = {
        "capability": "algorithm.fixture",
        "symbol": "crates/fixture-package/src/lib.rs#Owner",
        "fields": ["secret:secret"],
        "temporaries": ["scratch:secret"],
        "sanitization_symbol": "crates/fixture-package/src/lib.rs#Owner::wipe",
        "cleanup_callers": ["crates/fixture-package/src/lib.rs#Owner::drop"],
        "evidence": ["crates/fixture-package/src/lib.rs"],
        "storage": "crate-owned",
        "output_classification": "typed-secret-owned",
        "partial_failure_policy": "clear-complete-secret-destination",
    }
    registry = {"registered.algorithm.fixture": {"record": record}}
    tests = {
        record["symbol"]: {
            "package": "fixture-package",
            "contract_test": (
                "assurance_contract::"
                "registered_algorithm_fixture_owner_contract_is_compiler_checked"
            ),
        },
    }
    headers = {record["cleanup_callers"][0]: ["drop(_1: &mut Owner", "Owner"]}
    sanitizers = {record["sanitization_symbol"]: "fixture::Owner::wipe("}
    observed_tests, calls = compiler.compiler_inventory(
        registry, tests, headers, sanitizers,
    )
    assert tests[record["symbol"]]["contract_test"] in observed_tests["fixture-package"]
    assert calls["fixture-package"][-1] == (
        ("drop(_1: &mut Owner", "Owner"), "fixture::Owner::wipe(",
    )
    for replacement in ("", "   "):
        broken = copy.deepcopy(sanitizers)
        broken[record["sanitization_symbol"]] = replacement
        rejects_inventory(registry, tests, headers, broken)
    broken_headers = copy.deepcopy(headers)
    broken_headers[record["cleanup_callers"][0]] = [""]
    rejects_inventory(registry, tests, broken_headers, sanitizers)
    broken_headers[record["cleanup_callers"][0]] = ["expose(_1: &mut Owner"]
    rejects_inventory(registry, tests, broken_headers, sanitizers)
    rejects_inventory(registry, tests, {}, sanitizers)
    broken_tests = copy.deepcopy(tests)
    broken_tests[record["symbol"]]["contract_test"] = (
        "entropy::assurance_contract::raw_entropy_owner_contract_is_compiler_checked"
    )
    rejects_inventory(registry, broken_tests, headers, sanitizers)
    broken_sanitizers = copy.deepcopy(sanitizers)
    broken_sanitizers[record["sanitization_symbol"]] = "fixture::Owner::wrong_sanitizer("
    rejects_inventory(registry, tests, headers, broken_sanitizers)
    for wrong_owner in ("NotOwner", "SecretState", "SecureRandomEngine", "HardenedState"):
        collision = copy.deepcopy(registry)
        declared = copy.deepcopy(record)
        expected_owner = {
            "NotOwner": "Owner",
            "SecretState": "Secret",
            "SecureRandomEngine": "RandomEngine",
            "HardenedState": "State",
        }[wrong_owner]
        declared["sanitization_symbol"] = (
            f"crates/fixture-package/src/lib.rs#{expected_owner}::wipe"
        )
        collision["registered.algorithm.fixture"]["record"] = declared
        collision_sanitizers = {declared["sanitization_symbol"]: f"fixture::{wrong_owner}::wipe("}
        rejects_inventory(collision, tests, headers, collision_sanitizers)
    print(
        "secret-owner MIR evidence rejects six empty, target, and ambiguity "
        "regressions plus eleven registered identity and coverage bypasses"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
