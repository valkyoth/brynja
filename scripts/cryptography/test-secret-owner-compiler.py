#!/usr/bin/env python3
"""Regression tests for compiler secret-owner evidence parsing."""

import secret_owner_compiler as compiler


def rejects(mir: str, header: tuple[str, ...], call: str) -> None:
    try:
        compiler.require_mir_call(mir, header, call)
    except compiler.CompilerContractError:
        return
    raise AssertionError("broken MIR fixture unexpectedly passed")


def main() -> int:
    valid = """fn owner::drop(_1: &mut Owner) -> () {
    bb0: { _2 = exact_sanitizer(move _1) -> [return: bb1, unwind unreachable]; }
}
"""
    compiler.require_mir_call(valid, ("owner::drop", "&mut Owner"), "exact_sanitizer(")
    rejects(valid.replace("exact_sanitizer", "same_named_method"), ("owner::drop",), "exact_sanitizer(")
    rejects(valid + valid, ("owner::drop",), "exact_sanitizer(")
    rejects(valid, ("missing::drop",), "exact_sanitizer(")
    rejects("const DECOY: &str = \"fn owner::drop\";\n", ("owner::drop",), "exact_sanitizer(")
    record = {
        "capability": "algorithm.fixture",
        "symbol": "fixture.rs#Owner",
        "fields": ["secret:secret"],
        "temporaries": ["scratch:secret"],
        "sanitization_symbol": "fixture.rs#exact_sanitizer",
        "cleanup_callers": ["fixture.rs#Owner::drop"],
        "evidence": ["fixture.rs"],
        "storage": "crate-owned",
        "output_classification": "typed-secret-owned",
        "partial_failure_policy": "clear-complete-secret-destination",
    }
    contract = {
        "record": record,
        "package": "fixture-package",
        "contract_test": "assurance_contract::owner_contract_is_compiler_checked",
        "mir_callers": {
            "fixture.rs#Owner::drop": {
                "header": ["owner::drop", "&mut Owner"],
                "sanitizer": "exact_sanitizer(",
            },
        },
    }
    tests, calls = compiler.compiler_inventory({"registered.algorithm.fixture": contract})
    assert contract["contract_test"] in tests["fixture-package"]
    assert calls["fixture-package"] == ((('owner::drop', '&mut Owner'), 'exact_sanitizer('),)
    broken = {"registered.algorithm.fixture": {**contract, "mir_callers": {}}}
    try:
        compiler.compiler_inventory(broken)
    except compiler.CompilerContractError:
        pass
    else:
        raise AssertionError("registered owner escaped exact MIR caller coverage")
    print(
        "secret-owner MIR evidence rejects four target and ambiguity regressions "
        "plus incomplete registered-owner contracts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
