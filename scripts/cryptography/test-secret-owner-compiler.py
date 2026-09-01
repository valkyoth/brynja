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
    assert compiler.mir_callable_identity("fixture_package::module::Owner::<N>::wipe(") == (
        ["fixture_package", "module", "Owner"], "wipe",
    )
    assert compiler.mir_callable_identity(
        "<E as fixture_package::module::Owner>::wipe("
    ) == (
        ["fixture_package", "module", "Owner"], "wipe",
    )
    target = "fixture_package::module::Owner::wipe("
    valid = """fn owner::drop(_1: &mut Owner) -> () {
    bb0: {
        _2 = &mut (*_1);
        _3 = fixture_package::module::Owner::wipe(move _2) -> [return: bb1, unwind unreachable];
    }
    bb1: {
        return;
    }
}
"""
    compiler.require_mir_call(valid, ("owner::drop", "&mut Owner"), target)
    rejects(valid.replace("Owner::wipe", "Owner::same_named_method"), ("owner::drop",), target)
    rejects(valid + valid, ("owner::drop",), target)
    rejects(valid, ("missing::drop",), target)
    rejects("const DECOY: &str = \"fn owner::drop\";\n", ("owner::drop",), target)
    rejects(valid, ("owner::drop",), "")
    rejects(valid, ("",), target)
    rejects(valid.replace("move _2", "move _4"), ("owner::drop",), target)
    for substituted in (
        "outer::fixture_package::module::Owner::wipe",
        "other_crate::fixture_package::module::Owner::wipe",
        "prefixfixture_package::module::Owner::wipe",
        "<E as fixture_package::module::Owner>::wipe",
    ):
        rejects(
            valid.replace("fixture_package::module::Owner::wipe", substituted),
            ("owner::drop",),
            target,
        )
    duplicate_call = valid.replace(
        "_3 = fixture_package::module::Owner::wipe(move _2) -> [return: bb1, unwind unreachable];",
        "_3 = fixture_package::module::Owner::wipe(move _2) -> [return: bb2, unwind unreachable];\n"
        "    }\n    bb2: {\n"
        "        _4 = fixture_package::module::Owner::wipe(move _2) -> [return: bb1, unwind unreachable];",
    )
    rejects(duplicate_call, ("owner::drop",), target)
    conditional = """fn owner::drop(_1: &mut Owner, _2: bool) -> () {
    bb0: {
        switchInt(copy _2) -> [0: bb2, otherwise: bb1];
    }
    bb1: {
        _3 = exact_sanitizer(move _1) -> [return: bb2, unwind unreachable];
    }
    bb2: {
        return;
    }
}
"""
    rejects(conditional, ("owner::drop", "&mut Owner"), "exact_sanitizer(")
    unwind_valid = """fn owner::drop(_1: &mut Owner) -> () {
    bb0: {
        _2 = exact_sanitizer(move _1) -> [return: bb1, unwind: bb2];
    }
    bb1: {
        return;
    }
    bb2 (cleanup): {
        resume;
    }
}
"""
    compiler.require_mir_call(
        unwind_valid, ("owner::drop", "&mut Owner"), "exact_sanitizer("
    )
    unrelated_call_destination = """fn owner::drop(_1: &mut Owner) -> () {
    bb0: {
        _2 = &mut (*_1);
        _4 = unrelated_result() -> [return: bb1, unwind unreachable];
    }
    bb1: {
        _3 = exact_sanitizer(move _2) -> [return: bb2, unwind unreachable];
    }
    bb2: {
        return;
    }
}
"""
    compiler.require_mir_call(
        unrelated_call_destination,
        ("owner::drop", "&mut Owner"),
        "exact_sanitizer(",
    )
    unwind_bypass = """fn owner::drop(_1: &mut Owner, _2: bool) -> () {
    bb0: {
        switchInt(copy _2) -> [0: bb2, otherwise: bb1];
    }
    bb1: {
        _3 = exact_sanitizer(move _1) -> [return: bb3, unwind: bb2];
    }
    bb2 (cleanup): {
        resume;
    }
    bb3: {
        return;
    }
}
"""
    rejects(unwind_bypass, ("owner::drop", "&mut Owner"), "exact_sanitizer(")
    call_overwrite = """fn owner::drop(_1: &mut Owner) -> () {
    bb0: {
        _2 = &mut (*_1);
        _2 = get_unrelated_owner() -> [return: bb1, unwind unreachable];
    }
    bb1: {
        _3 = exact_sanitizer(move _2) -> [return: bb2, unwind unreachable];
    }
    bb2: {
        return;
    }
}
"""
    rejects(call_overwrite, ("owner::drop", "&mut Owner"), "exact_sanitizer(")
    arrow_assignment = call_overwrite.replace(
        "_2 = get_unrelated_owner() -> [return: bb1, unwind unreachable];",
        "_2 = copy _4 as fn() -> &mut Owner;\n        goto -> bb1;",
    )
    rejects(arrow_assignment, ("owner::drop", "&mut Owner"), "exact_sanitizer(")
    branch_overwrite = """fn owner::drop(_1: &mut Owner, _2: bool) -> () {
    bb0: {
        _3 = &mut (*_1);
        switchInt(copy _2) -> [0: bb1, otherwise: bb2];
    }
    bb1: {
        _3 = get_unrelated_owner() -> [return: bb3, unwind unreachable];
    }
    bb2: {
        goto -> bb3;
    }
    bb3: {
        _4 = exact_sanitizer(move _3) -> [return: bb4, unwind unreachable];
    }
    bb4: {
        return;
    }
}
"""
    rejects(branch_overwrite, ("owner::drop", "&mut Owner"), "exact_sanitizer(")
    loop_reassignment = """fn owner::drop(_1: &mut Owner, _2: bool) -> () {
    bb0: {
        _3 = &mut (*_1);
        goto -> bb1;
    }
    bb1: {
        switchInt(copy _2) -> [0: bb3, otherwise: bb2];
    }
    bb2: {
        _3 = move _4;
        goto -> bb1;
    }
    bb3: {
        _5 = exact_sanitizer(move _3) -> [return: bb4, unwind unreachable];
    }
    bb4: {
        return;
    }
}
"""
    rejects(loop_reassignment, ("owner::drop", "&mut Owner"), "exact_sanitizer(")
    owner_reassignment = """fn owner::drop(_1: &mut Owner) -> () {
    bb0: {
        _1 = get_unrelated_owner() -> [return: bb1, unwind unreachable];
    }
    bb1: {
        _2 = exact_sanitizer(move _1) -> [return: bb2, unwind unreachable];
    }
    bb2: {
        return;
    }
}
"""
    rejects(owner_reassignment, ("owner::drop", "&mut Owner"), "exact_sanitizer(")
    record = {
        "capability": "algorithm.fixture",
        "symbol": "crates/fixture-package/src/module.rs#fixture_package::module::Owner",
        "fields": ["secret:secret"],
        "temporaries": ["scratch:secret"],
        "sanitization_symbol": (
            "crates/fixture-package/src/module.rs#fixture_package::module::Owner::wipe"
        ),
        "cleanup_callers": [
            "crates/fixture-package/src/module.rs#fixture_package::module::Owner::drop"
        ],
        "evidence": ["crates/fixture-package/src/module.rs"],
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
    headers = {record["cleanup_callers"][0]: [
        "fn module::<impl at crates/fixture-package/src/module.rs:7:1: 7:20>::"
        "drop(_1: &mut Owner) -> () {"
    ]}
    sanitizers = {
        record["sanitization_symbol"]: "fixture_package::module::Owner::wipe("
    }
    observed_tests, calls = compiler.compiler_inventory(
        registry, tests, headers, sanitizers,
    )
    assert tests[record["symbol"]]["contract_test"] in observed_tests["fixture-package"]
    assert calls["fixture-package"][-1] == (
        tuple(headers[record["cleanup_callers"][0]]),
        "fixture_package::module::Owner::wipe(",
        True,
    )
    for replacement in ("", "   "):
        broken = copy.deepcopy(sanitizers)
        broken[record["sanitization_symbol"]] = replacement
        rejects_inventory(registry, tests, headers, broken)
    broken_headers = copy.deepcopy(headers)
    broken_headers[record["cleanup_callers"][0]] = [""]
    rejects_inventory(registry, tests, broken_headers, sanitizers)
    broken_headers[record["cleanup_callers"][0]] = [
        headers[record["cleanup_callers"][0]][0].replace("::drop(", "::expose(")
    ]
    rejects_inventory(registry, tests, broken_headers, sanitizers)
    rejects_inventory(registry, tests, {}, sanitizers)
    broken_tests = copy.deepcopy(tests)
    broken_tests[record["symbol"]]["contract_test"] = (
        "entropy::assurance_contract::raw_entropy_owner_contract_is_compiler_checked"
    )
    rejects_inventory(registry, broken_tests, headers, sanitizers)
    broken_sanitizers = copy.deepcopy(sanitizers)
    broken_sanitizers[record["sanitization_symbol"]] = (
        "fixture_package::module::Owner::wrong_sanitizer("
    )
    rejects_inventory(registry, tests, headers, broken_sanitizers)
    incomplete_owner = copy.deepcopy(registry)
    incomplete_owner["registered.algorithm.fixture"]["record"]["symbol"] = (
        "crates/fixture-package/src/module.rs#Owner"
    )
    incomplete_tests = {
        incomplete_owner["registered.algorithm.fixture"]["record"]["symbol"]:
            tests[record["symbol"]]
    }
    rejects_inventory(incomplete_owner, incomplete_tests, headers, sanitizers)
    incomplete_sanitizer = copy.deepcopy(registry)
    incomplete_sanitizer["registered.algorithm.fixture"]["record"]["sanitization_symbol"] = (
        "crates/fixture-package/src/module.rs#Owner::wipe"
    )
    incomplete_sanitizers = {
        incomplete_sanitizer["registered.algorithm.fixture"]["record"]["sanitization_symbol"]:
            sanitizers[record["sanitization_symbol"]]
    }
    rejects_inventory(incomplete_sanitizer, tests, headers, incomplete_sanitizers)
    wrong_caller = copy.deepcopy(registry)
    wrong_caller["registered.algorithm.fixture"]["record"]["cleanup_callers"] = [
        "crates/fixture-package/src/module.rs#fixture_package::other::Owner::drop"
    ]
    wrong_caller_headers = {
        wrong_caller["registered.algorithm.fixture"]["record"]["cleanup_callers"][0]:
            headers[record["cleanup_callers"][0]]
    }
    rejects_inventory(wrong_caller, tests, wrong_caller_headers, sanitizers)
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
            "crates/fixture-package/src/module.rs#"
            f"fixture_package::module::{expected_owner}::wipe"
        )
        collision["registered.algorithm.fixture"]["record"] = declared
        collision_sanitizers = {
            declared["sanitization_symbol"]:
                f"fixture_package::module::{wrong_owner}::wipe("
        }
        rejects_inventory(collision, tests, headers, collision_sanitizers)
    namespace_collisions = (
        ("fixture_package::module_a::Owner", "fixture_package::module_b::Owner::wipe("),
        ("fixture_package::module_a::Owner", "other_crate::module_a::Owner::wipe("),
        (
            "fixture_package::module_a::Trait",
            "<E as fixture_package::module_b::Trait>::wipe(",
        ),
        ("fixture_package::nested::State", "fixture_package::other::nested::State::wipe("),
    )
    for declared_owner, wrong_sanitizer in namespace_collisions:
        collision = copy.deepcopy(registry)
        declared = copy.deepcopy(record)
        declared["sanitization_symbol"] = (
            f"crates/fixture-package/src/module.rs#{declared_owner}::wipe"
        )
        collision["registered.algorithm.fixture"]["record"] = declared
        broken = {declared["sanitization_symbol"]: wrong_sanitizer}
        rejects_inventory(collision, tests, headers, broken)
    wrong_headers = (
        headers[record["cleanup_callers"][0]][0].replace("fn module::", "fn module_b::"),
        headers[record["cleanup_callers"][0]][0].replace(
            "crates/fixture-package/", "crates/other-crate/"
        ),
        headers[record["cleanup_callers"][0]][0].replace("fn module::", "fn other::module::"),
        headers[record["cleanup_callers"][0]][0].replace("&mut Owner", "&mut OtherOwner"),
    )
    for wrong_header in wrong_headers:
        broken = {record["cleanup_callers"][0]: [wrong_header]}
        rejects_inventory(registry, tests, broken, sanitizers)
    print(
        "secret-owner MIR evidence rejects nineteen identity, target, data-flow, and dominance "
        "regressions plus twenty-two registered identity, namespace, and coverage bypasses"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
