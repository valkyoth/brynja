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
    print("secret-owner MIR evidence rejects four target and ambiguity regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
