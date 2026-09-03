#!/usr/bin/env python3
"""Adversarial place, alias, and lifecycle tests for strict MIR cleanup flow."""

import secret_owner_compiler as compiler


HEADER = ("owner::drop", "&mut Owner")
TARGET = "exact_sanitizer("


def accepts(mir: str) -> None:
    compiler.require_mir_call(mir, HEADER, TARGET)


def rejects(mir: str) -> None:
    try:
        accepts(mir)
    except compiler.CompilerContractError:
        return
    raise AssertionError("unsafe MIR place or alias fixture unexpectedly passed")


def plain_before(statement: str) -> str:
    return f"""fn owner::drop(_1: &mut Owner) -> () {{
    bb0: {{
        _2 = &mut (*_1);
        {statement}
        _3 = exact_sanitizer(move _2) -> [return: bb1, unwind unreachable];
    }}
    bb1: {{
        return;
    }}
}}
"""


def call_before(destination: str) -> str:
    return f"""fn owner::drop(_1: &mut Owner) -> () {{
    bb0: {{
        _2 = &mut (*_1);
        {destination} = unrelated_call() -> [return: bb1, unwind unreachable];
    }}
    bb1: {{
        _3 = exact_sanitizer(move _2) -> [return: bb2, unwind unreachable];
    }}
    bb2: {{
        return;
    }}
}}
"""


def main() -> int:
    accepts(plain_before("_5.0 = const 7_u8;"))
    accepts(plain_before("_5.0 = const 7_u8;") + """
const owner::drop::{constant#0}: usize = {
    let mut _0: usize;
    bb0: {
        _0 = const 1_usize;
        return;
    }
}
""")
    accepts(plain_before("_5.0 = const 7_u8;") + """
Owner::field::{constant#0}: usize = {
    let mut _0: usize;
    bb0: {
        _0 = const 1_usize;
        return;
    }
}
""")
    accepts("""fn owner::drop(_1: &mut Owner) -> () {
    bb0: {
        _2 = unrelated_call() -> [return: bb1, unwind unreachable];
    }
    bb1: {
        _2 = &mut (*_1);
        _3 = exact_sanitizer(move _2) -> [return: bb2, unwind unreachable];
    }
    bb2: {
        return;
    }
}
""")
    accepts("""fn owner::drop(_1: &mut Owner, _2: bool) -> () {
    bb0: {
        switchInt(copy _2) -> [0: bb1, otherwise: bb2];
    }
    bb1: {
        _3 = &mut (*_1);
        goto -> bb3;
    }
    bb2: {
        _3 = &mut (*_1);
        goto -> bb3;
    }
    bb3: {
        _4 = exact_sanitizer(move _3) -> [return: bb4, unwind unreachable];
    }
    bb4: {
        return;
    }
}
""")
    accepts("""fn owner::drop(_1: &mut Owner) -> OwnerAlias {
    bb0: {
        _0 = exact_sanitizer(move _1) -> [return: bb1, unwind unreachable];
    }
    bb1: {
        _0 = unrelated_value;
        return;
    }
}
""")

    for statement in (
        "_1.0 = unrelated_value;",
        "(*_2) = unrelated_value;",
        "(*_2).0 = unrelated_value;",
        "((*_2).0: SecretRegion) = unrelated_value;",
        "discriminant((*_2).0) = 1;",
        "deinit((*_2).0);",
    ):
        rejects(plain_before(statement))

    for destination in ("(*_2).0", "(*_2).0.1", "((*_2).0: SecretRegion)"):
        rejects(call_before(destination))

    rejects("""fn owner::drop(_1: &mut Owner) -> () {
    bb0: {
        _2 = &mut (*_1);
        _3 = mutate_owner(move _2) -> [return: bb1, unwind unreachable];
    }
    bb1: {
        _4 = exact_sanitizer(move _1) -> [return: bb2, unwind unreachable];
    }
    bb2: {
        return;
    }
}
""")
    rejects("""fn owner::drop(_1: &mut Owner) -> OwnerAlias {
    bb0: {
        _0 = exact_sanitizer(move _1) -> [return: bb1, unwind unreachable];
    }
    bb1: {
        return;
    }
}
""")
    rejects("""fn owner::drop(_1: &mut Owner) -> OwnerAlias {
    bb0: {
        _0.0 = exact_sanitizer(move _1) -> [return: bb1, unwind unreachable];
    }
    bb1: {
        return;
    }
}
""")
    rejects("""fn owner::drop(_1: &mut Owner, _2: bool) -> OwnerAlias {
    bb0: {
        _0 = exact_sanitizer(move _1) -> [return: bb1, unwind unreachable];
    }
    bb1: {
        switchInt(copy _2) -> [0: bb2, otherwise: bb3];
    }
    bb2: {
        _0 = unrelated_value;
        goto -> bb4;
    }
    bb3: {
        goto -> bb4;
    }
    bb4: {
        return;
    }
}
""")
    for destination, argument in (
        ("_5.0", "_5.0"),
        ("_5.0.1", "_5.0.1"),
        ("((_5.0: OwnerTuple).1: OwnerAlias)", "((_5.0: OwnerTuple).1: OwnerAlias)"),
    ):
        rejects(f"""fn owner::drop(_1: &mut Owner) -> () {{
    bb0: {{
        {destination} = exact_sanitizer(move _1) -> [return: bb1, unwind unreachable];
    }}
    bb1: {{
        _6 = mutate_owner(move {argument}) -> [return: bb2, unwind unreachable];
    }}
    bb2: {{
        return;
    }}
}}
""")
    rejects("""fn owner::drop(_1: &mut Owner) -> () {
    bb0: {
        _5.0 = exact_sanitizer(move _1) -> [return: bb1, unwind unreachable];
    }
    bb1: {
        _5.1 = unrelated_value;
        return;
    }
}
""")
    rejects("""fn owner::drop(_1: &mut Owner, _2: bool) -> () {
    bb0: {
        _3 = exact_sanitizer(move _1) -> [return: bb1, unwind unreachable];
    }
    bb1: {
        switchInt(copy _2) -> [0: bb2, otherwise: bb99];
    }
    bb2: {
        return;
    }
}
""")
    rejects("""fn owner::drop(_1: &mut Owner) -> () {
    bb0: {
        _2 = exact_sanitizer(move _1) -> [return: bb1, unwind unreachable];
    }
    bb1: {
        (*_1).0 = unrelated_value;
        goto -> bb2;
    }
    bb1: {
        goto -> bb2;
    }
    bb2: {
        return;
    }
}
""")
    rejects("""fn owner::drop(_1: &mut Owner) -> () {
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
""")
    rejects("""fn owner::drop(_1: &mut Owner) -> () {
    bb0: {
        _2 = exact_sanitizer(move _1) -> [return: bb1, unwind unreachable];
    }
    bb1: {
        _3 = mutate_owner(move _2) -> [return: bb2, unwind unreachable];
    }
    bb2: {
        return;
    }
}
""")
    rejects(plain_before("_3 = move _2 as *mut Owner;"))
    rejects(plain_before("_3 = Aggregate(move _2);"))
    rejects(plain_before("_5.0 = move _2;"))

    rejects("""fn owner::drop(_1: &mut Owner, _2: bool) -> () {
    bb0: {
        switchInt(copy _2) -> [0: bb1, otherwise: bb2];
    }
    bb1: {
        _3 = &mut (*_1);
        goto -> bb3;
    }
    bb2: {
        _3 = &mut (*_4);
        goto -> bb3;
    }
    bb3: {
        (*_3).0 = unrelated_value;
        _5 = exact_sanitizer(move _1) -> [return: bb4, unwind unreachable];
    }
    bb4: {
        return;
    }
}
""")
    rejects("""fn owner::drop(_1: &mut Owner) -> () {
    bb0: {
        _2 = &mut (*_1);
        _3 = exact_sanitizer(move _1) -> [return: bb1, unwind unreachable];
    }
    bb1: {
        (*_2).0 = unrelated_value;
        return;
    }
}
""")
    rejects("""fn owner::drop(_1: &mut Owner) -> () {
    bb0: {
        _2 = &mut (*_1);
        _3 = exact_sanitizer(move _1) -> [return: bb1, unwind unreachable];
    }
    bb1: {
        _4 = mutate_owner(move _2) -> [return: bb2, unwind unreachable];
    }
    bb2: {
        return;
    }
}
""")
    rejects("""fn owner::drop(_1: &mut Owner) -> () {
    bb0: {
        _2 = &mut (*_1);
        asm!("", inout(reg) _2) -> [return: bb1, unwind unreachable];
    }
    bb1: {
        _3 = exact_sanitizer(move _1) -> [return: bb2, unwind unreachable];
    }
    bb2: {
        return;
    }
}
""")
    rejects("""fn owner::drop(_1: &mut Owner) -> () {
    bb0: {
        _2 = &mut (*_1);
        copy_nonoverlapping(copy _5, move _2, const 1_usize) -> [return: bb1, unwind unreachable];
    }
    bb1: {
        _3 = exact_sanitizer(move _1) -> [return: bb2, unwind unreachable];
    }
    bb2: {
        return;
    }
}
""")
    print(
        "strict MIR cleanup flow accepts five valid place/provenance paths and "
        "rejects twenty-nine projected-write, alias-escape, return-escape, may-flow, unwind, CFG, assembly, "
        "and post-cleanup regressions"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
