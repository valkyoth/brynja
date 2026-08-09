#!/usr/bin/env python3
"""Reject target-assembly regressions in the v0.12 constant-time gate."""

from __future__ import annotations

import constant_time_codegen


def require_rejection(function: str, body: str, target: str, expected: str) -> None:
    try:
        constant_time_codegen.validate_assembly_body(function, body, target)
    except constant_time_codegen.CodegenError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"constant-time assembly accepted {expected}")


def test() -> None:
    require_rejection(
        "select_u32",
        "\tbltz\ta2, .Lsecret\n.Lsecret:\n\tret\n",
        "riscv32imac-unknown-none-elf",
        "conditional",
    )
    require_rejection(
        "select_u32",
        "\tlw\ta0, 0(a2)\n\tret\n",
        "riscv32imac-unknown-none-elf",
        "memory address",
    )
    require_rejection(
        "swap_bytes",
        "\tbne\ta0, a1, .Lsecret\n.Lsecret:\n\tret\n",
        "riscv32imac-unknown-none-elf",
        "non-public forward",
    )
    require_rejection(
        "select_bytes",
        ".Lsecret:\n\tbltz\ta3, .Lsecret\n\tret\n",
        "riscv32imac-unknown-none-elf",
        "secret Choice register",
    )
    require_rejection(
        "select_u64",
        "\tjne\t.Lsecret\n.Lsecret:\n\tretq\n",
        "x86_64-unknown-linux-gnu",
        "conditional",
    )
    require_rejection(
        "select_u64",
        "\tcbnz\tw2, .Lsecret\n.Lsecret:\n\tret\n",
        "aarch64-apple-ios",
        "conditional",
    )

    constant_time_codegen.validate_assembly_body(
        "swap_bytes",
        ".Lpublic_loop:\n\tadd\ta0, a0, 1\n\tbne\ta0, a1, .Lpublic_loop\n\tret\n",
        "riscv32imac-unknown-none-elf",
    )


if __name__ == "__main__":
    test()
    print("constant-time codegen rejects six branch and secret-address regressions")
