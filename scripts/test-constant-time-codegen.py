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
    riscv_conditional_mnemonics = (
        "beq",
        "bne",
        "blt",
        "bge",
        "bltu",
        "bgeu",
        "beqz",
        "bnez",
        "bltz",
        "bgez",
        "blez",
        "bgtz",
        "bgt",
        "ble",
        "bgtu",
        "bleu",
        "c.beqz",
        "c.bnez",
    )
    if (
        constant_time_codegen.RISCV_CONDITIONAL_MNEMONICS
        != riscv_conditional_mnemonics
    ):
        raise AssertionError("RISC-V conditional-branch classification drifted")
    one_register = {
        "beqz",
        "bnez",
        "bltz",
        "bgez",
        "blez",
        "bgtz",
        "c.beqz",
        "c.bnez",
    }
    for mnemonic in riscv_conditional_mnemonics:
        operands = "a0, .Lsecret" if mnemonic in one_register else "a0, a1, .Lsecret"
        require_rejection(
            "select_u32",
            f"\t{mnemonic}\t{operands}\n.Lsecret:\n\tret\n",
            "riscv32imac-unknown-none-elf",
            "conditional",
        )

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
        ".Lsecret:\n\tBLTZ\tA3, .Lsecret\n\tret\n",
        "riscv32imac-unknown-none-elf",
        "secret Choice register",
    )
    require_rejection(
        "select_bytes",
        ".Lsecret:\n\tbltz\tx13, .Lsecret\n\tret\n",
        "riscv32imac-unknown-none-elf",
        "secret Choice register",
    )
    require_rejection(
        "select_bytes",
        ".Lsecret:\n\tbgt\ta3, a0, .Lsecret\n\tret\n",
        "riscv32imac-unknown-none-elf",
        "secret Choice register",
    )
    require_rejection(
        "select_bytes",
        ".Lsecret:\n\tc.bnez\ta3, .Lsecret\n\tret\n",
        "riscv32imac-unknown-none-elf",
        "secret Choice register",
    )
    require_rejection(
        "select_bytes",
        "\tlw\ta0, 0(x13)\n\tret\n",
        "riscv32imac-unknown-none-elf",
        "memory address",
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
    print(
        "constant-time codegen rejects all 18 RISC-V conditional forms "
        "and ten focused branch/address regressions"
    )
