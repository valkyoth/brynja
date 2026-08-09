#!/usr/bin/env python3
"""Exercise positive and broken unsafe-policy inventories."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import unsafe_policy


ROOT = Path(__file__).resolve().parents[1]


def fixture(root: Path) -> None:
    source = root / "crates/brynja-core/src"
    source.mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(
        '[workspace.lints.rust]\nunsafe_code = "deny"\n', encoding="utf-8"
    )
    (source / "lib.rs").write_text(
        "mod secret_memory_volatile;\npub mod safe {}\n", encoding="utf-8"
    )
    shutil.copyfile(
        ROOT / unsafe_policy.ALLOWED,
        source / "secret_memory_volatile.rs",
    )


def require_rejection(root: Path, expected: str) -> None:
    try:
        unsafe_policy.validate(root)
    except unsafe_policy.UnsafePolicyError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"unsafe policy accepted {expected}")


def test() -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-unsafe-") as temporary:
        root = Path(temporary)
        fixture(root)
        unsafe_policy.validate(root)

        (root / "Cargo.toml").write_text(
            '[workspace.lints.rust]\nunsafe_code = "forbid"\n', encoding="utf-8"
        )
        require_rejection(root, "workspace unsafe lint")
        fixture(root)

        extra = root / "crates/brynja-core/src/extra.rs"
        extra.write_text(
            "#[allow(unsafe_code)] fn escaped() { unsafe {} }\n", encoding="utf-8"
        )
        require_rejection(root, "unapproved unsafe")
        extra.unlink()

        extra.write_text(
            """#![deny(unsafe_code)]
#[expect(unsafe_code)]
unsafe extern    "C" {
    pub safe fn unreviewed_native_entry();
}
pub fn reachable_from_safe_rust() { unreviewed_native_entry(); }
""",
            encoding="utf-8",
        )
        require_rejection(root, "unapproved unsafe")
        extra.unlink()

        extra.write_text(
            "pub fn escaped() { core::arch::asm \n ! (\"nop\"); }\n",
            encoding="utf-8",
        )
        require_rejection(root, "assembly")
        extra.unlink()

        extra.write_text('include ! ("generated.inc");\n', encoding="utf-8")
        require_rejection(root, "code inclusion")
        extra.unlink()

        extra.write_text(
            '#[path = "/tmp/unreviewed.rs"] mod unreviewed;\n',
            encoding="utf-8",
        )
        require_rejection(root, "code inclusion")
        extra.unlink()

        allowed = root / unsafe_policy.ALLOWED
        allowed.write_text(
            allowed.read_text(encoding="utf-8").replace(
                "unsafe { core::ptr::write_volatile(destination, 0_u8) };",
                "unsafe {\n"
                "            core::ptr::write_volatile(destination, 0_u8);\n"
                "            core::ptr::write_volatile(destination, 0_u8);\n"
                "        }",
            ),
            encoding="utf-8",
        )
        require_rejection(root, "approved unsafe module changed")


if __name__ == "__main__":
    test()
    print("unsafe policy rejects seven exception-boundary regressions")
