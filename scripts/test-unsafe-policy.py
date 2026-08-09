#!/usr/bin/env python3
"""Exercise positive and broken unsafe-policy inventories."""

from __future__ import annotations

import tempfile
from pathlib import Path

import unsafe_policy


VALID = """//! Isolated implementation.
use core::sync::atomic::{Ordering, compiler_fence};
#[allow(unsafe_code)]
pub(crate) fn zeroize_region_volatile(region: &mut [u8]) {
    for byte in region {
        let destination = core::ptr::from_mut(byte);
        // SAFETY: fixture proof.
        unsafe { core::ptr::write_volatile(destination, 0_u8) };
    }
    compiler_fence(Ordering::SeqCst);
}
"""


def fixture(root: Path) -> None:
    source = root / "crates/brynja-core/src"
    source.mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(
        '[workspace.lints.rust]\nunsafe_code = "deny"\n', encoding="utf-8"
    )
    (source / "lib.rs").write_text(
        "mod secret_memory_volatile;\npub mod safe {}\n", encoding="utf-8"
    )
    (source / "secret_memory_volatile.rs").write_text(VALID, encoding="utf-8")


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
        require_rejection(root, "escaped the approved module")
        extra.unlink()

        allowed = root / unsafe_policy.ALLOWED
        allowed.write_text(VALID.replace("// SAFETY:", "// Proof:"), encoding="utf-8")
        require_rejection(root, "local safety proof")
        allowed.write_text(VALID.replace("write_volatile", "write"), encoding="utf-8")
        require_rejection(root, "volatile-store call site")
        allowed.write_text(VALID + "fn machine() { asm!() }\n", encoding="utf-8")
        require_rejection(root, "assembly or FFI")


if __name__ == "__main__":
    test()
    print("unsafe policy rejects five exception-boundary regressions")
