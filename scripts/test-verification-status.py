#!/usr/bin/env python3
"""Broken-fixture tests for the README independent-review status checker."""

from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-verification-status.py")
SPEC = importlib.util.spec_from_file_location("verification_status", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load verification-status checker")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ROW = "| `example` | Example protocol | ❌ Not verified |"
BASE = f"""# example

## Cryptography Verification Status

No protocol code has been independently reviewed. This component only moves
from ❌ to ✅ when a named independent reviewer signs off and evidence is
linked. Project tests, CI, Kani, Miri, fuzzing, and pentesting do not by
themselves constitute independent verification.

| Component | Protocol scope | Independently verified |
| --- | --- | --- |
{ROW}
"""
SUPPORT = """# support

## Cryptography Verification Status

This crate does not implement cryptographic or protocol code. Only a named
independent reviewer and linked review evidence can change status.
"""


def must_fail(text: str, expected: str) -> None:
    try:
        MODULE.validate_document(Path("fixture.md"), text, (ROW,))
    except MODULE.VerificationStatusError as error:
        if expected not in str(error):
            raise AssertionError(f"unexpected failure: {error}") from error
    else:
        raise AssertionError(f"fixture unexpectedly passed: {expected}")


def main() -> int:
    MODULE.validate_document(Path("fixture.md"), BASE, (ROW,))
    must_fail(BASE.replace(MODULE.HEADING, "## Status"), "heading")
    must_fail(BASE.replace("named independent reviewer", "reviewer"), "disclaimer")
    must_fail(BASE.replace(ROW, ""), "status row")
    must_fail(
        BASE
        + "| `other` | Other protocol | ✅ Verified |\n",
        "named independent reviewer",
    )
    MODULE.validate_checkmarks(
        "| `example` | Example protocol | "
        "✅ Independently verified by Alice Example — "
        "[review report](security/reviews/example.md) |"
    )
    MODULE.validate_support_document(Path("support.md"), SUPPORT)
    try:
        MODULE.validate_support_document(
            Path("support.md"), SUPPORT.replace("linked review evidence", "evidence")
        )
    except MODULE.VerificationStatusError as error:
        if "linked review evidence" not in str(error):
            raise
    else:
        raise AssertionError("support note without linked evidence unexpectedly passed")
    print("verification-status broken fixtures: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
