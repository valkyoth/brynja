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
ROOT = (
    BASE
    + "\nThese concrete public capabilities require a complete public API. "
    "Implemented does not mean independently verified. See component "
    "verification status.\n"
    + "\nFIPS validation is a separate official claim. Brynja has no FIPS 140-3 "
    "validation and no certificate-bound operational-environment claim.\n"
)
IMPLEMENTED = (
    "| Example capability | ✅ Implemented | ❌ Not independently verified |"
)
FULLY_IMPLEMENTED = (
    "| Example family | ✅ Fully implemented | ❌ Not independently verified |"
)


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
    MODULE.validate_document(Path("README.md"), ROOT, (ROW,))
    must_fail(BASE.replace(MODULE.HEADING, "## Status"), "heading")
    must_fail(BASE.replace("named independent reviewer", "reviewer"), "disclaimer")
    must_fail(BASE.replace(ROW, ""), "status row")
    must_fail(
        BASE
        + "| `other` | Other protocol | ✅ Verified |\n",
        "named independent reviewer",
    )
    try:
        MODULE.validate_document(
            Path("README.md"),
            ROOT.replace("no FIPS 140-3 validation", "no validation"),
            (ROW,),
        )
    except MODULE.VerificationStatusError as error:
        if "no FIPS 140-3 validation" not in str(error):
            raise
    else:
        raise AssertionError("root FIPS disclaimer regression unexpectedly passed")
    MODULE.validate_checkmarks(
        "| `example` | Example protocol | "
        "✅ Independently verified by Alice Example — "
        "[review report](security/reviews/example.md) |"
    )
    MODULE.validate_checkmarks(IMPLEMENTED)
    MODULE.validate_checkmarks(FULLY_IMPLEMENTED)
    try:
        MODULE.validate_checkmarks(
            "| Example capability | ✅ Probably implemented | ❌ Not verified |"
        )
    except MODULE.VerificationStatusError as error:
        if "exactly" not in str(error):
            raise
    else:
        raise AssertionError("ambiguous implementation checkmark unexpectedly passed")
    MODULE.validate_readme_split(b"full GitHub README\n", b"compact crate README\n")
    for root_readme, crate_readme, expected in (
        (b"same\n", b"same\n", "purpose-specific"),
        (b"full\n", b"line\n" * 201, "200-line ceiling"),
    ):
        try:
            MODULE.validate_readme_split(root_readme, crate_readme)
        except MODULE.VerificationStatusError as error:
            if expected not in str(error):
                raise
        else:
            raise AssertionError(f"README split regression passed: {expected}")
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
