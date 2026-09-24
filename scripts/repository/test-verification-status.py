#!/usr/bin/env python3
"""Broken-fixture tests for the README independent-review status checker."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import patch


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
OWNED_IMPLEMENTED = (
    "| Example capability | ✅ Implemented | `example-crate` | "
    "❌ Not independently verified |"
)
COMPONENT_COMPLETION = (
    "The combined v0.24.11 cross-family acceptance has passed. Both expanded "
    "families are therefore **Fully implemented**."
)


def must_fail(text: str, expected: str) -> None:
    try:
        MODULE.validate_document(Path("fixture.md"), text, (ROW,))
    except MODULE.VerificationStatusError as error:
        if expected not in str(error):
            raise AssertionError(f"unexpected failure: {error}") from error
    else:
        raise AssertionError(f"fixture unexpectedly passed: {expected}")


def crate_tables() -> None:
    root = SCRIPT.resolve().parents[2]
    mutations = 0
    for name, rows in MODULE.CRATE_ROWS.items():
        path = Path(name)
        text = (root / path).read_text()
        MODULE.validate_crate_document(path, text)
        first = rows[0]
        cells = [cell.strip() for cell in first.strip("|").split("|")]
        for changed in (
            text.replace(MODULE.HEADING, "## Status"),
            text.replace(first, ""),
            text.replace(first, first + "\n" + first),
            text.replace(first, "| Invented capability | ✅ Fully implemented | ❌ No |"),
            text.replace(first, f"| {cells[0]} | ✅ Verified | {cells[-1]} |"),
            text.replace(first, f"| {cells[0]} | {cells[1]} | ✅ Verified |"),
            text.replace(first, f"| {cells[0]} | {cells[1]} | ✅ FIPS validated |"),
            text.replace(first, f"| {cells[0]} | {cells[1]} | ✅ Independently verified by CI — [tests](tests) |"),
            text.replace(first, first.replace(cells[1], "✅ Fully implemented"
                         if cells[1] != "✅ Fully implemented" else "🚧 In progress", 1)),
            text.replace("| Independently verified |", "| Internal tests |", 1),
        ):
            try:
                MODULE.validate_crate_document(path, changed)
            except MODULE.VerificationStatusError:
                mutations += 1
            else:
                raise AssertionError(f"unreviewed capability/status mutation accepted: {path}")
    # Exercise non-leading batch rows too: these additions must be admitted
    # explicitly, without permitting deletion or upgrading independent claims.
    for name in ("brynja-crypto-cpu", "brynja-crypto-cpu-std", "brynja-hash-sha3"):
        path = Path("crates") / name / "README.md"
        text = (root / path).read_text()
        row = next(row for row in MODULE.CRATE_ROWS[path.as_posix()]
                   if "Keccak four-state" in row or "SHA-3/SHAKE/cSHAKE" in row)
        for changed in (text.replace(row, ""),
                        text.replace(row, row.replace("❌ No", "✅ Independently verified"))):
            try:
                MODULE.validate_crate_document(path, changed)
            except MODULE.VerificationStatusError:
                mutations += 1
            else:
                raise AssertionError(f"batch capability drift accepted: {path}")
    for removed in MODULE.CRATE_ROWS:
        altered = dict(MODULE.CRATE_ROWS)
        del altered[removed]
        with patch.object(MODULE, "CRATE_ROWS", altered):
            try:
                MODULE.check(root)
            except MODULE.VerificationStatusError as error:
                assert "inventory" in str(error), error
            else:
                raise AssertionError(f"missing crate status inventory accepted: {removed}")
    print(f"Crate status tables reject {mutations} claim/table and 38 inventory regressions")


def scoped_status_rows() -> None:
    """Review additions stay static; no qualification or verification upgrade."""
    root = SCRIPT.resolve().parents[2]
    counts = {
        "brynja-core": 1, "brynja-hash-sha2": 2, "brynja-hash-sha3": 2,
        "brynja-mac-kmac": 1, "brynja-hash-tuple": 3,
        "brynja-hash-parallel": 5, "brynja-hash-parallel-std": 3,
        "brynja-legacy-sha1": 2, "brynja-legacy-md5": 2,
    }
    mutations = 0
    for crate, count in counts.items():
        path = Path("crates") / crate / "README.md"
        text = (root / path).read_text()
        rows = MODULE.CRATE_ROWS[path.as_posix()]
        added = [row for row in rows if "scoped" in row.lower() or "Checked borrowed" in row]
        assert len(added) == count, (path, added)
        for row in added:
            capability, status, review = [cell.strip() for cell in row.strip("|").split("|")]
            assert review in ("❌ No", "❌ Not independently verified")
            for replacement in ("", row + "\n" + row,
                                f"| {capability} | ✅ Fully implemented | {review} |",
                                f"| {capability} | {status} | ✅ Independently verified |",
                                f"| {capability} | {status} | ✅ FIPS validated |"):
                assert replacement != row
                try:
                    MODULE.validate_crate_document(path, text.replace(row, replacement))
                except MODULE.VerificationStatusError:
                    mutations += 1
                else:
                    raise AssertionError(f"scoped capability mutation accepted: {path}: {row}")
            # Reproduce a stale inventory entry while leaving the real README intact.
            stale = dict(MODULE.CRATE_ROWS)
            stale[path.as_posix()] = [value for value in rows if value != row]
            with patch.object(MODULE, "CRATE_ROWS", stale):
                try:
                    MODULE.validate_crate_document(path, text)
                except MODULE.VerificationStatusError as error:
                    assert "capability status changed" in str(error), error
                    mutations += 1
                else:
                    raise AssertionError(f"stale scoped inventory accepted: {path}: {row}")
    assert sum(counts.values()) == 21 and mutations == 126
    print("Scoped/borrowed status rows reject 126 omission, duplication, overclaim and stale-inventory regressions")


def main() -> int:
    crate_tables()
    scoped_status_rows()
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
    MODULE.validate_checkmarks(OWNED_IMPLEMENTED)
    try:
        MODULE.validate_checkmarks(
            "| Example capability | ✅ Probably implemented | ❌ Not verified |"
        )
    except MODULE.VerificationStatusError as error:
        if "exactly" not in str(error):
            raise
    else:
        raise AssertionError("ambiguous implementation checkmark unexpectedly passed")
    for invalid, expected in (
        (
            "| Example capability | ✅ Implemented | ✅ crate | "
            "❌ Not independently verified |",
            "owning-crate column",
        ),
        (
            "| Example capability | ✅ Implemented | `example-crate` | "
            "✅ Verified |",
            "named independent reviewer",
        ),
    ):
        try:
            MODULE.validate_checkmarks(invalid)
        except MODULE.VerificationStatusError as error:
            if expected not in str(error):
                raise
        else:
            raise AssertionError(f"four-column status regression passed: {expected}")
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
    component = (
        "This crate-level assurance inventory does not claim a consumer-usable "
        "cryptographic capability. A named independent reviewer is required. "
        "There is no FIPS 140-3 validation. "
        + COMPONENT_COMPLETION
        + "\n"
        + "\n".join(MODULE.COMPONENT_ROWS)
    )
    MODULE.validate_component_document(Path("component.md"), component)
    for stale in (
        "The combined cross-backend acceptance remains pending through v0.24.11. "
        "Both expanded families therefore remain **In progress**.",
        "Both expanded families are therefore **In progress**.",
    ):
        try:
            MODULE.validate_component_document(
                Path("component.md"), component.replace(COMPONENT_COMPLETION, stale)
            )
        except MODULE.VerificationStatusError as error:
            if "acceptance status" not in str(error):
                raise
        else:
            raise AssertionError("stale SHA-2/SHA-3 status unexpectedly passed")
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
