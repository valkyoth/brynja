#!/usr/bin/env python3
"""Broken fixtures for security commit-subject classification."""

from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-commit-classification.py")
SPEC = importlib.util.spec_from_file_location("commit_classification", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load commit-classification checker")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def must_fail(subject: str, paths: tuple[str, ...]) -> None:
    try:
        MODULE.validate(subject, paths)
    except MODULE.ClassificationError:
        return
    raise AssertionError(f"subject unexpectedly passed: {subject}")


def main() -> int:
    must_fail("fix: close release gap", ("docs/RELEASE_PLAN.md",))
    must_fail(
        "fix: close v0.3.5 pentest gaps",
        ("requirements/coverage.md", "scripts/check-requirements.py"),
    )
    must_fail(
        "docs: remediate pentest finding",
        ("security/pentest/v0.4.0.md",),
    )
    MODULE.validate("fix: reject malformed record", ("crates/brynja/src/lib.rs",))
    MODULE.validate(
        "docs: record pentest report",
        ("security/pentest/v0.4.0.md",),
    )
    MODULE.validate(
        "chore(requirements): close RFC ownership gaps",
        ("requirements/coverage.md",),
    )
    MODULE.validate(
        "test(constant-time): close RISC-V assembly classifier gaps",
        (
            "scripts/constant_time_codegen.py",
            "scripts/test-constant-time-codegen.py",
            "security/pentest/v0.12.0.md",
        ),
    )
    print("commit-classification broken fixtures: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
