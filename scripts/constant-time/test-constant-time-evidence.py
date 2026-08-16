#!/usr/bin/env python3
"""Exercise fail-closed constant-time evidence-matrix fixtures."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import constant_time_evidence


ROOT = Path(__file__).resolve().parents[2]
FILES = (
    Path("assurance/constant-time-matrix.toml"),
    Path(".github/workflows/ci.yml"),
    Path("scripts/checks.sh"),
)


def copy_fixture(destination: Path) -> None:
    for relative in FILES:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)


def replace(path: Path, old: str, new: str) -> None:
    content = path.read_text(encoding="utf-8")
    if old not in content:
        raise AssertionError(f"fixture source missing {old!r}")
    path.write_text(content.replace(old, new, 1), encoding="utf-8")


def require_rejection(root: Path, expected: str) -> None:
    try:
        constant_time_evidence.validate(root)
    except constant_time_evidence.EvidenceError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"constant-time evidence accepted {expected}")


def test() -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-ct-evidence-") as temporary:
        root = Path(temporary)
        copy_fixture(root)
        constant_time_evidence.validate(root)

        matrix = root / "assurance/constant-time-matrix.toml"
        replace(matrix, '"assembly"', '"machine-code"')
        require_rejection(root, "claim or artifact")
        copy_fixture(root)

        matrix = root / "assurance/constant-time-matrix.toml"
        replace(matrix, '  "1.90.0",\n', "")
        require_rejection(root, "compiler or target coverage")
        copy_fixture(root)

        matrix = root / "assurance/constant-time-matrix.toml"
        replace(matrix, "array_witness_width = 32", "array_witness_width = 31")
        require_rejection(root, "claim or artifact")
        copy_fixture(root)

        workflow = root / ".github/workflows/ci.yml"
        replace(workflow, "scripts/constant-time/check-constant-time-codegen.sh", "scripts/omitted-codegen.sh")
        require_rejection(root, "both constant-time evidence dimensions")
        copy_fixture(root)

        checks = root / "scripts/checks.sh"
        replace(checks, "scripts/constant-time/check-constant-time-codegen.sh", "scripts/omitted-codegen.sh")
        require_rejection(root, "ordinary checks omit")
        copy_fixture(root)

        checks = root / "scripts/checks.sh"
        replace(
            checks,
            "python3 scripts/constant-time/test-constant-time-codegen.py",
            "python3 scripts/omitted-codegen-fixtures.py",
        )
        require_rejection(root, "assembly regression fixtures")


if __name__ == "__main__":
    test()
    print("constant-time evidence rejects six claim, coverage, CI, and local-gate regressions")
