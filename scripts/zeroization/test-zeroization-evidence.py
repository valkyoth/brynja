#!/usr/bin/env python3
"""Exercise broken zeroization claim and CI-evidence fixtures."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import zeroization_evidence


ROOT = Path(__file__).resolve().parents[2]


def copy_fixture(destination: Path) -> None:
    for relative in (
        Path("assurance/zeroization-matrix.toml"),
        Path(".github/workflows/ci.yml"),
        Path("scripts/checks.sh"),
        Path("scripts/tag_gate.sh"),
        Path("scripts/zeroization/check-tag-miri.sh"),
    ):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)


def replace(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"fixture source missing {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def require_rejection(root: Path, expected: str) -> None:
    try:
        zeroization_evidence.validate(root)
    except zeroization_evidence.EvidenceError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"zeroization evidence accepted {expected}")


def test() -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-zero-evidence-") as temporary:
        root = Path(temporary)
        copy_fixture(root)
        zeroization_evidence.validate(root)

        matrix = root / "assurance/zeroization-matrix.toml"
        workflow = root / ".github/workflows/ci.yml"
        checks = root / "scripts/checks.sh"
        tag_gate = root / "scripts/tag_gate.sh"

        replace(matrix, '  "registers",\n', "")
        require_rejection(root, "exclusions")
        copy_fixture(root)

        replace(matrix, 'artifacts = ["mir", "llvm-ir", "assembly"]', 'artifacts = ["llvm-ir"]')
        require_rejection(root, "claim or artifact")
        copy_fixture(root)

        replace(workflow, "1.90.0, 1.91.0", "1.91.0")
        require_rejection(root, "compiler matrix")
        copy_fixture(root)

        replace(tag_gate, "scripts/zeroization/check-tag-miri.sh", "true")
        require_rejection(root, "local tag gate")
        copy_fixture(root)

        tag_miri = root / "scripts/zeroization/check-tag-miri.sh"
        replace(tag_miri, '"$miri_runner" --full', "true")
        require_rejection(root, "complete Miri evidence")
        copy_fixture(root)

        tag_miri = root / "scripts/zeroization/check-tag-miri.sh"
        replace(tag_miri, '"$miri_runner" --focused "${groups[@]}"', "true")
        require_rejection(root, "focused Miri evidence")
        copy_fixture(root)

        workflow.write_text(
            workflow.read_text(encoding="utf-8")
            + "\n      - run: scripts/zeroization/check-zeroization-miri.sh\n",
            encoding="utf-8",
        )
        require_rejection(root, "ordinary CI")
        copy_fixture(root)

        replace(
            checks,
            "scripts/zeroization/check-zeroization-codegen.sh 1.98.1 x86_64-unknown-linux-gnu",
            "true",
        )
        require_rejection(root, "ordinary repository checks")


if __name__ == "__main__":
    test()
    print("zeroization evidence rejects eight claim, coverage, and execution-boundary regressions")
