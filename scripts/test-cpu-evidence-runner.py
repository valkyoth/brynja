#!/usr/bin/env python3
"""Adversarial tests for detached native CPU candidate bundles."""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

import cpu_evidence_run as runner


def write_bundle(root: Path) -> Path:
    bundle = root / "bundle"
    bundle.mkdir()
    files = {
        "cargo.txt": "cargo 1.97.1\n",
        "candidate-tests.log": (
            "test evidence_route_is_exact_and_accelerated ... ok\n"
            "test result: ok. 5 passed; 0 failed\n"
        ),
        "codegen.log": (
            "target=x86_64-unknown-linux-gnu\n"
            "required_instruction=sha256rnds2\n"
            "assembly_sha256=" + "a" * 64 + "\nstatus=pass\n"
        ),
        "host.txt": "vendor_id: AuthenticAMD\n",
        "manifest.txt": (
            "schema=brynja-sha256-native-candidate-v1\n"
            "source_commit=" + "1" * 40 + "\n"
            "source_tree=" + "2" * 40 + "\n"
            "lane=local-amd-x86_64\n"
            "backend=x86-sha\n"
            "architecture=x86_64\n"
            "os=linux\n"
            "captured_utc=2026-08-14T12:00:00Z\n"
            "tree_state=clean\n"
            "status=pass\n"
            "authority=non-authorizing-native-candidate-observation\n"
        ),
        "rustc.txt": "rustc 1.97.1\n",
    }
    for name, content in files.items():
        (bundle / name).write_text(content, encoding="utf-8")
    refresh(bundle)
    return bundle


def refresh(bundle: Path) -> None:
    lines = []
    for name in sorted(runner.REQUIRED_FILES):
        digest = hashlib.sha256((bundle / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}\n")
    (bundle / "SHA256SUMS").write_text("".join(lines), encoding="ascii")


def replace(bundle: Path, name: str, before: str, after: str) -> None:
    path = bundle / name
    content = path.read_text(encoding="utf-8")
    assert before in content
    path.write_text(content.replace(before, after, 1), encoding="utf-8")
    refresh(bundle)


def rejects(label: str, mutate: object) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        bundle = write_bundle(Path(temporary))
        mutate(bundle)
        try:
            runner.validate_bundle(bundle)
        except runner.CandidateRunError:
            return
        raise AssertionError(f"candidate runner accepted {label}")


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        assert runner.validate_bundle(write_bundle(Path(temporary)))["backend"] == "x86-sha"
    rejects("extra file", lambda bundle: (bundle / "extra").write_text("x"))
    rejects("checksum drift", lambda bundle: (bundle / "host.txt").write_text("changed"))
    rejects(
        "admission authority",
        lambda bundle: replace(
            bundle,
            "manifest.txt",
            "non-authorizing-native-candidate-observation",
            "admitted",
        ),
    )
    rejects(
        "dirty source",
        lambda bundle: replace(bundle, "manifest.txt", "tree_state=clean", "tree_state=dirty"),
    )
    rejects(
        "unknown lane",
        lambda bundle: replace(bundle, "manifest.txt", "local-amd-x86_64", "unknown-lane"),
    )
    rejects(
        "architecture substitution",
        lambda bundle: replace(bundle, "manifest.txt", "architecture=x86_64", "architecture=aarch64"),
    )
    rejects(
        "missing accelerated execution",
        lambda bundle: replace(
            bundle,
            "candidate-tests.log",
            "evidence_route_is_exact_and_accelerated",
            "ordinary_test",
        ),
    )
    rejects(
        "missing instruction",
        lambda bundle: replace(bundle, "codegen.log", "sha256rnds2", "ordinary-code"),
    )
    rejects(
        "invalid timestamp",
        lambda bundle: replace(bundle, "manifest.txt", "2026-08-14T12:00:00Z", "today"),
    )
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        bundle = write_bundle(root)
        link = root / "link"
        os.symlink(bundle, link)
        try:
            runner.validate_bundle(link)
        except runner.CandidateRunError:
            pass
        else:
            raise AssertionError("candidate runner accepted a symlinked bundle")
    for path in (
        Path("scripts/manage-cpu-evidence.py"),
        Path("scripts/cpu_evidence_run.py"),
        Path("scripts/validate-cpu-evidence-run.py"),
        Path("scripts/test-cpu-evidence-runner.py"),
    ):
        assert path.is_file() and not path.is_symlink()
        assert len(path.read_text(encoding="utf-8").splitlines()) <= 500
    print("CPU evidence runner rejects ten provenance and bundle regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
