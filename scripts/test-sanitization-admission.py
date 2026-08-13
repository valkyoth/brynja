#!/usr/bin/env python3
"""Exercise fail-closed sanitization admission fixtures."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import sanitization_admission


ROOT = Path(__file__).resolve().parents[1]


def copy_fixture(destination: Path) -> None:
    for relative in (
        Path("Cargo.toml"),
        Path("Cargo.lock"),
        Path("release-crates.toml"),
        Path("crates/brynja-sanitization/Cargo.toml"),
        Path("assurance/sanitization-admission/Cargo.toml"),
        Path("assurance/sanitization-admission/Cargo.lock"),
        Path("assurance/sanitization-admission/src/lib.rs"),
        Path("docs/sanitization-admission-review.md"),
        Path("security/dependency-admissions/sanitization-2.0.3.toml"),
    ):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    for manifest in (ROOT / "crates").glob("*/Cargo.toml"):
        target = destination / manifest.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(manifest, target)


def replace(path: Path, old: str, new: str) -> None:
    content = path.read_text(encoding="utf-8")
    if old not in content:
        raise AssertionError(f"fixture source missing {old!r}")
    path.write_text(content.replace(old, new, 1), encoding="utf-8")


def require_rejection(root: Path, expected: str) -> None:
    try:
        sanitization_admission.validate(root)
    except sanitization_admission.AdmissionError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"admission fixture accepted {expected}")


def test() -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-sanitization-admission-") as temporary:
        root = Path(temporary)
        copy_fixture(root)
        sanitization_admission.validate(root)

        record = root / "security/dependency-admissions/sanitization-2.0.3.toml"
        replace(record, 'version = "2.0.3"', 'version = "2.0.4"')
        require_rejection(root, "package identity")
        copy_fixture(root)

        record = root / "security/dependency-admissions/sanitization-2.0.3.toml"
        replace(record, "default_features = false", "default_features = true")
        require_rejection(root, "default features")
        copy_fixture(root)

        record = root / "security/dependency-admissions/sanitization-2.0.3.toml"
        replace(record, 'fips_boundary = "excluded"', 'fips_boundary = "included"')
        require_rejection(root, "outside FIPS")
        copy_fixture(root)

        manifest = root / "crates/brynja/Cargo.toml"
        replace(manifest, "[dependencies]", "[dependencies]\nsanitization = \"=2.0.3\"")
        require_rejection(root, "escaped adapter")
        copy_fixture(root)

        candidate = root / "assurance/sanitization-admission/Cargo.toml"
        replace(candidate, "default-features = false", "default-features = true")
        require_rejection(root, "candidate dependency selection")
        copy_fixture(root)

        lock = root / "Cargo.lock"
        lock.write_text(lock.read_text(encoding="utf-8") + '\n[[package]]\nname = "zeroize"\nversion = "1.0.0"\n', encoding="utf-8")
        require_rejection(root, "zeroize entered")
        copy_fixture(root)

        release = root / "release-crates.toml"
        replace(release, 'baseline = "0.15.0"', 'baseline = "0.14.0"')
        require_rejection(root, "post-publication cumulative baseline")
        copy_fixture(root)

        release = root / "release-crates.toml"
        replace(release, 'milestone = "0.18.1"', 'milestone = "0.11.2"')
        require_rejection(root, "version and milestone")
        copy_fixture(root)

        document = root / "docs/sanitization-admission-review.md"
        replace(document, "forces a new admission review", "permits silent updates")
        require_rejection(root, "forces a new admission review")
        copy_fixture(root)

        candidate = root / "assurance/sanitization-admission/src/lib.rs"
        replace(candidate, "try_from_fallible(", "try_from_fallible<E>(")
        require_rejection(root, "arbitrary source error")
        copy_fixture(root)

        candidate = root / "assurance/sanitization-admission/src/lib.rs"
        replace(candidate, "try_replace_from_fallible(", "try_replace_from_fallible<E>(")
        require_rejection(root, "arbitrary source error")


if __name__ == "__main__":
    test()
    print("sanitization admission rejects eleven identity, graph, error-boundary, release-history, feature, FIPS, and drift regressions")
