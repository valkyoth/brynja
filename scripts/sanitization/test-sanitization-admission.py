#!/usr/bin/env python3
"""Exercise fail-closed sanitization admission fixtures."""

from __future__ import annotations

import shutil
import tempfile
import tomllib
from pathlib import Path

import sanitization_admission


ROOT = Path(__file__).resolve().parents[2]


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
        Path("security/dependency-admissions/sanitization-2.1.1.toml"),
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

        record = root / "security/dependency-admissions/sanitization-2.1.1.toml"
        replace(record, 'version = "2.1.1"', 'version = "2.1.2"')
        require_rejection(root, "package identity")
        copy_fixture(root)

        record = root / "security/dependency-admissions/sanitization-2.1.1.toml"
        replace(
            record,
            "a159daa45728fa63e6a42a16bfb8bb5d099f7e6fd05338b7393f3f105fbf2491",
            "069a1386cf42ff5645fb7af70472ade67a737dceb97cdd897226deffaf1de76f",
        )
        require_rejection(root, "selected TCB hash inventory drift")
        copy_fixture(root)

        record = root / "security/dependency-admissions/sanitization-2.1.1.toml"
        replace(record, "previous_selected_feature_tcb_version = \"2.1.0\"",
                "previous_selected_feature_tcb_version = \"2.0.4\"")
        require_rejection(root, "comparison baseline drift")
        copy_fixture(root)

        for current, stale in (
            (sanitization_admission.PACKAGE_SHA256,
             "0c395c5164295d69016c014a3c2dd69d28a84b7e89ba971c1e81b17acc41e411"),
            (sanitization_admission.SOURCE_COMMIT,
             "a3032977ebed2f704687da1a900f9921102351b4"),
            (sanitization_admission.REVIEWED_COMMIT,
             "2ab1c6fcadb5482bbfb223d92492daae0d9c607c"),
        ):
            replace(record, current, stale)
            require_rejection(root, "package identity")
            copy_fixture(root)

        replace(root / "Cargo.lock", sanitization_admission.PACKAGE_SHA256,
                "0c395c5164295d69016c014a3c2dd69d28a84b7e89ba971c1e81b17acc41e411")
        require_rejection(root, "lock identity drift")
        copy_fixture(root)

        record = root / "security/dependency-admissions/sanitization-2.1.1.toml"
        replace(record, "default_features = false", "default_features = true")
        require_rejection(root, "default features")
        copy_fixture(root)

        record = root / "security/dependency-admissions/sanitization-2.1.1.toml"
        replace(record, 'fips_boundary = "excluded"', 'fips_boundary = "included"')
        require_rejection(root, "outside FIPS")
        copy_fixture(root)

        manifest = root / "crates/brynja/Cargo.toml"
        replace(manifest, "[dependencies]", "[dependencies]\nsanitization = \"=2.1.1\"")
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
        release_data = tomllib.loads(release.read_text(encoding="utf-8"))["release"]
        baseline = release_data["baseline"]
        replace(release, f'baseline = "{baseline}"', 'baseline = "0.19.0"')
        require_rejection(root, "post-publication cumulative baseline")
        copy_fixture(root)

        release = root / "release-crates.toml"
        release_data = tomllib.loads(release.read_text(encoding="utf-8"))["release"]
        milestone = release_data["milestone"]
        replace(release, f'milestone = "{milestone}"', 'milestone = "0.11.2"')
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


def test_adapter_release_history() -> None:
    """First-party release metadata must not relax third-party admission."""
    with tempfile.TemporaryDirectory(prefix="brynja-sanitization-release-") as temporary:
        root = Path(temporary)
        copy_fixture(root)
        original = (root / "release-crates.toml").read_text()
        manifest = root / "crates/brynja-sanitization/Cargo.toml"
        original_manifest = manifest.read_text()
        manifest_version = tomllib.loads(original_manifest)["package"]["version"]
        release_version = tomllib.loads(original)["release"]["version"]
        start = original.index('[crates."brynja-sanitization"]')
        end = original.index('\n[crates.', start + 1)

        def case(version="0.1.2", previous="0.1.1", change="dependency",
                 publish=True, stage="public", actual=None, name="brynja-sanitization"):
            row = ('[crates."brynja-sanitization"]\n'
                   f'previous_version = "{previous}"\nversion = "{version}"\n'
                   f'change = "{change}"\npublish = {str(publish).lower()}\n')
            text = original[:start] + row + original[end:]
            text = text.replace('stage = "public"', f'stage = "{stage}"', 1)
            (root / "release-crates.toml").write_text(text)
            manifest.write_text(original_manifest.replace(
                f'version = "{manifest_version}"', f'version = "{actual or version}"', 1
            ).replace('name = "brynja-sanitization"', f'name = "{name}"', 1))

        # Both the historical no-publication state and the current selected
        # dependency release retain all package/checksum/feature admission checks.
        for change in ("unchanged", "metadata", "dependency"):
            case(version="0.1.1", change=change, publish=False, stage="internal")
            sanitization_admission.validate(root)
        case()
        sanitization_admission.validate(root)

        rejections = (
            {"version": "0.1.3"}, {"previous": "unpublished"},
            {"previous": "0.1.0"}, {"change": "code"}, {"change": "initial"},
            {"change": "unchanged"}, {"change": "metadata"},
            {"publish": False}, {"stage": "internal"}, {"stage": "unknown"},
            {"version": "0.1.1", "publish": True},
        )
        for mutation in rejections:
            case(**mutation)
            require_rejection(root, "published adapter release history drift")
        for mutation in ({"actual": "0.1.1"}, {"actual": "0.1.3"},
                         {"name": "substituted-adapter"}):
            case(**mutation)
            require_rejection(root, "adapter release/manifest identity drift")

        # New adapter publication must not admit a new third-party identity,
        # checksum, feature set or FIPS claim. Exercise the full validator.
        for path, before, after, diagnostic in (
            ("Cargo.toml", 'version = "=2.1.1", default-features = false',
             'version = "=2.1.2", default-features = false', "workspace sanitization"),
            ("Cargo.lock", sanitization_admission.PACKAGE_SHA256, "0" * 64, "lock identity"),
            (str(sanitization_admission.RECORD), "default_features = false",
             "default_features = true", "default features"),
            (str(sanitization_admission.RECORD), 'fips_boundary = "excluded"',
             'fips_boundary = "included"', "outside FIPS"),
        ):
            copy_fixture(root)
            case()
            replace(root / path, before, after)
            require_rejection(root, diagnostic)
        copy_fixture(root)
        assert tomllib.loads((root / "release-crates.toml").read_text())["release"]["version"] == release_version
        sanitization_admission.validate(root)
    print("Adapter release history: four accepted states and eighteen identity/publication/admission regressions passed")


if __name__ == "__main__":
    test()
    print("sanitization admission rejects seventeen identity, graph, error-boundary, release-history, feature, FIPS, and drift regressions")
    test_adapter_release_history()
