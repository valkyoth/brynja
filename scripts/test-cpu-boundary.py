#!/usr/bin/env python3
"""Broken-fixture tests for the v0.22.2 CPU boundary."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import cpu_boundary_policy as policy


ROOT = Path(__file__).resolve().parents[1]


def copy_file(root: Path, relative: Path) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / relative, target)


def fixture(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for relative in (Path("Cargo.toml"), Path("package-policy.toml"), policy.POLICY):
        copy_file(root, relative)
    for manifest in sorted((ROOT / "crates").glob("*/Cargo.toml")):
        copy_file(root, manifest.relative_to(ROOT))
    for package in (policy.CPU, policy.DETECTOR):
        for source in sorted((ROOT / "crates" / package / "src").glob("*.rs")):
            copy_file(root, source.relative_to(ROOT))


def reset(root: Path) -> None:
    shutil.rmtree(root)
    fixture(root)


def replace(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"fixture marker missing: {old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def require_rejection(root: Path, expected: str) -> None:
    try:
        policy.validate(root)
    except policy.CpuBoundaryPolicyError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"CPU boundary accepted broken fixture: {expected}")


def test() -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-cpu-boundary-") as temporary:
        root = Path(temporary) / "fixture"
        fixture(root)
        policy.validate(root)
        document = root / policy.POLICY

        cases = (
            ("implemented_backend_count = 5", "implemented_backend_count = 6", "limits"),
            ("active_backend_count = 0", "active_backend_count = 1", "limits"),
            (
                "approved_cpu_low_level_allowances = 5",
                "approved_cpu_low_level_allowances = 6",
                "limits",
            ),
            ("milestone = \"0.23.3\"", "milestone = \"0.23.4\"", "schema"),
            (
                "status = \"complete-sha2-family-candidates-and-scalar-decisions\"",
                "status = \"all-admitted\"",
                "schema",
            ),
            (
                "scalar_owner = \"brynja-hash-sha2\"",
                "scalar_owner = \"brynja-crypto-cpu\"",
                "scalar owner",
            ),
            (
                "detector_adapter = \"excluded\"",
                "detector_adapter = \"included\"",
                "FIPS",
            ),
        )
        for old, new, expected in cases:
            replace(document, old, new)
            require_rejection(root, expected)
            reset(root)
            document = root / policy.POLICY

        replace(document, '  "no-register-erasure-claim",\n', "")
        require_rejection(root, "safe wrapper")
        reset(root)

        source = root / "crates/brynja-crypto-cpu/src/x86_sha.rs"
        source.write_text(source.read_text(encoding="utf-8") + "\n// drift\n", encoding="utf-8")
        require_rejection(root, "source changed")
        reset(root)

        source = root / "crates/brynja-crypto-cpu/src/aarch64_sha2.rs"
        replace(source, '#[target_feature(enable = "sha2")]', '#[target_feature(enable = "neon")]')
        require_rejection(root, "source changed")
        reset(root)

        source = root / "crates/brynja-crypto-cpu/src/riscv64_zknh.rs"
        replace(source, "sha256sum1", "sha256sum0")
        require_rejection(root, "source changed")
        reset(root)

        source = root / "crates/brynja-crypto-cpu-std/src/runtime_detection.rs"
        replace(source, 'is_x86_feature_detected!("sha")', "true")
        require_rejection(root, "source changed")
        reset(root)

        extra = root / "crates/brynja-crypto-cpu/src/unreviewed.rs"
        extra.write_text("pub fn unreviewed() {}\n", encoding="utf-8")
        require_rejection(root, "unreviewed source")
        reset(root)

        source = root / "crates/brynja-crypto-cpu/src/sha256_schedule.rs"
        source.write_text(source.read_text(encoding="utf-8") + "\n" * 501, encoding="utf-8")
        require_rejection(root, "exceeds 500 lines")
        reset(root)

        reserved = root / "crates/brynja-crypto-cpu/src/x86_avx2.rs"
        reserved.write_text("pub fn candidate() {}\n", encoding="utf-8")
        require_rejection(root, "unreviewed source")
        reset(root)

        cpu_manifest = root / "crates/brynja-crypto-cpu/Cargo.toml"
        cpu_manifest.write_text(
            cpu_manifest.read_text(encoding="utf-8")
            + "\n[dependencies]\nbrynja-core = { workspace = true }\n",
            encoding="utf-8",
        )
        require_rejection(root, "zero dependencies")
        reset(root)

        detector = root / "crates/brynja-crypto-cpu-std/Cargo.toml"
        replace(
            detector,
            "brynja-hash-sha2 = { workspace = true, features = [\"cpu\"] }",
            'brynja-hash-sha2 = { workspace = true, features = ["cpu"] }\nthird-party = "1"',
        )
        require_rejection(root, "dependency boundary")
        reset(root)

        sha2 = root / "crates/brynja-hash-sha2/Cargo.toml"
        replace(sha2, 'cpu = ["dep:brynja-crypto-cpu"]', "cpu = []")
        require_rejection(root, "optional CPU feature")
        reset(root)

        facade = root / "crates/brynja/Cargo.toml"
        replace(
            facade,
            "[dependencies]",
            "[dependencies]\nbrynja-crypto-cpu = { workspace = true }",
        )
        require_rejection(root, "ordinary facade")
        reset(root)

        engine = root / "crates/brynja-tls13/Cargo.toml"
        replace(
            engine,
            "[dependencies]",
            "[dependencies]\nbrynja-crypto-cpu = { workspace = true }",
        )
        require_rejection(root, "forbidden CPU package consumer")
        reset(root)

        cpu_manifest = root / "crates/brynja-crypto-cpu/Cargo.toml"
        replace(cpu_manifest, "[package]", '[package]\nbuild = "build.rs"')
        require_rejection(root, "build or native linking")


if __name__ == "__main__":
    test()
    print("CPU boundary rejects twenty package, source, dispatch, and admission regressions")
