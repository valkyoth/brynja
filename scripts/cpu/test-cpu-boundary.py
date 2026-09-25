#!/usr/bin/env python3
"""Broken-fixture tests for the v0.24.4 CPU boundary."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

import cpu_boundary_policy as policy
import cpu_boundary_backends


ROOT = Path(__file__).resolve().parents[2]


def copy_file(root: Path, relative: Path) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / relative, target)


def fixture(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for relative in (
        Path("Cargo.toml"), Path("package-policy.toml"), policy.POLICY,
        Path("scripts/checks.sh"), Path(".github/workflows/ci.yml"),
    ):
        copy_file(root, relative)
    for relative in policy.EVIDENCE_STATUS:
        copy_file(root, Path(relative))
    for manifest in sorted((ROOT / "crates").glob("*/Cargo.toml")):
        copy_file(root, manifest.relative_to(ROOT))
    for package in (policy.CPU, policy.DETECTOR):
        for source in sorted((ROOT / "crates" / package / "src").rglob("*.rs")):
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
    assert policy.BACKENDS is cpu_boundary_backends.BACKENDS
    assert len(cpu_boundary_backends.STRICT_COMPILED_SOURCES) == 12
    for path, status in cpu_boundary_backends.STRICT_COMPILED_SOURCES.items():
        assert policy.SOURCE_STATUS[(policy.DETECTOR, path)] == status
    with tempfile.TemporaryDirectory(prefix="brynja-cpu-boundary-") as temporary:
        root = Path(temporary) / "fixture"
        fixture(root)
        policy.validate(root)
        document = root / policy.POLICY

        # A valid inner source review still requires its enclosing policy pin.
        with patch.object(policy, "EXPECTED_POLICY_SHA256",
                          "888dd5bfb1c9589d187f1ed5772ff07bb2507050480ed7a1733f99f7bbcb1cc8"):
            require_rejection(root, "CPU security policy changed")
        document.write_text(document.read_text(encoding="utf-8") + "\n# review drift\n",
                            encoding="utf-8")
        require_rejection(root, "CPU security policy changed")
        reset(root)

        cases = (
            ("implemented_backend_count = 7", "implemented_backend_count = 8", "limits"),
            ("active_backend_count = 0", "active_backend_count = 1", "limits"),
            (
                "approved_cpu_low_level_allowances = 8",
                "approved_cpu_low_level_allowances = 9",
                "limits",
            ),
            ("milestone = \"0.24.4\"", "milestone = \"0.24.5\"", "schema"),
            (
                "status = \"sha2-and-keccak-candidates-with-scalar-decisions\"",
                "status = \"all-admitted\"",
                "schema",
            ),
            (
                'scalar_owners = ["brynja-hash-sha2", "brynja-hash-sha3"]',
                'scalar_owners = ["brynja-crypto-cpu"]',
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
        cpu_manifest.write_text(cpu_manifest.read_text(encoding="utf-8").replace(
            'workspace = true, optional = true', 'workspace = true'), encoding="utf-8")
        require_rejection(root, "opt-in first-party clearing dependency")
        reset(root)

        detector = root / "crates/brynja-crypto-cpu-std/Cargo.toml"
        replace(
            detector,
            "brynja-hash-sha2 = { workspace = true, features = [\"cpu\"] }",
            'brynja-hash-sha2 = { workspace = true, features = ["cpu"] }\nthird-party = "1"',
        )
        require_rejection(root, "dependency boundary")
        reset(root)

        for before, after, expected in (
            ('protected-memory = ["dep:brynja-core"]', 'protected-memory = []', 'default feature'),
            ('strict-sha2 = ["protected-memory", "brynja-hash-sha2/general-sha512-t"]', 'strict-sha2 = ["brynja-hash-sha2/general-sha512-t"]', 'default feature'),
            ('strict-sha2-acceleration = ["strict-sha2", "brynja-hash-sha2/hardened-execution"]', 'strict-sha2-acceleration = ["brynja-hash-sha2/hardened-execution"]', 'default feature'),
            ('default = []', 'default = ["strict-sha2-acceleration"]', 'default feature'),
            ('strict-sha3 = ["protected-memory", "dep:brynja-hash-sha3"]', 'strict-sha3 = ["dep:brynja-hash-sha3"]', 'default feature'),
            ('strict-kmac = ["protected-memory", "dep:brynja-mac-kmac"]', 'strict-kmac = ["dep:brynja-mac-kmac"]', 'default feature'),
            ('strict-tuplehash = ["protected-memory", "dep:brynja-hash-tuple"]', 'strict-tuplehash = ["dep:brynja-hash-tuple"]', 'default feature'),
            ('default = []', 'default = ["strict-tuplehash"]', 'default feature'),
            ('brynja-hash-tuple = { workspace = true, optional = true }', 'brynja-hash-tuple = { workspace = true }', 'dependency boundary'),
            ('default = []', 'default = ["strict-kmac"]', 'default feature'),
            ('brynja-mac-kmac = { workspace = true, optional = true }', 'brynja-mac-kmac = { workspace = true }', 'dependency boundary'),
            ('default = []', 'default = ["strict-sha3"]', 'default feature'),
            ('strict-sha3-acceleration = ["strict-sha3", "brynja-hash-sha3/hardened-execution"]', 'strict-sha3-acceleration = ["brynja-hash-sha3/hardened-execution"]', 'default feature'),
            ('default = []', 'default = ["strict-sha3-acceleration"]', 'default feature'),
            ('strict-kmac-acceleration = ["strict-kmac", "brynja-mac-kmac/hardened-execution"]', 'strict-kmac-acceleration = ["brynja-mac-kmac/hardened-execution"]', 'default feature'),
            ('default = []', 'default = ["strict-kmac-acceleration"]', 'default feature'),
            ('default = []', 'default = ["strict-sha2"]', 'default feature'),
            ('brynja-core = { workspace = true, optional = true }', 'brynja-core = { workspace = true }', 'dependency boundary'),
        ):
            replace(detector, before, after)
            require_rejection(root, expected)
            reset(root)

        for relative in ('src/protected_memory/platform/thread.rs', 'src/protected_memory/platform/thread/group_tests.rs', 'src/strict_sha2/worker.rs', 'src/strict_sha2/compiled/worker.rs', 'src/strict_sha3/worker.rs', 'src/strict_sha3/compiled/worker.rs', 'src/strict_kmac/worker.rs', 'src/strict_kmac/compiled/worker.rs', 'src/strict_tuplehash/worker.rs'):
            source = root / 'crates' / policy.DETECTOR / relative
            source.write_text(source.read_text() + '\n// unreviewed resource drift\n')
            require_rejection(root, 'source changed')
            reset(root)

        sha2 = root / "crates/brynja-hash-sha2/Cargo.toml"
        replace(sha2, 'cpu = ["dep:brynja-crypto-cpu"]', "cpu = []")
        require_rejection(root, "optional CPU feature")
        reset(root)

        for before, after in (
            ('default = []', 'default = ["static-execution"]'),
            ('static-execution = ["cpu", "brynja-crypto-cpu/static-execution"]', 'static-execution = []'),
            ('runtime-execution = ["static-execution", "brynja-crypto-cpu/runtime-execution"]', 'runtime-execution = []'),
            ('runtime-execution = ["static-execution", "brynja-crypto-cpu/runtime-execution"]', 'runtime-execution = ["brynja-crypto-cpu/runtime-execution"]'),
        ):
            replace(sha2, before, after)
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
    print("CPU boundary rejects twenty-six existing and eighteen protected-resource package/source regressions")
