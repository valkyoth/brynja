#!/usr/bin/env python3
"""Broken-fixture tests for the v0.13.2 CPU package boundary."""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from pathlib import Path

import cpu_boundary_policy


ROOT = Path(__file__).resolve().parents[1]


def copy_file(root: Path, relative: Path) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / relative, target)


def fixture(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for relative in (
        Path("Cargo.toml"),
        Path("package-policy.toml"),
        cpu_boundary_policy.POLICY,
    ):
        copy_file(root, relative)
    for manifest in sorted((ROOT / "crates").glob("*/Cargo.toml")):
        copy_file(root, manifest.relative_to(ROOT))
    for package in (cpu_boundary_policy.CPU, cpu_boundary_policy.DETECTOR):
        copy_file(root, Path("crates") / package / "src/lib.rs")


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
        cpu_boundary_policy.validate(root)
    except cpu_boundary_policy.CpuBoundaryPolicyError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, received {error!s}") from error
    else:
        raise AssertionError(f"CPU boundary accepted broken fixture: {expected}")


def source(root: Path, package: str) -> Path:
    return root / "crates" / package / "src/lib.rs"


def refresh_source_hash(root: Path, package: str) -> None:
    path = source(root, package)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    policy = root / cpu_boundary_policy.POLICY
    text = policy.read_text(encoding="utf-8")
    marker = f'package = "{package}"'
    start = text.index(marker)
    hash_start = text.index('sha256 = "', start) + len('sha256 = "')
    hash_end = text.index('"', hash_start)
    policy.write_text(text[:hash_start] + digest + text[hash_end:], encoding="utf-8")


def test() -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-cpu-boundary-") as temporary:
        root = Path(temporary) / "fixture"
        fixture(root)
        cpu_boundary_policy.validate(root)
        policy = root / cpu_boundary_policy.POLICY

        replace(policy, 'active_backend_count = 0', 'active_backend_count = 1')
        require_rejection(root, "limits")
        reset(root)
        policy = root / cpu_boundary_policy.POLICY

        replace(policy, 'approved_cpu_low_level_allowances = 0', 'approved_cpu_low_level_allowances = 1')
        require_rejection(root, "limits")
        reset(root)
        policy = root / cpu_boundary_policy.POLICY

        replace(policy, 'current_cpu_allowances = []', 'current_cpu_allowances = ["x86-sha"]')
        require_rejection(root, "amendment contract")
        reset(root)
        policy = root / cpu_boundary_policy.POLICY

        replace(policy, 'maximum_source_lines = 500', 'maximum_source_lines = 600')
        require_rejection(root, "limits")
        reset(root)
        policy = root / cpu_boundary_policy.POLICY

        replace(policy, 'detector_adapter = "excluded"', 'detector_adapter = "included"')
        require_rejection(root, "FIPS")
        reset(root)
        policy = root / cpu_boundary_policy.POLICY

        replace(policy, '  "secret-free-failure",\n', "")
        require_rejection(root, "safe wrapper invariant")
        reset(root)
        policy = root / cpu_boundary_policy.POLICY

        replace(policy, 'status = "reserved"', 'status = "active"')
        require_rejection(root, "implementation authority")
        reset(root)
        policy = root / cpu_boundary_policy.POLICY

        replace(policy, 'instructions = ["sha"]', 'instructions = ["sha", "avx2"]')
        require_rejection(root, "backend contract")
        reset(root)

        cpu_source = source(root, cpu_boundary_policy.CPU)
        cpu_source.write_text(cpu_source.read_text(encoding="utf-8") + "\n// drift\n", encoding="utf-8")
        require_rejection(root, "reopen security review")
        reset(root)

        cpu_source = source(root, cpu_boundary_policy.CPU)
        cpu_source.write_text(cpu_source.read_text(encoding="utf-8") + "\n// unsafe\n", encoding="utf-8")
        refresh_source_hash(root, cpu_boundary_policy.CPU)
        require_rejection(root, "reopen security review")
        reset(root)

        cpu_source = source(root, cpu_boundary_policy.CPU)
        cpu_source.write_text(cpu_source.read_text(encoding="utf-8") + "\n" * 501, encoding="utf-8")
        require_rejection(root, "exceeds 500 lines")
        reset(root)

        module = root / "crates" / cpu_boundary_policy.CPU / "src/x86_sha.rs"
        module.write_text("pub fn candidate() {}\n", encoding="utf-8")
        require_rejection(root, "unadmitted source")
        reset(root)

        cpu_source = source(root, cpu_boundary_policy.CPU)
        replace(cpu_source, "IMPLEMENTED: bool = false", "IMPLEMENTED: bool = true")
        refresh_source_hash(root, cpu_boundary_policy.CPU)
        require_rejection(root, "reopen security review")
        reset(root)

        cpu_source = source(root, cpu_boundary_policy.CPU)
        replace(cpu_source, "#![no_std]", "// #![no_std]")
        cpu_source.write_text(
            cpu_source.read_text(encoding="utf-8")
            + "\npub fn host_probe() { let _ = std::thread::available_parallelism(); }\n",
            encoding="utf-8",
        )
        refresh_source_hash(root, cpu_boundary_policy.CPU)
        require_rejection(root, "reopen security review")
        reset(root)

        cpu_source = source(root, cpu_boundary_policy.CPU)
        cpu_source.write_text(
            cpu_source.read_text(encoding="utf-8")
            + "\npub fn executable_operation(value: u8) -> u8 { value.wrapping_add(1) }\n",
            encoding="utf-8",
        )
        refresh_source_hash(root, cpu_boundary_policy.CPU)
        require_rejection(root, "reopen security review")
        reset(root)

        policy = root / cpu_boundary_policy.POLICY
        replace(policy, '  "side-channel-evidence",', '  "side-channel-review-waived",')
        require_rejection(root, "amendment contract")
        reset(root)

        policy = root / cpu_boundary_policy.POLICY
        replace(policy, '  "secret-free-failure",', '  "secret-bearing-failure",')
        require_rejection(root, "safe wrapper invariant")
        reset(root)

        policy = root / cpu_boundary_policy.POLICY
        replace(
            policy,
            'abi_preconditions = ["x86_64", "sha-usable-on-current-logical-cpu"]',
            'abi_preconditions = ["none"]',
        )
        require_rejection(root, "backend contract")
        reset(root)

        policy = root / cpu_boundary_policy.POLICY
        replace(policy, '  "foreign-abi",', '  "foreign-abi-allowed",')
        require_rejection(root, "amendment contract")
        reset(root)

        policy = root / cpu_boundary_policy.POLICY
        replace(policy, 'future_module = "brynja-fips-module"', 'future_module = "unbound"')
        require_rejection(root, "FIPS")
        reset(root)

        policy = root / cpu_boundary_policy.POLICY
        policy.write_text(policy.read_text(encoding="utf-8") + "\n# unreviewed drift\n", encoding="utf-8")
        require_rejection(root, "CPU security policy changed")
        reset(root)

        cpu_manifest = root / "crates" / cpu_boundary_policy.CPU / "Cargo.toml"
        cpu_manifest.write_text(
            cpu_manifest.read_text(encoding="utf-8")
            + "\n[dependencies]\nbrynja-core = { workspace = true }\n",
            encoding="utf-8",
        )
        require_rejection(root, "zero dependencies")
        reset(root)

        detector_manifest = root / "crates" / cpu_boundary_policy.DETECTOR / "Cargo.toml"
        replace(
            detector_manifest,
            "brynja-crypto-cpu = { workspace = true }",
            'brynja-crypto-cpu = { workspace = true }\nthird-party-detector = "1"',
        )
        require_rejection(root, "may depend only")
        reset(root)

        facade = root / "crates/brynja/Cargo.toml"
        replace(
            facade,
            "[dependencies]",
            "[dependencies]\nbrynja-crypto-cpu = { workspace = true }",
        )
        require_rejection(root, "entered the ordinary facade")
        reset(root)

        facade = root / "crates/brynja/Cargo.toml"
        replace(
            facade,
            "[dependencies]",
            "[dependencies]\nbrynja-crypto-cpu-std = { workspace = true }",
        )
        require_rejection(root, "entered the ordinary facade")
        reset(root)

        engine = root / "crates/brynja-tls13/Cargo.toml"
        replace(
            engine,
            "[dependencies]",
            "[dependencies]\nbrynja-crypto-cpu = { workspace = true }",
        )
        require_rejection(root, "dependency direction")
        reset(root)

        cpu_manifest = root / "crates" / cpu_boundary_policy.CPU / "Cargo.toml"
        replace(cpu_manifest, "[package]", '[package]\nbuild = "build.rs"')
        require_rejection(root, "build or native linking")


if __name__ == "__main__":
    test()
    print("CPU boundary rejects twenty-six package, graph, source, FIPS, and admission regressions")
