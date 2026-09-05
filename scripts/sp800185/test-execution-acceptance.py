#!/usr/bin/env python3
"""Frozen-contract, report, native-lane and executable corruption regressions."""

from __future__ import annotations

import os
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import execution_acceptance as acceptance
import native_capture


def rejects(function, *args) -> None:
    try:
        function(*args)
    except (acceptance.ExecutionError, RuntimeError):
        return
    raise AssertionError("unsafe evidence input was accepted")


def policy_tests() -> None:
    acceptance.validate()
    good = "\n".join(acceptance.REPORT)
    acceptance.check_report(good)
    for line in acceptance.REPORT:
        rejects(acceptance.check_report, good.replace(line, ""))
        rejects(acceptance.check_report, good + "\n" + line)
    rejects(acceptance.check_report, good + "\nFAIL")
    for lane, (system, machine, vendor) in native_capture.LANES.items():
        native_capture.validate_host(lane, system, machine, vendor or "test CPU")
        rejects(native_capture.validate_host, lane, "wrong-os", machine, vendor or "")
        rejects(native_capture.validate_host, lane, system, "wrong-arch", vendor or "")
        if vendor:
            rejects(native_capture.validate_host, lane, system, machine, "wrong-vendor")
    rejects(native_capture.validate_host, "unknown", "Linux", "x86_64", "")
    native_capture.check_environment({})
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                 "RUSTC", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET",
                 "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER", "CARGO_BUILD_RUSTFLAGS"):
        rejects(native_capture.check_environment, {name: "override"})
    with patch.object(acceptance, "execute", return_value=" M changed.rs\n"):
        rejects(native_capture.clean_commit)
    with patch.object(acceptance, "execute", side_effect=["", "not-a-commit"]):
        rejects(native_capture.clean_commit)
    with patch.object(acceptance, "execute", side_effect=["", "a" * 40]):
        assert native_capture.clean_commit() == "a" * 40
    frozen = acceptance.tomllib.loads(acceptance.read(acceptance.ROOT, acceptance.FROZEN))
    with tempfile.TemporaryDirectory(prefix="brynja-execution-policy-") as directory:
        root = Path(directory)
        for relative in (*acceptance.FILES, acceptance.HASHES,
                         *(Path(p) for p in frozen["files"])):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(acceptance.ROOT / relative, target)
        acceptance.validate(root)
        for relative in (acceptance.FIXTURE / "src/lib.rs", Path(next(iter(frozen["files"]))),
                         Path("scripts/checks.sh")):
            target = root / relative
            original = target.read_text(encoding="utf-8")
            target.write_text(original + "\n// unreviewed change\n", encoding="utf-8")
            rejects(acceptance.validate, root)
            target.write_text(original, encoding="utf-8")


def executable_tests() -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-execution-live-") as directory:
        root = Path(directory)
        fixture = root / "fixture"
        source = acceptance.ROOT / acceptance.FIXTURE
        shutil.copytree(source / "src", fixture / "src")
        shutil.copy2(source / "Cargo.lock", fixture / "Cargo.lock")
        manifest = (source / "Cargo.toml").read_text(encoding="utf-8")
        manifest = manifest.replace("../../crates/", acceptance.ROOT.as_posix() + "/crates/")
        manifest = manifest.replace("../sp800185-public-api", (
            acceptance.ROOT / "assurance/sp800185-public-api").as_posix())
        (fixture / "Cargo.toml").write_text(manifest, encoding="utf-8")
        environment = dict(os.environ, CARGO_TARGET_DIR=str(root / "target"))
        binary = root / "target/debug/brynja-sp800185-final-fixture"
        if os.name == "nt":
            binary = binary.with_suffix(".exe")

        def execute(error=None, arguments=()) -> None:
            result = subprocess.run(
                ["cargo", "build", "--quiet", "--locked", "--offline", "--manifest-path",
                 str(fixture / "Cargo.toml")], env=environment, capture_output=True,
                text=True, timeout=300, check=False,
            )
            assert result.returncode == 0, result.stderr
            result = subprocess.run([str(binary), *arguments], capture_output=True,
                                    text=True, timeout=60, check=False)
            if error is None:
                assert result.returncode == 0, result.stderr
                acceptance.check_report(result.stdout)
            elif error == "arguments":
                assert result.returncode == 2 and "PASS" not in result.stdout
            else:
                assert result.returncode == 1 and "PASS" not in result.stdout
                assert result.stderr.strip() == f"SP 800-185 execution acceptance: FAIL: {error}"

        execute()
        execute("arguments", ["--unexpected"])
        path = fixture / "src/parallel.rs"
        original = path.read_text(encoding="utf-8")
        # Corrupt each distinct byte, bit and scheduled comparison at runtime.
        marker = "if actual != expected"
        assert original.count(marker) == 3
        for occurrence in range(3):
            parts = original.split(marker)
            parts[occurrence] += "actual[0] ^= 1; "
            path.write_text(marker.join(parts), encoding="utf-8")
            execute("Parallel")
        path.write_text(original.replace(
            "if !accepted_error || $output != [0xa5; OUTPUT]",
            "$output[0] ^= 1; if !accepted_error || $output != [0xa5; OUTPUT]",
        ), encoding="utf-8")
        execute("Failure")
        path.write_text(original, encoding="utf-8")
        execute()


def capture_tests() -> None:
    """Exercise successful/failed report creation without inventing native evidence."""
    commit = "a" * 40

    def command(args, seconds=300):
        if args[:2] == ["git", "status"]:
            return ""
        if args[:2] == ["git", "rev-parse"]:
            return commit
        if args[0] == "rustc":
            return "rustc 1.98.1 (test compiler)"
        if "--benchmark" in args:
            return "\n".join(acceptance.REPORT) + "\n" + "benchmark: test\n" * 12
        if "test" in args:
            return "running 3 tests\ntest result: ok. 3 passed; 0 failed\n"
        return "KMAC tag comparison timing: test fixture only\n"

    previous = Path.cwd()
    try:
        with tempfile.TemporaryDirectory(prefix="brynja-native-report-test-") as directory:
            root = Path(directory)
            destination = root / "report.json"
            with (
                patch.object(acceptance, "ROOT", root),
                patch.object(acceptance, "validate"),
                patch.object(acceptance, "read", return_value="[files]\n"),
                patch.object(acceptance, "execute", side_effect=command),
                patch.object(native_capture.platform, "system", return_value="Linux"),
                patch.object(native_capture.platform, "machine", return_value="x86_64"),
                patch.object(Path, "read_text", return_value="AuthenticAMD"),
                patch.dict(os.environ, {}, clear=True),
            ):
                native_capture.capture("local-amd-x86_64", destination)
                rejects(native_capture.capture, "local-amd-x86_64", destination)
                with patch.object(acceptance, "execute", side_effect=acceptance.ExecutionError("failed")):
                    rejects(native_capture.capture, "local-amd-x86_64", root / "failed.json")
                assert not (root / "failed.json").exists()
                for marker in ("--benchmark", "brynja-hash-parallel-std", "brynja-crypto-cpu",
                               "assurance/kmac-timing/Cargo.toml"):
                    def failed_command(args, seconds=300):
                        if marker in args:
                            raise acceptance.ExecutionError("injected child failure")
                        return command(args, seconds)
                    with patch.object(acceptance, "execute", side_effect=failed_command):
                        rejects(native_capture.capture, "local-amd-x86_64", root / "failed.json")
                    assert not (root / "failed.json").exists()
            report = json.loads(destination.read_text(encoding="utf-8"))
            assert report["status"] == "PENDING_REVIEW" and report["commit"] == commit
            assert report["admitted_keccak_backends"] == []
            assert report["native_operator_attestation_required"] is True
            assert set(report["commands"]) == {"execution", "worker_faults", "candidate_kat", "tag_timing"}
            assert all(acceptance.digest(value) == report["stdout_sha256"][key]
                       for key, value in report["stdout"].items())
            assert all(word not in report for word in ("hostname", "username", "ip", "serial"))
            os.chdir(previous)
    finally:
        os.chdir(previous)


def main() -> int:
    policy_tests()
    capture_tests()
    executable_tests()
    print("SP 800-185 frozen, native-lane, report and four live corruption regressions: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
