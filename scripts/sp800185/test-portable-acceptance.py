#!/usr/bin/env python3
"""Adversarial tests for the portable SP 800-185 closure policy."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import portable_acceptance


def live_output_mutations() -> int:
    """Compile and execute each corrupt-output case, not just token checks.

    Mutate a public test-only copy at the observation boundary. Leave the
    real owner and Drop intact, reproducing the original cleanup-only blind
    spot without adding mutation hooks to production cryptography.
    """
    count = 0
    with tempfile.TemporaryDirectory(prefix="brynja-sp800185-live-") as directory:
        root = Path(directory)
        fixture = root / "fixture"
        source_root = portable_acceptance.ROOT / portable_acceptance.FIXTURE
        shutil.copytree(source_root / "src", fixture / "src")
        shutil.copytree(source_root / "fixtures", fixture / "fixtures")
        shutil.copy2(source_root / "Cargo.lock", fixture / "Cargo.lock")
        manifest = (source_root / "Cargo.toml").read_text(encoding="utf-8")
        manifest = manifest.replace(
            "../../crates/", portable_acceptance.ROOT.as_posix() + "/crates/",
        )
        (fixture / "Cargo.toml").write_text(manifest, encoding="utf-8")
        environment = dict(os.environ, CARGO_TARGET_DIR=str(root / "target"))
        executable = root / "target/debug/brynja-sp800185-public-api-fixture"
        if os.name == "nt":
            executable = executable.with_suffix(".exe")

        def execute(expected_error: str | None = None) -> None:
            build = subprocess.run(
                ["cargo", "build", "--quiet", "--locked", "--offline",
                 "--manifest-path", str(fixture / "Cargo.toml")],
                env=environment, cwd=portable_acceptance.ROOT,
                capture_output=True, text=True, timeout=300, check=False,
            )
            if build.returncode != 0:
                raise AssertionError(f"mutation failed to compile:\n{build.stderr}")
            result = subprocess.run(
                [str(executable)], capture_output=True, text=True,
                timeout=30, check=False,
            )
            if expected_error is None:
                if result.returncode != 0 or "public API acceptance: PASS" not in result.stdout:
                    raise AssertionError(f"pristine fixture failed: {result}")
            else:
                expected_stderr = (
                    "SP 800-185 portable public API acceptance: FAIL: " + expected_error
                )
                if (
                    result.returncode != 1
                    or result.stderr.strip() != expected_stderr
                    or "PASS" in result.stdout
                ):
                    raise AssertionError(f"wrong mutation disposition: {expected_error}: {result}")

        execute()
        for name, error in (
            ("cshake", "Cshake"), ("kmac", "Kmac"),
            ("tuplehash", "TupleHash"), ("parallelhash", "ParallelHash"),
        ):
            path = fixture / f"src/{name}.rs"
            original = path.read_text(encoding="utf-8")
            outputs = (("128", 32), ("256", 67)) if name == "cshake" else (
                ("_fixed128", 32), ("_fixed256", 64),
                ("_xof128", 37), ("_xof256", 73),
            )
            for output, size in outputs:
                token = f"if secret.expose() != expected{output} {{"
                if original.count(token) != 1:
                    raise AssertionError(f"missing or ambiguous live-output comparison: {token}")
                for damage in (
                    "corrupted.fill(0);", "corrupted.fill(0x42);",
                    f"corrupted[{size - 1}] ^= 1;",
                ):
                    observed = (
                        f"{{ let mut corrupted = [0_u8; {size}]; "
                        "corrupted.copy_from_slice(secret.expose()); "
                        f"{damage} corrupted }}"
                    )
                    mutated = original.replace(
                        token, f"if {observed} != expected{output} {{", 1,
                    )
                    try:
                        path.write_text(mutated, encoding="utf-8")
                        execute(error)
                    finally:
                        path.write_text(original, encoding="utf-8")
                    count += 1
        execute()
    return count


def reject(relative: Path, old: str, new: str) -> None:
    with tempfile.TemporaryDirectory(prefix="brynja-sp800185-mutation-") as directory:
        root = Path(directory)
        for item in (*portable_acceptance.FILES, portable_acceptance.HASHES):
            target = root / item
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(portable_acceptance.ROOT / item, target)
        target = root / relative
        text = target.read_text(encoding="utf-8")
        if old not in text:
            raise AssertionError(f"missing mutation token: {relative}: {old}")
        target.write_text(text.replace(old, new, 1), encoding="utf-8")
        try:
            portable_acceptance.validate(root, check_hashes=False)
        except portable_acceptance.PortableAcceptanceError:
            return
        raise AssertionError(f"portable policy accepted mutation: {relative}: {old}")


def main() -> int:
    fixture = portable_acceptance.FIXTURE
    cases = (
        (fixture / "src/lib.rs", "        identities: 14,", "        identities: 13,"),
        (fixture / "src/lib.rs", "#![no_std]", "extern crate std;"),
        (
            fixture / "src/cshake.rs",
            "let mut state = HardenedCshake256::new",
            "let mut state = Cshake256::new",
        ),
        (fixture / "src/kmac.rs", "Kmac128::new_conformance", "Kmac128::new"),
        (
            fixture / "src/tuplehash.rs",
            "let mut item = fixed.begin_item(48)",
            "let mut item = fixed.push_item(48)",
        ),
        (
            fixture / "src/parallelhash.rs",
            "let plan = ParallelHash256Plan::new",
            "let plan = ParallelHash128Plan::new",
        ),
        (fixture / "src/main.rs", "independently verified: NO", "independently verified: YES"),
        (Path("README.md"), "portable acceptance passed at v0.24.16", "portable acceptance pending"),
        (
            Path("docs/RELEASE_PLAN.md"),
            "### v0.24.16 - SP 800-185 Portable Public API Usability Acceptance\n\nStatus: awaiting green CI",
            "### v0.24.16 - SP 800-185 Portable Public API Usability Acceptance\n\nStatus: released",
        ),
        (Path("scripts/checks.sh"), "python3 scripts/sp800185/check-portable-acceptance.py", "true"),
        (Path(".github/workflows/ci.yml"), "assurance/sp800185-public-api/Cargo.toml", "assurance/cshake-public-api/Cargo.toml"),
    )
    for case in cases:
        reject(*case)
    comparison_count = 0
    for name in ("cshake", "kmac", "tuplehash", "parallelhash"):
        outputs = ("128", "256") if name == "cshake" else (
            "_fixed128", "_fixed256", "_xof128", "_xof256",
        )
        for output in outputs:
            reject(
                fixture / f"src/{name}.rs",
                f"if secret.expose() != expected{output} {{", "if false {",
            )
            comparison_count += 1
    with tempfile.TemporaryDirectory(prefix="brynja-sp800185-hash-") as directory:
        root = Path(directory)
        for item in (*portable_acceptance.FILES, portable_acceptance.HASHES):
            target = root / item
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(portable_acceptance.ROOT / item, target)
        target = root / portable_acceptance.MAIN
        target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        try:
            portable_acceptance.validate(root)
        except portable_acceptance.PortableAcceptanceError:
            pass
        else:
            raise AssertionError("portable reviewed-hash drift was accepted")
    print(f"SP 800-185 portable policy rejects {len(cases) + comparison_count + 1} closure regressions")
    count = live_output_mutations()
    print(f"SP 800-185 live hardened output rejects {count} executable corruptions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
