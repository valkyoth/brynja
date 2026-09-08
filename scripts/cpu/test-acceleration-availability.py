#!/usr/bin/env python3
"""Reject policy drift and compiled selection/lifecycle contract regressions."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import acceleration_availability as contract


def run(command: list[str], root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=180,
                          env={**os.environ, "CARGO_TERM_COLOR": "never"})


def policy_mutations() -> int:
    mutations = [
        ("state = \"contract-only-zero-activations\"", "state = \"operational\""),
        ("default_mode = \"Portable\"", "default_mode = \"Prefer\""),
        ("ordinary_operational = false", "ordinary_operational = true"),
        ("hardened_operational = false", "hardened_operational = true"),
        ("independent_review = false", "independent_review = true"),
        ("fips_validated = false", "fips_validated = true"),
        ("independent_review_required_for_ordinary_use = false", "independent_review_required_for_ordinary_use = true"),
        ("fips_certificate_required_for_ordinary_use = false", "fips_certificate_required_for_ordinary_use = true"),
        ("evidence_cfg_is_public_availability = false", "evidence_cfg_is_public_availability = true"),
        ("cargo_feature_is_cpu_authority = false", "cargo_feature_is_cpu_authority = true"),
        ("safe_boolean_is_cpu_authority = false", "safe_boolean_is_cpu_authority = true"),
        ("hidden_fallback = false", "hidden_fallback = true"),
        ("public_operational = false", "public_operational = true"),
        ("terminal-for-prefer-and-require", "silent-portable-fallback"),
        ("quarantine-no-fallback", "retry-other-backend"),
        ("SHA-512/t", "SHA-512/384"),
        ("lanes = 8", "lanes = 4"),
        ("compiler_features = [\"avx2\"]", "compiler_features = []"),
    ]
    with tempfile.TemporaryDirectory(prefix="brynja-availability-policy-") as tmp:
        root = Path(tmp)
        for name in [*contract.paths(contract.ROOT), contract.REVIEW]:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contract.read(contract.ROOT, name))
        contract.validate(root)
        path = root / contract.POLICY
        original = path.read_text()
        for before, after in mutations:
            if before not in original:
                raise AssertionError(f"stale mutation: {before}")
            path.write_text(original.replace(before, after, 1))
            try:
                contract.validate(root)
            except ValueError:
                pass
            else:
                raise AssertionError(f"accepted mutation: {before}")
        path.write_text(original)
        source = root / contract.FIXTURE / "src/selection.rs"
        source.write_text(source.read_text().replace("project_ready: false", "project_ready: true"))
        try:
            contract.validate(root)
        except ValueError:
            pass
        else:
            raise AssertionError("accepted source drift")
        source.write_bytes(contract.read(contract.ROOT, f"{contract.FIXTURE}/src/selection.rs"))
        review = root / contract.REVIEW
        review.write_text(review.read_text().replace('"schema": 1', '"schema": true', 1))
        try:
            contract.validate(root)
        except ValueError:
            return len(mutations) + 2
        raise AssertionError("accepted boolean review schema as integer")


def compiled_mutations() -> int:
    mutations = (
        ("!evidence.project_ready || !evidence.public_reachable", "!evidence.project_ready"),
        ("!evidence.project_ready || !evidence.public_reachable", "!evidence.public_reachable"),
        ("!evidence.platform_supported", "false"),
        ("!evidence.hardened_ready", "false"),
        ("!evidence.healthy", "false"),
        ("Some(Error::Quarantined) => Err(Error::Quarantined),", ""),
        ("matches!(request, Request::Prefer(_, _))", "true"),
        ("Route::Accelerated(backend, profile)", "Route::Portable(None)"),
        ("if self.failure.is_none()", "if true"),
    )
    with tempfile.TemporaryDirectory(prefix="brynja-availability-model-") as tmp:
        root = Path(tmp)
        shutil.copytree(contract.ROOT / contract.FIXTURE / "src", root / "src")
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copyfile(contract.ROOT / contract.FIXTURE / name, root / name)
        source = root / "src/selection.rs"
        original = source.read_text()
        for release in (False, True):
            base = ["cargo", "test", "--locked", "--offline", "--lib"]
            if release:
                base.append("--release")
            source.write_text(original)
            positive = run(base, root)
            if positive.returncode:
                raise AssertionError(positive.stdout + positive.stderr)
            for before, after in mutations:
                if before not in original:
                    raise AssertionError(f"stale model mutation: {before}")
                source.write_text(original.replace(before, after, 1))
                compiled = run(base + ["--no-run"], root)
                if compiled.returncode:
                    raise AssertionError("mutant failed to compile:\n" + compiled.stderr)
                result = run(base, root)
                if result.returncode == 0 or "test result: FAILED" not in result.stdout:
                    raise AssertionError(f"mutant not killed by tests: {before}\n{result.stdout}\n{result.stderr}")
        return len(mutations) * 2


def main() -> int:
    contract.validate()
    policies = policy_mutations()
    compiled = compiled_mutations()
    print(f"Acceleration contract rejects {policies} policy/source and {compiled} compiled regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
