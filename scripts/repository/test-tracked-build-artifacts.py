#!/usr/bin/env python3
"""Exercise positive and broken tracked Cargo artifact fixtures."""

from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-tracked-build-artifacts.py")
SPEC = importlib.util.spec_from_file_location("check_tracked_build_artifacts", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


def reject(paths: list[str]) -> None:
    try:
        policy.validate_paths(paths)
    except policy.TrackedBuildArtifactError:
        return
    raise AssertionError(f"tracked Cargo artifact was accepted: {paths}")


def main() -> int:
    policy.validate_paths(
        [
            "Cargo.toml",
            "crates/brynja-core/src/lib.rs",
            "docs/target",
            "docs/target-platforms.md",
            "target-notes/README.md",
        ]
    )
    reject(["target/debug/brynja"])
    reject(["assurance/fixture/target/release/fixture"])
    reject(["crates/example/target/.rustc_info.json"])
    print("tracked Cargo build-artifact policy rejects three target-directory regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
