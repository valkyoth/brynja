#!/usr/bin/env python3
"""Track cumulative package-tree changes across a multi-tag release train."""

from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
# Only the package README transition in this reviewed directory refresh is
# eligible to ride the next real release. Never ignore README.md generically.
DIRECTORY_REFRESH = "8b89c300acc0a0d44321b5131b73970429d4d90a"
REPOSITORY_ONLY = frozenset(
    {
        "brynja-interop",
        "brynja-proofs",
        "brynja-research-ssl1",
        "brynja-test-support",
        "brynja-xtask",
    }
)

def changed_packages(
    packages: dict[str, dict],
    baseline: str,
) -> set[str]:
    """Find package trees changed after the preceding public tag."""

    tag = f"v{baseline}"
    if subprocess.run(
        ["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode != 0:
        raise RuntimeError(f"release baseline tag is missing: {tag}")
    changed: set[str] = set()
    for name, package in packages.items():
        package_root = Path(package["manifest_path"]).resolve().parent
        relative = package_root.relative_to(ROOT)
        tracked = subprocess.check_output(
            ["git", "diff", "--no-renames", "--name-only", tag, "--", str(relative)],
            cwd=ROOT,
            text=True,
        ).strip()
        untracked = subprocess.check_output(
            [
                "git",
                "ls-files",
                "--others",
                "--exclude-standard",
                "--",
                str(relative),
            ],
            cwd=ROOT,
            text=True,
        ).strip()
        readme = relative / "README.md"
        if (not untracked and tracked == str(readme)
                and reviewed_directory_refresh(tag, readme)):
            continue
        if tracked or untracked:
            changed.add(name)
    return changed


def reviewed_directory_refresh(baseline: str, path: Path) -> bool:
    # Compare both endpoints (including file type/mode), not just the current
    # blob. An older outstanding README correction must not disappear either.
    # A shallow clone without the reviewed commit simply cannot defer the bump.
    return all(subprocess.run(
        ["git", "diff", "--no-ext-diff", "--no-textconv", "--quiet", *refs, "--", str(path)],
        cwd=ROOT, stderr=subprocess.DEVNULL, check=False,
    ).returncode == 0 for refs in (
        (baseline, DIRECTORY_REFRESH + "^"), (DIRECTORY_REFRESH,),
    ))


def validate_cumulative_changes(plan: dict, changed: set[str]) -> None:
    """Forbid losing a package delta inside a multi-tag release train."""

    for name in changed:
        if name in REPOSITORY_ONLY:
            continue
        entry = plan["crates"][name]
        if entry["previous_version"] == "unpublished":
            continue
        if entry["change"] == "unchanged":
            raise RuntimeError(
                f"{name} changed after v{plan['baseline']} but is marked unchanged"
            )
