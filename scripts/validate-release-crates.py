#!/usr/bin/env python3
"""Validate the foundation release crate inventory."""

from __future__ import annotations

import json
import subprocess
import tomllib
from pathlib import Path


def main() -> int:
    release = tomllib.loads(Path("release-crates.toml").read_text(encoding="utf-8"))
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--format-version", "1", "--no-deps"],
            text=True,
        )
    )
    packages = {package["name"]: package for package in metadata["packages"]}
    entries = release["crates"]
    if set(entries) != set(packages):
        missing = sorted(set(packages) - set(entries))
        extra = sorted(set(entries) - set(packages))
        raise ValueError(f"release inventory differs: missing={missing}, extra={extra}")
    for name, package in packages.items():
        entry = entries[name]
        if entry["version"] != package["version"]:
            raise ValueError(f"version mismatch for {name}")
        if entry["publish"] or package["publish"] != []:
            raise ValueError(f"foundation package is publishable: {name}")
        if entry["change"] != "unpublished":
            raise ValueError(f"invalid foundation change classification: {name}")
    print("release crate inventory matches all unpublished workspace packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

