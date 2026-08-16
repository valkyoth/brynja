#!/usr/bin/env python3
"""Validate the classified Brynja script tree."""

from __future__ import annotations

import argparse
import stat
import tomllib
from pathlib import Path


class ScriptLayoutError(RuntimeError):
    """The script tree violates its committed inventory."""


def fail(message: str) -> None:
    raise ScriptLayoutError(message)


def read_policy(root: Path) -> dict:
    path = root / "scripts" / "inventory.toml"
    try:
        policy = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read script inventory: {error}")
    if set(policy) != {"layout", "category"}:
        fail("script inventory must contain only layout and category tables")
    return policy


def visible_files(scripts: Path) -> list[Path]:
    return sorted(
        path
        for path in scripts.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    )


def validate(root: Path) -> int:
    scripts = root / "scripts"
    policy = read_policy(root)
    layout = policy["layout"]
    categories = policy["category"]
    if set(layout) != {"entrypoints", "root_files"}:
        fail("layout must define exactly root_files and entrypoints")
    if not categories:
        fail("script inventory must classify at least one category")

    root_files = set(layout["root_files"])
    entrypoints = set(layout["entrypoints"])
    if not entrypoints or not entrypoints <= root_files:
        fail("every script entry point must be an allowed root file")

    actual_root_files: set[str] = set()
    actual_categories: dict[str, int] = {name: 0 for name in categories}
    basenames: dict[str, str] = {}
    for path in visible_files(scripts):
        relative = path.relative_to(scripts)
        if len(relative.parts) == 1:
            actual_root_files.add(relative.name)
            continue
        if len(relative.parts) != 2:
            fail(f"script categories cannot contain nested directories: {relative}")
        category, name = relative.parts
        if category not in categories:
            fail(f"unclassified script directory: {category}")
        definition = categories[category]
        if set(definition) != {"extensions", "purpose"}:
            fail(f"category {category} must define extensions and purpose")
        if not str(definition["purpose"]).strip():
            fail(f"category {category} has no documented purpose")
        if path.suffix not in set(definition["extensions"]):
            fail(f"unsupported file type in {category}: {name}")
        if name in basenames:
            fail(f"duplicate script basename: {basenames[name]} and {relative}")
        basenames[name] = str(relative)
        actual_categories[category] += 1

    if actual_root_files != root_files:
        missing = sorted(root_files - actual_root_files)
        extra = sorted(actual_root_files - root_files)
        fail(f"root script inventory drift; missing={missing}, extra={extra}")
    empty = sorted(name for name, count in actual_categories.items() if count == 0)
    if empty:
        fail(f"empty script categories are forbidden: {empty}")

    executable_root = {
        name
        for name in actual_root_files
        if (scripts / name).stat().st_mode
        & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    }
    if executable_root != entrypoints:
        fail(
            "root executable inventory drift; "
            f"expected={sorted(entrypoints)}, actual={sorted(executable_root)}"
        )
    print(
        f"script inventory classifies {sum(actual_categories.values())} files "
        f"across {len(actual_categories)} owned directories"
    )
    return sum(actual_categories.values())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    try:
        validate(args.root.resolve())
    except ScriptLayoutError as error:
        print(error)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
