#!/usr/bin/env python3
"""Broken-fixture tests for the classified script tree."""

from __future__ import annotations

import importlib.util
import shutil
import stat
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-script-layout.py")
SPEC = importlib.util.spec_from_file_location("check_script_layout", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
layout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(layout)


def write(path: Path, data: str, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")
    if executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR)


def fixture() -> Path:
    root = Path(tempfile.mkdtemp(prefix="brynja-script-layout-"))
    scripts = root / "scripts"
    scripts.mkdir()
    shutil.copy2(Path(__file__).resolve().parents[1] / "inventory.toml", scripts)
    write(scripts / "README.md", "fixture\n")
    write(scripts / "checks.sh", "#!/usr/bin/env sh\n", executable=True)
    write(scripts / "tag_gate.sh", "#!/usr/bin/env sh\n", executable=True)
    policy = layout.read_policy(root)
    for index, (category, definition) in enumerate(policy["category"].items()):
        extension = definition["extensions"][0]
        write(scripts / category / f"fixture-{index}{extension}", "fixture\n")
    return root


def must_fail(root: Path, message: str) -> None:
    try:
        layout.validate(root)
    except layout.ScriptLayoutError:
        return
    raise AssertionError(message)


def main() -> int:
    roots: list[Path] = []
    try:
        valid = fixture()
        roots.append(valid)
        layout.validate(valid)

        unknown_root = fixture()
        roots.append(unknown_root)
        write(unknown_root / "scripts" / "mystery.sh", "#!/usr/bin/env sh\n")
        must_fail(unknown_root, "accepted an unknown root script")

        unknown_category = fixture()
        roots.append(unknown_category)
        write(unknown_category / "scripts" / "misc" / "check.py", "fixture\n")
        must_fail(unknown_category, "accepted an unclassified directory")

        nested = fixture()
        roots.append(nested)
        write(nested / "scripts" / "sha2" / "nested" / "check.py", "fixture\n")
        must_fail(nested, "accepted a nested category")

        duplicate = fixture()
        roots.append(duplicate)
        first = next((duplicate / "scripts" / "sha2").iterdir())
        write(duplicate / "scripts" / "cpu" / first.name, "fixture\n")
        must_fail(duplicate, "accepted a duplicate basename")
    finally:
        for root in roots:
            shutil.rmtree(root)
    print("script inventory rejects four classification regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
