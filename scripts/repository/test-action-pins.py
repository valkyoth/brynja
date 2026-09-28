#!/usr/bin/env python3
"""Exercise the real offline action-pin block without network/tool updates."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PIN = "3d3c42e5aac5ba805825da76410c181273ba90b1"


def check(block, workflows, expected):
    with tempfile.TemporaryDirectory(prefix="brynja-action-pins-") as temporary:
        root = Path(temporary)
        directory = root / ".github/workflows"
        directory.mkdir(parents=True)
        for name, text in workflows.items():
            (directory / name).write_text(text, encoding="utf-8")
        result = subprocess.run(["sh", "-eu", "-c", block], cwd=root,
                                text=True, capture_output=True, timeout=10)
        assert (result.returncode == 0) == expected, result.stdout + result.stderr
        if not expected:
            assert "GitHub Action is not pinned to a full SHA" in result.stdout


def regressions(block):
    count = 0
    for prefix in ("        uses: ", "      - uses: "):
        for action in (f"actions/checkout@{PIN}", f'"actions/checkout@{PIN}"',
                       f"'actions/checkout@{PIN}'"):
            check(block, {"fixture.yml": prefix + action + " # pinned\n"}, True)
            count += 1
        for action in ("", "actions/checkout", "actions/checkout@",
                       "actions/checkout@v7", "actions/checkout@main",
                       "actions/checkout@" + PIN[:7], "actions/checkout@" + PIN + "0",
                       "actions/checkout@" + PIN.upper(), "actions/checkout@" + "g" * 40,
                       "actions/checkout@extra@" + PIN):
            check(block, {"fixture.yml": prefix + action + "\n"}, False)
            count += 1
    check(block, {"run-only.yml": "steps:\n  - run: echo ok\n"}, True)
    check(block, {"comments.yml": "# - uses: actions/checkout@main\n"}, True)
    check(block, {"good.yml": f"  uses: actions/checkout@{PIN}\n",
                  "bad.yml": "  - uses: actions/checkout@main\n"}, False)
    check(block, {path.name: path.read_text() for path in
                  (ROOT / ".github/workflows").glob("*.yml")}, True)
    return count + 4


def main():
    driver = (ROOT / "scripts/ci/check_latest_tools.sh").read_text()
    start, end = "# BEGIN ACTION PIN CHECK", "# END ACTION PIN CHECK"
    assert driver.count(start) == driver.count(end) == 1
    block = driver.split(start, 1)[1].split(end, 1)[0]
    count = regressions(block)
    mutants = (
        block.replace("(-[[:space:]]+)?", ""),
        block.replace("length(parts[2]) != 40", "length(parts[2]) < 7"),
        block.replace("[0-9a-f]+$", "[0-9a-zA-Z]+$"),
        block.replace("failed = 1", "failed = 0"),
    )
    for mutant in mutants:
        assert mutant != block
        try:
            regressions(mutant)
        except AssertionError:
            continue
        raise AssertionError("action-pin parser mutation escaped regression tests")
    print(f"Action-pin parser: {count} cases passed; four parser/pin mutations rejected")


if __name__ == "__main__":
    main()
