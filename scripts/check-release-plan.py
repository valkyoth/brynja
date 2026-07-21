#!/usr/bin/env python3
"""Validate mandatory structure and pentest exits in the release plan."""

from __future__ import annotations

import re
import sys
from pathlib import Path

HEADING = re.compile(
    r"^#{2,3} (v(?:0\.[0-9]+\.0|1\.0\.0(?:-rc\.[0-9]+)?)) - .+$",
    re.MULTILINE,
)


def validate(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    matches = list(HEADING.finditer(text))
    if len(matches) != 97:
        raise ValueError(f"expected 97 version sections, found {len(matches)}")
    versions: list[str] = []
    for index, match in enumerate(matches):
        version = match.group(1)
        versions.append(version)
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        section = text[match.end():end]
        for field in ("Status:", "Goal:", "Deliverables:", "Verification:", "Exit criteria:"):
            if field not in section:
                raise ValueError(f"{version} is missing {field}")
        exit_text = f"{version} implementation stop reached. Run pentest for this exact commit."
        if exit_text not in section:
            raise ValueError(f"{version} is missing its exact pentest exit")
    if len(versions) != len(set(versions)):
        raise ValueError("duplicate release versions")
    expected = [f"v0.{number}.0" for number in range(1, 96)]
    expected.extend(["v1.0.0-rc.1", "v1.0.0"])
    if versions != expected:
        raise ValueError("release versions are missing or out of order")
    print("release plan has 97 ordered, pentest-gated version sections")


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else Path("docs/RELEASE_PLAN.md")
    try:
        validate(path)
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
