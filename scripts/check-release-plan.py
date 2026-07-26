#!/usr/bin/env python3
"""Validate release-plan structure and synchronization with the version plan."""

from __future__ import annotations

import re
import sys
from pathlib import Path

VERSION = r"(?:0\.[0-9]+\.[0-9]+|1\.0\.0(?:-rc\.[0-9]+)?)"
HEADING = re.compile(rf"^### (v{VERSION}) - (.+)$", re.MULTILINE)
VERSION_ROW = re.compile(
    rf"^\| `({VERSION})` \| ([^|]+) \| (.+) \|$",
    re.MULTILINE,
)
FIELDS = (
    "Status:",
    "Plan scope:",
    "Goal:",
    "Deliverables:",
    "Verification:",
    "Exit criteria:",
)


def expected_versions() -> list[str]:
    patch_releases = {
        3: (1, 2, 3, 4, 5),
        11: (1, 2),
        18: (1,),
        57: (1,),
        58: (1, 2, 3),
        76: (1, 2),
        83: (1, 2),
        99: (1,),
        111: (1,),
        123: (1,),
        124: (1, 2),
        127: (1,),
        130: (1,),
        131: (1,),
        132: (1, 2),
        134: (1, 2, 3),
        135: (1,),
        139: (1,),
        140: (1,),
        146: (1,),
    }
    versions = []
    for number in range(1, 163):
        versions.append(f"v0.{number}.0")
        versions.extend(
            f"v0.{number}.{patch}" for patch in patch_releases.get(number, ())
        )
    versions.extend(["v1.0.0-rc.1", "v1.0.0"])
    return versions


def version_entries(path: Path) -> list[tuple[str, str, str]]:
    text = path.read_text(encoding="utf-8")
    rows = [
        (f"v{match.group(1)}", match.group(2).strip(), match.group(3))
        for match in VERSION_ROW.finditer(text)
    ]
    versions = [version for version, _title, _scope in rows]
    if versions != expected_versions():
        raise ValueError("version plan is missing, duplicating, or reordering modern releases")
    return rows


def field_offset(section: str, field: str, version: str) -> int:
    matches = list(re.finditer(rf"^{re.escape(field)}", section, re.MULTILINE))
    if len(matches) != 1:
        raise ValueError(f"{version} must contain exactly one {field}")
    return matches[0].start()


def bullet_count(section: str, start: str, end: str) -> int:
    body = section.split(start, 1)[1].split(end, 1)[0]
    return sum(line.startswith("- ") for line in body.splitlines())


def validate(release_path: Path, version_path: Path) -> None:
    entries = version_entries(version_path)
    text = release_path.read_text(encoding="utf-8")
    matches = list(HEADING.finditer(text))
    versions = [match.group(1) for match in matches]
    expected = [version for version, _title, _scope in entries]

    if versions != expected:
        raise ValueError(
            "release plan versions differ from VERSION_PLAN.md "
            f"(expected {len(expected)} ordered sections, found {len(matches)})"
        )
    if len(versions) != len(set(versions)):
        raise ValueError("duplicate release versions")

    for index, (match, (version, planned_title, scope)) in enumerate(
        zip(matches, entries, strict=True)
    ):
        title = match.group(2).strip()
        if title != planned_title:
            raise ValueError(f"{version} title differs from VERSION_PLAN.md")
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        section = text[match.end():end]

        offsets = [field_offset(section, field, version) for field in FIELDS]
        if offsets != sorted(offsets):
            raise ValueError(f"{version} milestone fields are out of order")

        expected_scope = f"Plan scope: {scope}"
        scope_lines = [
            line for line in section.splitlines() if line.startswith("Plan scope:")
        ]
        if scope_lines != [expected_scope]:
            raise ValueError(f"{version} Plan scope differs from VERSION_PLAN.md")

        status_lines = [line for line in section.splitlines() if line.startswith("Status:")]
        if status_lines[0] not in ("Status: planned", "Status: awaiting pentest"):
            raise ValueError(f"{version} has an unsupported status")

        if bullet_count(section, "Deliverables:", "Verification:") < 3:
            raise ValueError(f"{version} requires at least three concrete deliverables")
        if bullet_count(section, "Verification:", "Exit criteria:") < 3:
            raise ValueError(f"{version} requires at least three verification classes")
        exit_body = section.split("Exit criteria:", 1)[1]
        if sum(line.startswith("- ") for line in exit_body.splitlines()) < 2:
            raise ValueError(f"{version} requires evidence and pentest exit criteria")

        exit_text = (
            f"`{version} implementation stop reached. "
            "Run pentest for this release candidate and commit the updated report.`"
        )
        if section.count(exit_text) != 1:
            raise ValueError(f"{version} is missing its exact pentest exit")

    print(
        f"release and version plans have {len(matches)} ordered, "
        "scope-locked, pentest-gated sections"
    )


def main() -> int:
    release_path = (
        Path(sys.argv[1]) if len(sys.argv) >= 2 else Path("docs/RELEASE_PLAN.md")
    )
    version_path = (
        Path(sys.argv[2]) if len(sys.argv) >= 3 else Path("docs/VERSION_PLAN.md")
    )
    try:
        validate(release_path, version_path)
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
