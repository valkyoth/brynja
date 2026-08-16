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

INTERNAL_EXIT = (
    "`{version} development milestone reached. Commit the verified scope, "
    "obtain green GitHub and CodeQL, then create the signed tag without a "
    "scheduled pentest or crates.io publication unless an exceptional "
    "trigger applies.`"
)
CHECKPOINT_EXIT = (
    "`{version} scheduled release checkpoint reached. Pentest all changes "
    "after the previous public tag through this candidate, commit the PASS "
    "report, obtain green GitHub and CodeQL, then create the signed tag and "
    "publish the selected crates.`"
)
HISTORICAL_EXIT = (
    "`{version} implementation stop reached. Run pentest for this release "
    "candidate and commit the updated report.`"
)


def expected_versions() -> list[str]:
    patch_releases = {
        3: (1, 2, 3, 4, 5),
        11: (1, 2),
        13: (1, 2, 3),
        18: (1,),
        22: (1, 2, 3),
        23: (1, 2, 3, 4),
        24: (1, 2, 3, 4, 5),
        25: (1, 2),
        26: (1,),
        27: (1, 2, 3),
        28: (1, 2),
        29: (1, 2),
        30: (1,),
        31: (1, 2),
        35: (1, 2),
        38: (1, 2),
        41: (1, 2),
        44: (1, 2),
        45: (1, 2, 3, 4, 5, 6, 7),
        46: tuple(range(1, 33)),
        47: (1,),
        57: (1,),
        58: (1, 2, 3),
        60: (1, 2, 3, 4, 5),
        76: (1, 2),
        82: (1, 2, 3, 4, 5),
        83: (1, 2),
        90: (1,),
        92: (1, 2, 3, 4, 5, 6),
        99: (1,),
        111: (1,),
        114: (1, 2),
        119: (1, 2),
        123: (1,),
        124: (1, 2),
        127: (1,),
        130: (1,),
        131: (1,),
        132: (1, 2),
        134: (1, 2, 3),
        135: (1,),
        139: (1, 2, 3, 4, 5),
        140: (1,),
        146: (1,),
        148: (1, 2, 3, 4, 5, 6, 7),
        151: (1, 2, 3, 4),
        163: (1,),
        164: (1, 2),
        166: (1, 2),
        167: (1,),
        168: (1, 2, 3, 4),
        169: tuple(range(1, 16)),
        171: (1, 2),
        172: (1,),
        173: (1, 2),
        174: (1,),
        176: (1,),
        177: (1,),
        178: (1, 2),
        179: (1, 2, 3),
        180: tuple(range(1, 25)),
    }
    versions = []
    for number in range(1, 186):
        versions.append(f"v0.{number}.0")
        versions.extend(
            f"v0.{number}.{patch}" for patch in patch_releases.get(number, ())
        )
    versions.extend(["v1.0.0-rc.1", "v1.0.0"])
    return versions


def is_scheduled_checkpoint(version: str) -> bool:
    """Classify public checkpoints after the historical v0.10.0 boundary."""
    if version.startswith("v1."):
        return True
    major, minor, patch = version.removeprefix("v").split(".")
    if major != "0":
        raise ValueError(f"unsupported release-plan version: {version}")
    minor_number = int(minor)
    patch_number = int(patch)
    if minor_number <= 10:
        return True
    return patch_number == 0 and minor_number % 5 == 0


def expected_exit(version: str) -> str:
    if version.startswith("v1.") or version.removeprefix("v").split(".")[1] in {
        str(number) for number in range(1, 11)
    }:
        return HISTORICAL_EXIT.format(version=version)
    template = CHECKPOINT_EXIT if is_scheduled_checkpoint(version) else INTERNAL_EXIT
    return template.format(version=version)


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


def has_concrete_detail(section: str, start: str, end: str) -> bool:
    """Accept three classes or one dense, explicitly scoped checklist item."""
    body = section.split(start, 1)[1].split(end, 1)[0]
    bullets = [line[2:].strip() for line in body.splitlines() if line.startswith("- ")]
    return len(bullets) >= 3 or (len(bullets) >= 1 and sum(map(len, bullets)) >= 70)


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
        if status_lines[0] not in (
            "Status: planned",
            "Status: awaiting pentest",
            "Status: awaiting green CI",
            "Status: released",
        ):
            raise ValueError(f"{version} has an unsupported status")

        if not has_concrete_detail(section, "Deliverables:", "Verification:"):
            raise ValueError(
                f"{version} requires three concrete deliverables or one detailed checklist"
            )
        if not has_concrete_detail(section, "Verification:", "Exit criteria:"):
            raise ValueError(
                f"{version} requires three verification classes or one detailed checklist"
            )
        exit_body = section.split("Exit criteria:", 1)[1]
        if sum(line.startswith("- ") for line in exit_body.splitlines()) < 2:
            raise ValueError(f"{version} requires evidence and cadence exit criteria")

        exit_text = expected_exit(version)
        if section.count(exit_text) != 1:
            release_class = (
                "scheduled checkpoint"
                if is_scheduled_checkpoint(version)
                else "development milestone"
            )
            raise ValueError(f"{version} is missing its exact {release_class} exit")

    checkpoints = sum(is_scheduled_checkpoint(version) for version in versions)
    print(
        f"release and version plans have {len(matches)} ordered, "
        f"scope-locked sections: {checkpoints} public checkpoints and "
        f"{len(matches) - checkpoints} tagged development milestones"
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
