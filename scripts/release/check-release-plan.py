#!/usr/bin/env python3
"""Validate release-plan structure and synchronization with the version plan."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import catalogue_plan
import roadmap_schedule

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

# Public-operation closure is required before executable downstream use.
API_CLOSURE_EDGES = (
    ("v0.34.6", "v0.39.0"),
    ("v0.34.6", "v0.77.2"),
    ("v0.34.6", "v0.103.0"),
    ("v0.49.6", "v0.91.0"),
    ("v0.50.1", "v0.186.1"),
    ("v0.89.2", "v0.90.0"),
    ("v0.90.7", "v0.91.0"),
    ("v0.141.1", "v0.142.0"),
    ("v0.163.4", "v0.166.1"),
    ("v0.166.2", "v0.166.3"),
    ("v0.166.3", "v0.167.0"),
    ("v0.216.3", "v0.218.0"),
    ("v0.217.1", "v0.221.0"),
    ("v0.235.2", "v0.237.2"),
    ("v0.351.1", "v0.352.0"),
)

API_SCOPE_CONTRACTS = {
    "v0.34.0": ("brynja-encoding-der", "compatibility re-exports"),
    "v0.34.6": ("encode/decode", "independent encodings", "hardened"),
    "v0.49.5": ("signing and verification", "DER"),
    "v0.50.0": ("static", "single-use ephemeral", "protocol-domain"),
    "v0.89.2": ("encode/decode", "typed-secret"),
    "v0.90.7": ("import/export", "independent-tool"),
    "v0.104.0": ("non-executable", "v0.166.1"),
    "v0.104.2": ("without executing unavailable", "v0.166.2"),
    "v0.141.0": ("parsing and encoding", "received-byte"),
    "v0.216.1": ("secret-bearing unkeyed BLAKE2b", "typed secret"),
    "v0.218.0": ("v0.216.3 BLAKE2b", "H-prime"),
    "v0.221.0": ("v0.217.1 AES-CMAC", "seal/open"),
    "v0.235.2": ("export", "typed-secret unprotected", "import"),
    "v0.351.1": ("public package", "complete safe operation directions"),
}


def validate_api_closure(entries: list[tuple[str, str, str]]) -> None:
    positions = {version: index for index, (version, _, _) in enumerate(entries)}
    scopes = {version: scope for version, _, scope in entries}
    for prerequisite, consumer in API_CLOSURE_EDGES:
        if prerequisite not in positions or consumer not in positions:
            raise ValueError("public API closure references a missing milestone")
        if positions[prerequisite] >= positions[consumer]:
            raise ValueError(f"{consumer} precedes public API prerequisite {prerequisite}")
    for version, tokens in API_SCOPE_CONTRACTS.items():
        if any(token not in scopes.get(version, "") for token in tokens):
            raise ValueError(f"{version} lost its public API operation-direction contract")

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
    return roadmap_schedule.expected_versions()


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
    validate_api_closure(entries)
    catalogue_plan.validate(entries)
    roadmap_schedule.validate(entries)
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
