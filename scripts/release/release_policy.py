#!/usr/bin/env python3
"""Validate Brynja's independent crate-version and publication policy."""

from __future__ import annotations

import json
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path

from release_change_policy import (
    REPOSITORY_ONLY,
    changed_packages as cumulative_changed_packages,
    validate_cumulative_changes,
)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PLAN = ROOT / "release-crates.toml"
FACADE = "brynja"
CHANGE_KINDS = (
    "initial",
    "code",
    "bugfix",
    "dependency",
    "metadata",
    "unchanged",
    "unpublished",
    "repository",
)
PUBLISH_ORDER = (
    "brynja-core",
    "brynja-hash-core",
    "brynja-crypto-cpu",
    "brynja-hash-sha2",
    "brynja-hash-sha3",
    "brynja-mac-kmac",
    "brynja-hash-tuple",
    "brynja-hash-parallel",
    "brynja-crypto",
    "brynja-crypto-cpu-std",
    "brynja-hash-parallel-std",
    "brynja-pki",
    "brynja-protocol",
    "brynja-platform",
    "brynja-tls13-handshake",
    "brynja-tls12",
    "brynja-tls13",
    "brynja-tls",
    "brynja-dtls",
    "brynja-quic-tls",
    "brynja-sanitization",
    "brynja-legacy-pct",
    "brynja-legacy-snp",
    "brynja-legacy-ssl2",
    "brynja-legacy-ssl3",
    "brynja-legacy-tls10",
    "brynja-legacy-tls11",
    "brynja-legacy-wtls",
    "brynja-legacy",
    "brynja-test-support",
    "brynja-interop",
    "brynja-xtask",
    "brynja-proofs",
    "brynja-research-ssl1",
    FACADE,
)
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-rc\.(0|[1-9][0-9]*))?$"
)
VERSION_ROW = re.compile(
    r"^\| `(0\.[0-9]+\.[0-9]+|1\.0\.0(?:-rc\.[0-9]+)?)` \|",
    re.MULTILINE,
)


@dataclass(frozen=True)
class Version:
    """The stable and release-candidate versions used by the Brynja roadmap."""

    major: int
    minor: int
    patch: int
    rc: int | None = None

    def core(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    def next_minor(self) -> Version:
        return Version(self.major, self.minor + 1, 0)

    def next_patch(self) -> Version:
        return Version(self.major, self.minor, self.patch + 1)

    def sort_key(self) -> tuple[int, int, int, int, int]:
        stability = 1 if self.rc is None else 0
        candidate = 0 if self.rc is None else self.rc
        return (self.major, self.minor, self.patch, stability, candidate)

    def __str__(self) -> str:
        core = f"{self.major}.{self.minor}.{self.patch}"
        return core if self.rc is None else f"{core}-rc.{self.rc}"


def parse_version(raw: str) -> Version:
    """Parse the deliberately narrow SemVer subset used for releases."""

    match = SEMVER.fullmatch(raw)
    if match is None:
        raise RuntimeError(f"version must be MAJOR.MINOR.PATCH[-rc.N]: {raw}")
    major, minor, patch, rc = match.groups()
    return Version(
        int(major),
        int(minor),
        int(patch),
        None if rc is None else int(rc),
    )


def milestone_class(raw: str) -> str:
    """Classify one roadmap milestone under the post-v0.10 cadence."""

    version = parse_version(raw)
    if version.major == 1:
        return "public"
    if version.major != 0:
        raise RuntimeError(f"unsupported roadmap major version: {raw}")
    if version.minor <= 10:
        return "public"
    if version.patch == 0 and version.minor % 5 == 0:
        return "public"
    return "internal"


def roadmap_range(baseline: str, milestone: str) -> list[str]:
    """Return the exact ordered roadmap delta after a public baseline."""

    versions = VERSION_ROW.findall(
        (ROOT / "docs" / "VERSION_PLAN.md").read_text(encoding="utf-8")
    )
    try:
        start = versions.index(baseline) + 1
        end = versions.index(milestone) + 1
    except ValueError as error:
        raise RuntimeError("release baseline and milestone must be roadmap rows") from error
    if start > end:
        raise RuntimeError("release milestone must follow its public baseline")
    return versions[start:end]


def roadmap_predecessor(milestone: str) -> str:
    """Return the immediately preceding roadmap tag version."""

    versions = VERSION_ROW.findall(
        (ROOT / "docs" / "VERSION_PLAN.md").read_text(encoding="utf-8")
    )
    try:
        index = versions.index(milestone)
    except ValueError as error:
        raise RuntimeError("release milestone must be a roadmap row") from error
    if index == 0:
        return "unpublished"
    return versions[index - 1]


def validate_release_context(release: dict, crates: dict) -> tuple[str, str]:
    """Validate public-checkpoint or empty internal-stop release context."""

    version = release.get("version")
    milestone = release.get("milestone")
    baseline = release.get("baseline")
    cumulative = release.get("cumulative_milestones")
    stage = release.get("stage")
    exceptional = release.get("exceptional")
    reason = release.get("exception_reason")
    if not all(isinstance(value, str) for value in (version, milestone, baseline, reason)):
        raise RuntimeError("release context has incomplete version metadata")
    parse_version(version)
    parse_version(milestone)
    parse_version(baseline)
    expected = roadmap_range(baseline, milestone)
    if cumulative != expected:
        raise RuntimeError(
            "cumulative_milestones must equal the exact roadmap delta: "
            f"{expected}"
        )
    if not isinstance(exceptional, bool):
        raise RuntimeError("release exceptional must be true or false")
    scheduled = milestone_class(milestone) == "public"
    selected = [name for name, entry in crates.items() if entry.get("publish")]
    if stage == "internal":
        if scheduled:
            raise RuntimeError("internal stage requires a non-checkpoint milestone")
        if exceptional and not reason.strip():
            raise RuntimeError("exceptional development milestone requires a reason")
        if version != milestone:
            raise RuntimeError("development facade version must equal milestone tag version")
        if selected:
            raise RuntimeError("internal stage must have an empty publication selection")
    elif stage == "public":
        if not scheduled and not exceptional:
            raise RuntimeError("early public checkpoint requires exceptional=true")
        if exceptional and not reason.strip():
            raise RuntimeError("exceptional public checkpoint requires a reason")
        if version != milestone:
            raise RuntimeError("public facade version must equal milestone and tag version")
    else:
        raise RuntimeError("release stage must be public or internal")
    return version, stage


def load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def cargo_metadata() -> dict:
    raw = subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=ROOT,
        text=True,
    )
    return json.loads(raw)


def workspace_packages(metadata: dict) -> dict[str, dict]:
    workspace_ids = set(metadata["workspace_members"])
    return {
        package["name"]: package
        for package in metadata["packages"]
        if package["id"] in workspace_ids
    }


def validate_common(name: str, entry: dict) -> tuple[str, str, bool]:
    previous = entry.get("previous_version")
    version = entry.get("version")
    change = entry.get("change")
    publish = entry.get("publish")
    reason = entry.get("reason")
    if not all(isinstance(value, str) for value in (previous, version, change, reason)):
        raise RuntimeError(f"{name} has incomplete release metadata")
    if not reason.strip():
        raise RuntimeError(f"{name} must record a non-empty release reason")
    if change not in CHANGE_KINDS:
        raise RuntimeError(f"{name} has invalid change kind {change!r}")
    if not isinstance(publish, bool):
        raise RuntimeError(f"{name} publish must be true or false")
    parse_version(version)
    return previous, change, publish


def validate_repository_entry(name: str, entry: dict) -> None:
    previous, change, publish = validate_common(name, entry)
    if previous != "unpublished":
        raise RuntimeError(f"{name} is repository-only and must remain unpublished")
    if change != "repository" or publish:
        raise RuntimeError(f"{name} must use change=repository and publish=false")


def validate_internal_entry(name: str, entry: dict) -> None:
    """Require an internal-stop entry to retain versions and publish nothing."""

    previous, change, publish = validate_common(name, entry)
    if publish:
        raise RuntimeError("internal stage must have an empty publication selection")
    if name in REPOSITORY_ONLY:
        validate_repository_entry(name, entry)
        return
    if previous == "unpublished":
        if change not in {"unpublished", "code"}:
            raise RuntimeError(
                f"{name} new internal entry must be unpublished or reviewed code"
            )
    elif entry["version"] != previous:
        raise RuntimeError(f"{name} internal stage must retain version {previous}")
    if change in {"initial", "repository"}:
        raise RuntimeError(f"{name} has invalid internal change kind {change}")


def validate_internal_facade_entry(entry: dict, milestone: str) -> None:
    """Advance the facade at every signed tag without publishing it."""

    previous, change, publish = validate_common(FACADE, entry)
    if entry["version"] != milestone:
        raise RuntimeError(f"{FACADE} version must match milestone {milestone}")
    expected_previous = roadmap_predecessor(milestone)
    if previous != expected_previous:
        raise RuntimeError(
            f"{FACADE} previous version must be prior milestone {expected_previous}"
        )
    if publish:
        raise RuntimeError("internal stage must have an empty publication selection")
    if change in {"unchanged", "unpublished", "repository", "initial"}:
        raise RuntimeError(f"{FACADE} must advance at every signed milestone tag")


def validate_facade_entry(entry: dict, release: str) -> None:
    previous, change, publish = validate_common(FACADE, entry)
    if entry["version"] != release:
        raise RuntimeError(f"{FACADE} version must match release {release}")
    if change in ("unchanged", "unpublished", "repository"):
        raise RuntimeError(f"{FACADE} must publish on every public release tag")
    if not publish:
        raise RuntimeError(f"{FACADE} must publish on every public release tag")
    if change == "initial":
        if previous != "unpublished":
            raise RuntimeError(f"{FACADE} initial publication requires unpublished")
    elif previous == "unpublished":
        raise RuntimeError(f"{FACADE} first publication must use change=initial")
    else:
        expected_previous = roadmap_predecessor(release)
        if previous != expected_previous:
            raise RuntimeError(
                f"{FACADE} previous version must be prior milestone "
                f"{expected_previous}"
            )
        old = parse_version(previous)
        if parse_version(release).sort_key() <= old.sort_key():
            raise RuntimeError(f"{FACADE} release version must advance")


def validate_support_entry(name: str, entry: dict) -> None:
    previous, change, publish = validate_common(name, entry)
    if name in REPOSITORY_ONLY:
        validate_repository_entry(name, entry)
        return
    planned = parse_version(entry["version"])
    if change == "initial":
        if previous != "unpublished" or not publish:
            raise RuntimeError(
                f"{name} initial publication requires unpublished and publish=true"
            )
        return
    if change == "unpublished":
        if previous != "unpublished" or publish:
            raise RuntimeError(f"{name} unpublished entry cannot be published")
        return
    if change == "repository":
        raise RuntimeError(f"{name} is not classified as repository-only")
    if previous == "unpublished":
        raise RuntimeError(f"{name} first publication must use change=initial")
    old = parse_version(previous)
    if change == "code":
        expected = old.next_minor()
    elif change in ("bugfix", "dependency", "metadata"):
        expected = old.next_patch()
    else:
        expected = old
    if planned != expected:
        raise RuntimeError(f"{name} {change} version must be {expected}")
    should_publish = change != "unchanged"
    if publish != should_publish:
        state = "true" if should_publish else "false"
        raise RuntimeError(f"{name} {change} entry requires publish={state}")


def release_plan(path: Path = DEFAULT_PLAN) -> dict:
    plan = load_toml(path)
    release = plan.get("release", {})
    crates = plan.get("crates", {})
    if release.get("policy") != "independent":
        raise RuntimeError("release policy must be independent")
    if set(crates) != set(PUBLISH_ORDER):
        raise RuntimeError(
            "release inventory differs from PUBLISH_ORDER: "
            f"missing={sorted(set(PUBLISH_ORDER) - set(crates))}, "
            f"extra={sorted(set(crates) - set(PUBLISH_ORDER))}"
        )
    version, stage = validate_release_context(release, crates)
    for name, entry in crates.items():
        if stage == "public" and name == FACADE:
            validate_facade_entry(entry, version)
        elif stage == "internal" and name == FACADE:
            validate_internal_facade_entry(entry, version)
        elif stage == "internal":
            validate_internal_entry(name, entry)
        else:
            validate_support_entry(name, entry)
    return {
        "version": version,
        "milestone": release["milestone"],
        "baseline": release["baseline"],
        "cumulative_milestones": release["cumulative_milestones"],
        "stage": stage,
        "exceptional": release["exceptional"],
        "crates": crates,
    }


def package_is_publishable(package: dict) -> bool:
    registries = package.get("publish")
    return registries is None or "crates-io" in registries


def verify_repository(packages: dict[str, dict], plan: dict) -> None:
    if set(packages) != set(PUBLISH_ORDER):
        raise RuntimeError("workspace packages differ from the enforced release inventory")
    seen: set[str] = set()
    for name in PUBLISH_ORDER:
        package = packages[name]
        entry = plan["crates"][name]
        if package["version"] != entry["version"]:
            raise RuntimeError(
                f"{name} manifest version {package['version']} "
                f"does not match planned {entry['version']}"
            )
        publishable = package_is_publishable(package)
        must_be_publishable = (
            name not in REPOSITORY_ONLY and entry["change"] != "unpublished"
        )
        if publishable != must_be_publishable:
            expected = "publishable" if must_be_publishable else "publish=false"
            raise RuntimeError(f"{name} manifest must be {expected}")
        for dependency in package["dependencies"]:
            dependency_name = dependency["name"]
            if dependency_name not in packages:
                continue
            if dependency_name not in seen:
                raise RuntimeError(
                    f"{name} depends on {dependency_name}, which appears later "
                    "in PUBLISH_ORDER"
                )
            dependency_entry = plan["crates"][dependency_name]
            expected_req = f"={dependency_entry['version']}"
            if dependency.get("req") != expected_req:
                raise RuntimeError(
                    f"{name} must pin {dependency_name} to {expected_req}"
                )
            if entry["publish"]:
                available = (
                    dependency_entry["publish"]
                    or dependency_entry["previous_version"] != "unpublished"
                )
                if not available:
                    raise RuntimeError(
                        f"{name} publishes with unavailable dependency "
                        f"{dependency_name}"
                    )
        seen.add(name)


def validate_repository(path: Path = DEFAULT_PLAN) -> dict:
    plan = release_plan(path)
    packages = workspace_packages(cargo_metadata())
    verify_repository(packages, plan)
    validate_cumulative_changes(
        plan,
        cumulative_changed_packages(packages, plan["baseline"]),
    )
    return plan


def publish_plan(plan: dict) -> tuple[str, ...]:
    return tuple(name for name in PUBLISH_ORDER if plan["crates"][name]["publish"])
