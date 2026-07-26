#!/usr/bin/env python3
"""Validate Brynja's independent crate-version and publication policy."""

from __future__ import annotations

import json
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
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
REPOSITORY_ONLY = frozenset(
    {
        "brynja-interop",
        "brynja-proofs",
        "brynja-research-ssl1",
        "brynja-test-support",
        "brynja-xtask",
    }
)
PUBLISH_ORDER = (
    "brynja-core",
    "brynja-crypto",
    "brynja-pki",
    "brynja-platform",
    "brynja-tls13-handshake",
    "brynja-tls12",
    "brynja-tls13",
    "brynja-tls",
    "brynja-dtls",
    "brynja-quic-tls",
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


def validate_foundation_entry(name: str, entry: dict, release: str) -> None:
    previous, change, publish = validate_common(name, entry)
    if name in REPOSITORY_ONLY:
        validate_repository_entry(name, entry)
        return
    if previous != "unpublished" or change != "unpublished" or publish:
        raise RuntimeError(f"{name} foundation entry must remain unpublished")
    if name == FACADE and entry["version"] != release:
        raise RuntimeError(f"{FACADE} foundation version must be {release}")


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
    version = release.get("version")
    stage = release.get("stage")
    if release.get("policy") != "independent":
        raise RuntimeError("release policy must be independent")
    if not isinstance(version, str):
        raise RuntimeError("release-crates.toml is missing [release].version")
    parse_version(version)
    if stage not in ("foundation", "public"):
        raise RuntimeError("release stage must be foundation or public")
    if set(crates) != set(PUBLISH_ORDER):
        raise RuntimeError(
            "release inventory differs from PUBLISH_ORDER: "
            f"missing={sorted(set(PUBLISH_ORDER) - set(crates))}, "
            f"extra={sorted(set(crates) - set(PUBLISH_ORDER))}"
        )
    for name, entry in crates.items():
        if stage == "foundation":
            validate_foundation_entry(name, entry, version)
        elif name == FACADE:
            validate_facade_entry(entry, version)
        else:
            validate_support_entry(name, entry)
    return {"version": version, "stage": stage, "crates": crates}


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
            plan["stage"] == "public"
            and name not in REPOSITORY_ONLY
            and entry["change"] != "unpublished"
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
    verify_repository(workspace_packages(cargo_metadata()), plan)
    return plan


def publish_plan(plan: dict) -> tuple[str, ...]:
    return tuple(name for name in PUBLISH_ORDER if plan["crates"][name]["publish"])
