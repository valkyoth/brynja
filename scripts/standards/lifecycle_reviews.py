#!/usr/bin/env python3
"""Fail-closed archival review rules for authority lifecycle observations."""

from __future__ import annotations

import json
import re
import stat
import subprocess
from pathlib import Path
from typing import Callable

import lifecycle_model as model
import standards_lib as standards


RELEASE_PLAN = model.ROOT / "docs/RELEASE_PLAN.md"
MILESTONE = re.compile(
    r"^### v(?P<version>(?:0\.[0-9]+\.[0-9]+|1\.0\.0(?:-rc\.[0-9]+)?)) - .+$",
    re.MULTILINE,
)
OBSERVATION_FIELDS = {
    "affected_evidence",
    "affected_milestones",
    "affected_requirements",
    "affected_symbols",
    "authority",
    "detail",
    "effective_brynja_state",
    "id",
    "requested_action",
    "state",
}
REVIEW_FIELDS = {
    "affected_evidence",
    "affected_requirements",
    "affected_symbols",
    "authority",
    "corrective_milestone",
    "disposition",
    "evidence",
    "observation_id",
    "pentest",
    "pentest_report",
    "reviewed_impact",
}
SECURITY_DISPOSITIONS = model.ALLOWED_REVIEW_DISPOSITIONS - {"no-effect"}


def observation_id(item: dict) -> str:
    payload = {key: item[key] for key in sorted(OBSERVATION_FIELDS - {"id"})}
    return standards.sha256(standards.json_bytes(payload))[:24]


def validate_observation(item: dict) -> None:
    if set(item) != OBSERVATION_FIELDS:
        raise model.LifecycleError("archived authority observation has invalid fields")
    if item["state"] not in model.ALLOWED_OBSERVATION_STATES:
        raise model.LifecycleError("archived authority observation has invalid state")
    if item["requested_action"] != "human-review":
        raise model.LifecycleError("archived authority observation is authorizing")
    if item["id"] != observation_id(item):
        raise model.LifecycleError("archived authority observation identity is invalid")
    for field in (
        "affected_evidence",
        "affected_milestones",
        "affected_requirements",
        "affected_symbols",
    ):
        if item[field] != sorted(set(item[field])):
            raise model.LifecycleError(f"archived observation has invalid {field}")


def milestone_sections(text: str | None = None) -> dict[str, str]:
    text = RELEASE_PLAN.read_text(encoding="utf-8") if text is None else text
    matches = list(MILESTONE.finditer(text))
    return {
        match.group("version"): text[
            match.start() : matches[index + 1].start() if index + 1 < len(matches) else len(text)
        ]
        for index, match in enumerate(matches)
    }


def repository_file(value: str, root: Path = model.ROOT) -> Path:
    relative = Path(value)
    if not value or relative.is_absolute() or ".." in relative.parts:
        raise model.LifecycleError("review evidence path escapes the repository")
    path = root / relative
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        raise model.LifecycleError(f"review evidence is missing: {value}") from error
    if not stat.S_ISREG(mode):
        raise model.LifecycleError(f"review evidence is not a regular file: {value}")
    return path


def require_committed(value: str, path: Path, root: Path = model.ROOT) -> None:
    if root.resolve() != model.ROOT.resolve():
        return
    result = subprocess.run(
        ["git", "cat-file", "blob", f"HEAD:{value}"],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0 or result.stdout != path.read_bytes():
        raise model.LifecycleError(f"review evidence is not committed at HEAD: {value}")


def report_field(text: str, label: str) -> str:
    prefix = f"{label}: "
    values = [line.removeprefix(prefix) for line in text.splitlines() if line.startswith(prefix)]
    if len(values) != 1:
        raise model.LifecycleError(f"pentest report requires exactly one {label} field")
    return values[0]


def prior_committed_reviews() -> dict | None:
    current = subprocess.run(
        ["git", "cat-file", "blob", "HEAD:standards/authority-reviews.json"],
        cwd=model.ROOT,
        check=False,
        capture_output=True,
    )
    if current.returncode != 0:
        return None
    working = model.REVIEWS.read_bytes()
    reference = "HEAD" if current.stdout != working else "HEAD^"
    prior = subprocess.run(
        ["git", "cat-file", "blob", f"{reference}:standards/authority-reviews.json"],
        cwd=model.ROOT,
        check=False,
        capture_output=True,
    )
    if prior.returncode != 0:
        return None
    try:
        value = json.loads(prior.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise model.LifecycleError("prior authority review register is malformed") from error
    return value if value.get("schema") == 2 else None


def validate_append_only(reviews: dict) -> None:
    prior = prior_committed_reviews()
    if prior is None:
        return
    for field, identity in (("observations", "id"), ("reviews", "observation_id")):
        current = {item[identity]: item for item in reviews[field]}
        for item in prior[field]:
            if current.get(item[identity]) != item:
                raise model.LifecycleError(f"authority {field} history is not append-only")


def validate_pentest_report(path: str, milestone: str, root: Path = model.ROOT) -> None:
    expected = f"security/pentest/v{milestone}.md"
    if path != expected:
        raise model.LifecycleError(f"corrective pentest report must be {expected}")
    report = repository_file(path, root)
    require_committed(path, report, root)
    text = report.read_text(encoding="utf-8")
    expected_fields = {
        "Version": f"v{milestone}",
        "Status": "PASS",
        "Retest": "PASS",
        "Open-Findings": "0",
    }
    for label, expected_value in expected_fields.items():
        if report_field(text, label) != expected_value:
            raise model.LifecycleError(
                f"corrective pentest report must record {label}: {expected_value}"
            )


def validate_review(
    review: dict,
    observation: dict,
    sections: dict[str, str],
    *,
    root: Path = model.ROOT,
    pentest_validator: Callable[[str, str, Path], None] = validate_pentest_report,
) -> None:
    if set(review) != REVIEW_FIELDS or review["disposition"] not in model.ALLOWED_REVIEW_DISPOSITIONS:
        raise model.LifecycleError("authority disposition review has invalid fields")
    if review["authority"] != observation["authority"]:
        raise model.LifecycleError("review authority does not match observation")
    if not review["reviewed_impact"].strip():
        raise model.LifecycleError("authority disposition review is unexplained")
    for field in ("affected_evidence", "affected_requirements", "affected_symbols"):
        if review[field] != observation[field]:
            raise model.LifecycleError(f"review does not cover observation {field}")
    evidence = review["evidence"]
    if not evidence or evidence != sorted(set(evidence)):
        raise model.LifecycleError("authority review lacks unique corrective evidence")
    for path in evidence:
        evidence_path = repository_file(path, root)
        require_committed(path, evidence_path, root)
    if review["disposition"] == "no-effect":
        if any(
            (
                review["corrective_milestone"] is not None,
                review["pentest"] != "not-required",
                review["pentest_report"] is not None,
            )
        ):
            raise model.LifecycleError("no-effect review claims corrective release authority")
        return
    milestone = review["corrective_milestone"]
    if milestone not in sections:
        raise model.LifecycleError("corrective milestone is not in the release plan")
    section = sections[milestone]
    if observation["id"] not in section or observation["authority"] not in section:
        raise model.LifecycleError("corrective milestone is not bound to the observation")
    if review["pentest"] != "exceptional-required" or not review["pentest_report"]:
        raise model.LifecycleError("security-changing review lacks an exceptional pentest")
    pentest_validator(review["pentest_report"], milestone, root)


def validate_reviews(reviews: dict, *, enforce_history: bool = True) -> None:
    required = {"observations", "reviews", "schema", "unresolved_observations"}
    if set(reviews) != required or reviews["schema"] != 2:
        raise model.LifecycleError("authority review register requires schema 2")
    if enforce_history:
        validate_append_only(reviews)
    observations: dict[str, dict] = {}
    for item in reviews["observations"]:
        validate_observation(item)
        if item["id"] in observations:
            raise model.LifecycleError("archived authority observation is duplicate")
        observations[item["id"]] = item
    unresolved: set[str] = set()
    for item in reviews["unresolved_observations"]:
        validate_observation(item)
        if item["id"] in unresolved or observations.get(item["id"]) != item:
            raise model.LifecycleError("unresolved observation is duplicate or not archived")
        unresolved.add(item["id"])
    reviewed: set[str] = set()
    sections = milestone_sections()
    for review in reviews["reviews"]:
        identifier = review.get("observation_id")
        if identifier in reviewed:
            raise model.LifecycleError("authority disposition review is duplicate")
        observation = observations.get(identifier)
        if observation is None:
            raise model.LifecycleError("review references an unknown observation")
        validate_review(review, observation, sections)
        reviewed.add(identifier)
    if unresolved & reviewed:
        raise model.LifecycleError("reviewed observation remains unresolved")
    if set(observations) != unresolved | reviewed:
        raise model.LifecycleError("archived observation lacks unresolved or reviewed disposition")


def review_observation(
    item: dict,
    disposition: str,
    *,
    corrective_milestone: str | None,
    evidence: list[str],
    pentest: str,
    pentest_report: str | None,
) -> dict:
    if disposition not in model.ALLOWED_REVIEW_DISPOSITIONS:
        raise model.LifecycleError("invalid authority drift disposition")
    if not evidence:
        raise model.LifecycleError("authority review requires corrective evidence")
    if disposition in SECURITY_DISPOSITIONS and (
        not corrective_milestone
        or pentest != "exceptional-required"
        or not pentest_report
    ):
        raise model.LifecycleError(
            "security-behavior disposition requires a corrective milestone and pentest"
        )
    if disposition == "no-effect" and (
        corrective_milestone is not None
        or pentest != "not-required"
        or pentest_report is not None
    ):
        raise model.LifecycleError("no-effect disposition cannot claim corrective authority")
    return {
        "affected_evidence": item["affected_evidence"],
        "affected_requirements": item["affected_requirements"],
        "affected_symbols": item["affected_symbols"],
        "authority": item["authority"],
        "corrective_milestone": corrective_milestone,
        "disposition": disposition,
        "evidence": evidence,
        "observation_id": item["id"],
        "pentest": pentest,
        "pentest_report": pentest_report,
        "reviewed_impact": item["detail"],
    }
