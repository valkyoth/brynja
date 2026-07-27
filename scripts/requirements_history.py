#!/usr/bin/env python3
"""Immutable Git-history enforcement for normative requirements."""

from __future__ import annotations

import json
import subprocess

import requirements_lib as lib
import surface_lib as surfaces


AUTO = object()
TRACKED_INPUTS = (
    "requirements/policy.json",
    "requirements/matrix.json",
    "standards/surface-policy.json",
    "standards/protocol-surfaces.json",
)


def git_run(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["git", *arguments],
            cwd=lib.ROOT,
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", "") or str(error)
        lib.fail(f"cannot inspect immutable requirement history: {detail.strip()}")


def default_ref() -> str:
    changed = git_run(
        ["diff", "--quiet", "HEAD", "--", *TRACKED_INPUTS],
        check=False,
    )
    if changed.returncode not in {0, 1}:
        lib.fail("cannot determine requirement-history worktree state")
    return "HEAD" if changed.returncode == 1 else "HEAD^"


def load_matrix(ref: str | None = None) -> dict | None:
    ref = ref or default_ref()
    commit = git_run(["cat-file", "-e", f"{ref}^{{commit}}"], check=False)
    if commit.returncode != 0:
        lib.fail(f"requirement-history commit is unavailable: {ref}")
    result = git_run(
        ["show", f"{ref}:requirements/matrix.json"],
        check=False,
    )
    if result.returncode != 0:
        return None
    try:
        value = json.loads(
            result.stdout,
            object_pairs_hook=surfaces.unique_object,
        )
    except json.JSONDecodeError as error:
        lib.fail(f"{ref} requirement matrix is invalid JSON: {error}")
    if (
        not isinstance(value, dict)
        or value.get("schema") != 1
        or not isinstance(value.get("requirements"), list)
    ):
        lib.fail(f"{ref} requirement matrix has an invalid schema")
    return value


def without_revision(requirement: dict) -> dict:
    return {
        key: value
        for key, value in requirement.items()
        if key != "revision"
    }


def validate(previous: dict | None, current: list[dict], transition) -> None:
    if previous is None:
        invalid = [
            item["id"] for item in current if item["revision"] != 1
        ]
        if invalid:
            lib.fail(
                "bootstrap requirements must begin at revision 1: "
                f"{sorted(invalid)}"
            )
        return

    before = {
        requirement["id"]: requirement
        for requirement in previous["requirements"]
    }
    after = {requirement["id"]: requirement for requirement in current}
    removed = set(before) - set(after)
    if removed:
        lib.fail(f"released requirement IDs cannot disappear: {sorted(removed)}")

    for requirement_id, now in after.items():
        old = before.get(requirement_id)
        if old is None:
            if now["revision"] != 1:
                lib.fail(f"{requirement_id} must begin at revision 1")
            continue
        if old["scope"] != now["scope"]:
            lib.fail(f"{requirement_id} released scope cannot change")
        if now["lifecycle"] != old["lifecycle"]:
            transition(old["lifecycle"], now["lifecycle"])
        changed = without_revision(old) != without_revision(now)
        expected = old["revision"] + int(changed)
        if now["revision"] != expected:
            lib.fail(f"{requirement_id} revision must be {expected}")
