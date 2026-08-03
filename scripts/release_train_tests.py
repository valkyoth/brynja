#!/usr/bin/env python3
"""Focused fixtures for post-v0.10 internal and checkpoint release trains."""

from __future__ import annotations

import release_policy as policy
import release_crates as publisher


def assert_fails(expected: str, function, *args) -> None:
    try:
        function(*args)
    except RuntimeError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r} in {error!r}") from error
        return
    raise AssertionError("expected validation failure")


def selections(*selected: str) -> dict[str, dict[str, bool]]:
    return {
        name: {"publish": name in selected}
        for name in policy.PUBLISH_ORDER
    }


def entry(previous: str, version: str, change: str, publish: bool) -> dict:
    return {
        "previous_version": previous,
        "version": version,
        "change": change,
        "publish": publish,
        "reason": "test fixture",
    }


def test_internal_facade_advances_without_publication() -> None:
    policy.validate_internal_facade_entry(
        entry("0.10.0", "0.11.0", "code", False),
        "0.11.0",
    )
    policy.validate_internal_facade_entry(
        entry("0.11.0", "0.11.1", "metadata", False),
        "0.11.1",
    )
    assert_fails(
        "must match milestone",
        policy.validate_internal_facade_entry,
        entry("0.10.0", "0.10.0", "code", False),
        "0.11.0",
    )
    assert_fails(
        "empty publication selection",
        policy.validate_internal_facade_entry,
        entry("0.10.0", "0.11.0", "code", True),
        "0.11.0",
    )
    assert_fails(
        "previous version must be prior milestone",
        policy.validate_internal_facade_entry,
        entry("0.9.0", "0.11.0", "code", False),
        "0.11.0",
    )


def test_future_checkpoint_uses_complete_generic_tag_gate() -> None:
    calls = []
    original_run = publisher.run
    publisher.run = lambda command, **kwargs: calls.append((command, kwargs))
    try:
        publisher.run_preflight(
            "0.15.0",
            dry_run=False,
            release_tag_at_head=True,
        )
    finally:
        publisher.run = original_run
    assert calls[0] == (
        ["scripts/tag_gate.sh", "v0.15.0"],
        {
            "dry_run": False,
            "extra_env": {"BRYNJA_RELEASE_PUBLISH_TAG": "v0.15.0"},
        },
    )


def test_internal_stage_refuses_crates_io_publication() -> None:
    assert_fails(
        "refusing crates.io publication",
        publisher.require_public_stage,
        "internal",
    )
    publisher.require_public_stage("public")


def test_internal_stop_requires_empty_publication() -> None:
    crates = selections()
    context = {
        "version": "0.11.0",
        "milestone": "0.11.0",
        "baseline": "0.10.0",
        "cumulative_milestones": ["0.11.0"],
        "stage": "internal",
        "exceptional": False,
        "exception_reason": "",
    }
    policy.validate_release_context(context, crates)
    context["version"] = "0.10.0"
    assert_fails(
        "must equal milestone tag version",
        policy.validate_release_context,
        context,
        crates,
    )
    context["version"] = "0.11.0"
    crates["brynja-core"]["publish"] = True
    assert_fails(
        "empty publication selection",
        policy.validate_release_context,
        context,
        crates,
    )


def test_checkpoint_requires_exact_cumulative_range() -> None:
    context = {
        "version": "0.15.0",
        "milestone": "0.15.0",
        "baseline": "0.10.0",
        "cumulative_milestones": [
            "0.11.0",
            "0.11.1",
            "0.11.2",
            "0.12.0",
            "0.13.0",
            "0.14.0",
            "0.15.0",
        ],
        "stage": "public",
        "exceptional": False,
        "exception_reason": "",
    }
    policy.validate_release_context(context, selections(policy.FACADE))
    context["cumulative_milestones"] = ["0.15.0"]
    assert_fails(
        "exact roadmap delta",
        policy.validate_release_context,
        context,
        selections(policy.FACADE),
    )


def test_early_public_checkpoint_requires_exception_reason() -> None:
    context = {
        "version": "0.11.0",
        "milestone": "0.11.0",
        "baseline": "0.10.0",
        "cumulative_milestones": ["0.11.0"],
        "stage": "public",
        "exceptional": False,
        "exception_reason": "",
    }
    crates = selections(policy.FACADE)
    assert_fails("exceptional=true", policy.validate_release_context, context, crates)
    context["exceptional"] = True
    assert_fails("requires a reason", policy.validate_release_context, context, crates)
    context["exception_reason"] = "Material security boundary requires review."
    policy.validate_release_context(context, crates)
