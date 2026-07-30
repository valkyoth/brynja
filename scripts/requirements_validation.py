#!/usr/bin/env python3
"""Shared target, test, and evidence validation for requirement profiles."""

from __future__ import annotations

import re

import requirements_lib as lib


def validate_targets(requirement: dict) -> None:
    lifecycle = requirement["lifecycle"]
    targets = requirement["targets"]
    if not isinstance(targets, list) or len(targets) != 1:
        lib.fail(f"{requirement['id']} requires exactly one target")
    target = targets[0]
    if set(target) != {"kind", "target"}:
        lib.fail(f"{requirement['id']} has malformed target")
    kind = target["kind"]
    value = target["target"]
    expected_kinds = {
        "blocked": "blocker",
        "caller-owned": "boundary",
        "evidenced": "actual-symbol",
        "implemented": "actual-symbol",
        "legacy": "legacy-boundary",
        "planned": "planned-symbol",
        "rejected": "boundary",
        "tested": "actual-symbol",
    }
    if kind != expected_kinds[lifecycle]:
        lib.fail(f"{requirement['id']} has target incompatible with lifecycle")
    if kind == "boundary":
        if not isinstance(value, str) or re.fullmatch(
            r"boundary:[a-z0-9.-]+", value
        ) is None:
            lib.fail(f"{requirement['id']} has invalid caller boundary")
    else:
        lib.validate_repository_target(value, requirement["id"])
        if kind in {"actual-symbol", "blocker", "legacy-boundary"}:
            lib.require_actual_target(value, requirement["id"])
        if kind == "legacy-boundary" and "brynja-legacy" not in value:
            lib.fail(f"{requirement['id']} legacy target is not isolated")


def validate_tests_and_evidence(requirement: dict) -> None:
    tests = requirement["tests"]
    if not isinstance(tests, list) or not tests:
        lib.fail(f"{requirement['id']} requires test targets")
    actual_tests = 0
    for test in tests:
        if set(test) != {"status", "target"} or test["status"] not in {
            "actual",
            "planned",
        }:
            lib.fail(f"{requirement['id']} has malformed test target")
        target = lib.validate_repository_target(
            test["target"], f"{requirement['id']} test"
        )
        if test["status"] == "actual":
            actual_tests += 1
            lib.require_actual_target(target, f"{requirement['id']} test")
    lifecycle = requirement["lifecycle"]
    if lifecycle in {"tested", "evidenced"} and actual_tests == 0:
        lib.fail(f"{requirement['id']} lifecycle requires an actual test")
    if lifecycle in {"planned", "implemented"} and actual_tests:
        lib.fail(f"{requirement['id']} claims tests before tested lifecycle")

    evidence = requirement["evidence"]
    if not isinstance(evidence, list) or len(evidence) != len(set(evidence)):
        lib.fail(f"{requirement['id']} has invalid evidence")
    if lifecycle == "evidenced":
        if not evidence:
            lib.fail(f"{requirement['id']} evidenced lifecycle lacks evidence")
        for target in evidence:
            target = lib.validate_repository_target(
                target, f"{requirement['id']} evidence"
            )
            lib.require_actual_target(target, f"{requirement['id']} evidence")
    elif evidence:
        lib.fail(f"{requirement['id']} has premature evidence")
