#!/usr/bin/env python3
"""Shared dependency-free support for requirement-matrix fixtures."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import requirements_lib as lib
import standards_lib as standards
import surface_lib as surfaces


SPEC = importlib.util.spec_from_file_location(
    "check_requirements", Path(__file__).with_name("check-requirements.py")
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load requirement checker")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def assert_fails(expected: str, function, *args, **kwargs) -> None:
    try:
        function(*args, **kwargs)
    except RuntimeError as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r} in {error!r}") from error
        return
    raise AssertionError("expected validation failure")


def inputs() -> tuple[dict, dict, dict]:
    return (
        lib.read_json(lib.POLICY),
        lib.read_json(standards.LEDGER),
        lib.read_json(surfaces.REGISTER),
    )


def bind(policy: dict, ledger: dict, register: dict) -> None:
    policy["source_ledger_sha256"] = standards.sha256(
        standards.json_bytes(ledger)
    )
    policy["surface_register_sha256"] = standards.sha256(
        standards.json_bytes(register)
    )


def requirement(policy: dict, requirement_id: str) -> dict:
    return next(
        item for item in policy["requirements"] if item["id"] == requirement_id
    )


def run_tests(namespace: dict) -> int:
    tests = [
        value
        for name, value in sorted(namespace.items())
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        test()
    return len(tests)
