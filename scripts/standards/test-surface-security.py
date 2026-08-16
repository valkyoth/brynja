#!/usr/bin/env python3
"""Broken fixtures for security-critical protocol-surface boundaries."""

from __future__ import annotations

import copy
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import requirements_test_support as support  # noqa: E402
import surface_lib as lib  # noqa: E402
import surface_security  # noqa: E402

assert_fails = support.assert_fails


def current_surfaces() -> list[dict]:
    return lib.read_json(lib.REGISTER)["surfaces"]


def test_current_security_boundaries() -> None:
    surface_security.validate(current_surfaces())


def test_dtls_rrc_boundary_drift_fails() -> None:
    broken = copy.deepcopy(current_surfaces())
    surface = next(
        item
        for item in broken
        if item["id"]
        == "iana.tls-parameters.tls-parameters-5."
        "return-routability-check.1"
    )
    surface["domain"] = "tls"
    assert_fails(
        "DTLS RRC boundary drift",
        surface_security.validate,
        broken,
    )


def test_rfc6066_wire_boundary_drift_fails() -> None:
    broken = copy.deepcopy(current_surfaces())
    surface = next(
        item
        for item in broken
        if item["id"]
        == "iana.tls-extensiontype-values.tls-extensiontype-values-1."
        "client-certificate-url.1"
    )
    surface["disposition"] = "intentionally-rejected"
    assert_fails(
        "RFC 6066 wire surface drift",
        surface_security.validate,
        broken,
    )


def test_rfc6066_configuration_boundary_drift_fails() -> None:
    broken = copy.deepcopy(current_surfaces())
    surface = next(
        item
        for item in broken
        if item["id"] == "facility.rfc6066-unsupported-configuration"
    )
    surface["disposition"] = "safely-ignored"
    assert_fails(
        "RFC 6066 configuration boundary drift",
        surface_security.validate,
        broken,
    )


def main() -> int:
    count = support.run_tests(globals())
    print(f"{count} surface-security tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
