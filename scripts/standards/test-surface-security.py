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


def test_september_registry_refresh_does_not_admit_draft_authority() -> None:
    surfaces = {item["id"]: item for item in current_surfaces()}
    for name, value in (("mldsa44", "0x0904"), ("mldsa65", "0x0905"),
                        ("mldsa87", "0x0906")):
        entry = surfaces[f"iana.tls-parameters.tls-signaturescheme.{name}.1"]
        assert entry["disposition"] == "future-work"
        assert entry["owner"] == "0.51.0"
        assert entry["record"]["fields"] == {
            "description": name, "recommended": "N", "value": value,
        }
        assert entry["record"]["references"] == [
            {"type": "draft", "data": "RFC-ietf-tls-mldsa-06"},
        ]
        assert entry["normative_sources"] == ["iana:tls-parameters", "rfc:9846"]
    entry = surfaces[
        "iana.smi-numbers.security-smime-0.id-mod-composite-mlkem-cms-2026.1"
    ]
    assert entry["disposition"] == "caller-owned"
    assert entry["owner"] == "0.94.0"
    assert entry["record"]["fields"]["value"] == "91"
    assert entry["record"]["references"] == [
        {"type": "draft", "data": "RFC-ietf-lamps-cms-composite-kem-03"},
    ]
    assert entry["normative_sources"] == ["iana:smi-numbers", "rfc:5280"]


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
