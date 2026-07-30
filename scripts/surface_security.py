#!/usr/bin/env python3
"""Security-critical cross-protocol surface invariants."""

from __future__ import annotations

import surface_lib as lib


RRC_IDS = {
    "iana.tls-extensiontype-values.tls-extensiontype-values-1.rrc.1",
    "iana.tls-parameters.tls-parameters-5.return-routability-check.1",
    "iana.tls-parameters.tls-rrc-message-types",
    "iana.tls-parameters.tls-rrc-message-types.path-challenge.1",
    "iana.tls-parameters.tls-rrc-message-types.path-drop.1",
    "iana.tls-parameters.tls-rrc-message-types.path-response.1",
    "iana.tls-parameters.tls-rrc-message-types.reserved-for-private-use.1",
    "iana.tls-parameters.tls-rrc-message-types.unassigned.1",
    "state.dtls.return-routability",
}
RFC6066_REJECTED_IDS = {
    "iana.tls-extensiontype-values.tls-extensiontype-values-1."
    "client-certificate-url.1",
    "iana.tls-extensiontype-values.tls-extensiontype-values-1."
    "max-fragment-length.1",
    "iana.tls-extensiontype-values.tls-extensiontype-values-1."
    "truncated-hmac.1",
    "iana.tls-extensiontype-values.tls-extensiontype-values-1."
    "trusted-ca-keys.1",
}


def validate(surfaces: list[dict]) -> None:
    by_id = {surface["id"]: surface for surface in surfaces}
    if not RRC_IDS <= set(by_id):
        lib.fail("DTLS RRC security surface set is incomplete")
    for identifier in RRC_IDS:
        surface = by_id[identifier]
        if (
            surface["domain"] != "dtls"
            or surface["owner"] != "0.111.1"
            or not surface["code_target"].startswith(
                "crates/brynja-dtls-core/src/"
            )
            or not surface["test_target"].startswith(
                "tests/requirements/dtls_routability.rs#"
            )
        ):
            lib.fail(f"DTLS RRC boundary drift: {identifier}")
    content = by_id[
        "iana.tls-parameters.tls-parameters-5."
        "return-routability-check.1"
    ]
    if (
        content["code_target"]
        != "crates/brynja-dtls-core/src/routability.rs#RrcContentType"
        or content["test_target"]
        != "tests/requirements/dtls_routability.rs#"
        "reject_rrc_content_type_outside_dtls"
    ):
        lib.fail("DTLS RRC content-type admission boundary drift")

    if not RFC6066_REJECTED_IDS <= set(by_id):
        lib.fail("RFC 6066 rejected surface set is incomplete")
    for identifier in RFC6066_REJECTED_IDS:
        surface = by_id[identifier]
        if (
            surface["domain"] != "tls"
            or surface["owner"] != "0.148.0"
            or surface["disposition"] != "intentionally-rejected"
            or surface["code_target"]
            != "crates/brynja-tls/src/rejected_rfc6066.rs#LegacyExtension"
            or surface["test_target"]
            != "tests/requirements/rfc6066_exclusions.rs#legacy_extensions"
        ):
            lib.fail(f"RFC 6066 rejected surface drift: {identifier}")
