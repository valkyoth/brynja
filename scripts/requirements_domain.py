#!/usr/bin/env python3
"""v0.3.3 cryptography, encoding, and PKIX requirement coverage."""

from __future__ import annotations

import requirements_bundle as bundle
import requirements_lib as lib


SCOPE = lib.DIRECTORY / "domain-scope.toml"
POLICY_DIRECTORY = lib.DIRECTORY / "domains"
POLICY_FILES = (
    POLICY_DIRECTORY / "cryptography.toml",
    POLICY_DIRECTORY / "encoding.toml",
    POLICY_DIRECTORY / "pkix.toml",
    POLICY_DIRECTORY / "ocsp.toml",
    POLICY_DIRECTORY / "ct.toml",
)
SOURCE_DOMAINS = {
    "ct",
    "key-containers",
    "ocsp",
    "pkix",
    "public-key",
    "riscv-acceleration",
    "symmetric",
}
SURFACE_DOMAINS = {"cryptography", "ct", "ocsp", "pki", "pkix"}
AUTHORITY_ROLES = {"compatibility", "current", "evidence"}
CONFIG = bundle.Config(
    scope=SCOPE,
    policy_files=POLICY_FILES,
    milestone="0.3.3",
    profile="crypto-encoding-pkix",
    source_domains=frozenset(SOURCE_DOMAINS),
    surface_domains=frozenset(SURFACE_DOMAINS),
    authority_roles=frozenset(AUTHORITY_ROLES),
    lifecycles=frozenset(
        {"evidenced", "implemented", "planned", "rejected", "tested"}
    ),
    section_policy=lib.DIRECTORY / "domain-sections.toml",
)


def load_policy() -> tuple[dict, list[dict], str]:
    return bundle.load_policy(CONFIG)


def validate_scope(scope: dict, ledger: dict, register: dict) -> None:
    bundle.validate_scope(CONFIG, scope, ledger, register)


def expected_authorities(ledger: dict) -> dict[str, dict]:
    scope, _requirements, _digest = load_policy()
    return bundle.authority_partition(CONFIG, scope, ledger)[0]


def validate_requirement(
    requirement: dict,
    versions: set[str],
    authorities: dict[str, dict],
    surface_map: dict[str, dict],
    allowed_surfaces: set[str],
) -> dict:
    return bundle.validate_requirement(
        CONFIG,
        requirement,
        versions,
        authorities,
        surface_map,
        allowed_surfaces,
    )


def build(
    ledger: dict,
    register: dict,
    versions: set[str],
) -> tuple[list[dict], dict, str]:
    return bundle.build(CONFIG, ledger, register, versions)
