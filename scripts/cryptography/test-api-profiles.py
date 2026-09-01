#!/usr/bin/env python3
"""Mutation tests for the cryptographic API-profile closure register."""

from __future__ import annotations

import copy

import api_profile_model as model


def rejects(mutator, expected: str) -> None:
    policy = copy.deepcopy(model.read_policy())
    surfaces = copy.deepcopy(model.read_surfaces())
    mutator(policy, surfaces)
    try:
        model.build_register(policy, surfaces)
    except model.ProfileError as error:
        assert expected in str(error), str(error)
    else:
        raise AssertionError(f"mutation unexpectedly passed: {expected}")


def remove_assignment(policy: dict, _surfaces: dict) -> None:
    policy["assignment"][0]["ids"].remove("algorithm.sha2")


def remove_dimension(policy: dict, _surfaces: dict) -> None:
    policy["api"]["dimensions"].remove("bit-input")


def forbid_hash_bits(policy: dict, _surfaces: dict) -> None:
    profile = policy["profile"]["fixed-hash"]
    profile["required"].remove("bit-input")
    profile["forbidden"].append("bit-input")


def remove_ownership(policy: dict, _surfaces: dict) -> None:
    profile = policy["profile"]["aead"]
    profile["required"].remove("ownership")
    profile["not_applicable"].append("ownership")


def remove_field(policy: dict, _surfaces: dict) -> None:
    policy["secret-template"]["aead-key"]["fields"] = []


def remove_temporary(policy: dict, _surfaces: dict) -> None:
    policy["secret-template"]["private-key"]["temporaries"] = []


def remove_edge(policy: dict, _surfaces: dict) -> None:
    policy["lifecycle"]["edges"].remove("recoverable-unwind")


def replace_sanitizer(policy: dict, _surfaces: dict) -> None:
    policy["cleanup"]["mandatory_core_symbol"] = "crates/brynja-core/src/lib.rs#fake"


def remove_evidence(policy: dict, _surfaces: dict) -> None:
    policy["current-secret-owner"][0]["evidence"] = []


def remove_consumer(policy: dict, _surfaces: dict) -> None:
    policy["profile"]["protocol"]["consumers"] = []


def remove_rejection(policy: dict, _surfaces: dict) -> None:
    policy["rejection"]["values"].remove("downstream-hardened-marker-forgery")


def remove_residual(policy: dict, _surfaces: dict) -> None:
    policy["residual"]["risks"].remove("process-abort")


def change_source(policy: dict, _surfaces: dict) -> None:
    policy["reviewed-source"][0]["sha256"] = "0" * 64


def remove_surface(policy: dict, surfaces: dict) -> None:
    surfaces["surfaces"] = [
        row for row in surfaces["surfaces"] if row["id"] != "algorithm.sha2"
    ]
    policy["schema"]["surface_register_sha256"] = model.sha256(model.json_bytes(surfaces))


def require_adapter(policy: dict, _surfaces: dict) -> None:
    policy["cleanup"]["adapter_required_for_core"] = True


def main() -> int:
    policy = model.read_policy()
    surfaces = model.read_surfaces()
    first = model.build_register(policy, surfaces)
    second = model.build_register(policy, surfaces)
    assert model.json_bytes(first) == model.json_bytes(second)
    assert len(first["capabilities"]) == 129
    assert len(first["api_dimensions"]) == 22
    assert len(first["current_secret_owners"]) == 8
    assert len(first["planned_secret_owners"]) == 75
    assert all(len(row["api"]) == 22 for row in first["capabilities"])
    assert all(row["consumer_links"] for row in first["capabilities"])
    assert all(row["explicit_rejections"] == list(model.REJECTIONS) for row in first["capabilities"])
    assert all(row["residual_risks"] == list(model.RESIDUALS) for row in first["planned_secret_owners"])
    assert all(row["lifecycle_edges"] == list(model.LIFECYCLE_EDGES) for row in first["planned_secret_owners"])
    hashes = {row["id"]: row for row in first["capabilities"]}
    assert hashes["algorithm.sha2"]["api"]["bit-input"]["owner"] == "0.24.7"
    assert hashes["algorithm.sha2"]["api"]["ownership"]["owner"] == "0.24.8"
    assert hashes["algorithm.sha3-shake"]["api"]["bit-input"]["owner"] == "0.24.9"
    assert hashes["algorithm.sha3-shake"]["api"]["ownership"]["owner"] == "0.24.10"
    model.validate_cleanup(policy, model.ROOT, adapter_available=False)

    for mutator, expected in (
        (remove_assignment, "no API profile"),
        (remove_dimension, "API dimensions"),
        (forbid_hash_bits, "byte and bit input"),
        (remove_ownership, "hardened ownership"),
        (remove_field, "lacks fields or temporaries"),
        (remove_temporary, "lacks fields or temporaries"),
        (remove_edge, "lifecycle edges"),
        (replace_sanitizer, "mandatory cleanup symbol"),
        (remove_evidence, "lacks fields, temporaries, or evidence"),
        (remove_consumer, "exact consumer links"),
        (remove_rejection, "explicit unsafe or nonstandard rejections"),
        (remove_residual, "residual risks"),
        (change_source, "reviewed secret-state source changed"),
        (remove_surface, "semantic capability count"),
        (require_adapter, "optional adapter cannot be mandatory"),
    ):
        rejects(mutator, expected)
    print("cryptographic API-profile policy rejects fifteen closure regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
