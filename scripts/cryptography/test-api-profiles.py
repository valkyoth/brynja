#!/usr/bin/env python3
"""Mutation tests for the cryptographic API-profile closure register."""

from __future__ import annotations

import copy
from pathlib import Path
from tempfile import TemporaryDirectory

import api_profile_model as model
import rust_source_contract as rust_contract


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


def fabricated_current_owner(policy: dict, _surfaces: dict) -> None:
    policy["current-secret-owner"][3] = {
        "id": "fabricated.not-a-real-owner",
        "symbol": "crates/brynja-core/src/secure_random.rs#Result",
        "sanitization_symbol": "crates/brynja-core/src/secure_random.rs#Result",
        "cleanup_callers": ["crates/brynja-core/src/secure_random.rs#Result"],
        "fields": ["invented:secret"],
        "temporaries": ["invented:secret"],
        "evidence": ["crates/brynja-core/tests/entropy.rs"],
        "storage": "fabricated",
    }


def fabricated_sanitizer(policy: dict, _surfaces: dict) -> None:
    owner = policy["current-secret-owner"][3]
    owner["sanitization_symbol"] = "crates/brynja-core/src/secure_random.rs#Result"


def inconsistent_owner_fields(policy: dict, _surfaces: dict) -> None:
    owner = next(
        item for item in policy["current-secret-owner"]
        if item["id"] == "core.secure-random"
    )
    owner["fields"][0] = "invented:secret"


def missing_registered_type(policy: dict, _surfaces: dict) -> None:
    policy["registered-secret-owner"].append({
        "capability": "algorithm.sha2",
        "id": "registered.algorithm.sha2",
        "symbol": "crates/brynja-hash-sha2/src/sha256.rs#HardenedSecretOwner",
        "fields": ["state:secret"],
        "temporaries": ["schedule:secret"],
        "sanitization_symbol": "crates/brynja-core/src/secret_memory_volatile.rs#zeroize_region_volatile",
        "cleanup_callers": ["crates/brynja-hash-sha2/src/sha256.rs#HardenedSecretOwner::drop"],
        "evidence": ["crates/brynja-hash-sha2/tests/sha256.rs"],
        "storage": "crate-owned",
        "output_classification": "typed-secret-owned",
        "partial_failure_policy": "clear-complete-secret-destination",
    })


def duplicate_registered_coverage(policy: dict, _surfaces: dict) -> None:
    policy["registered-secret-owner"] = [
        {"capability": "algorithm.sha2"}, {"capability": "algorithm.sha2"},
    ]


def downgrade_template(policy: dict, _surfaces: dict) -> None:
    policy["secret-template"]["private-key"]["secret_output_classification"] = "public-non-secret"


def remove_operation(policy: dict, _surfaces: dict) -> None:
    del policy["profile"]["aead"]["operations"]["open"]


def downgrade_operation(profile: str, operation: str):
    def mutate(policy: dict, _surfaces: dict) -> None:
        policy["profile"][profile]["operations"][operation]["output_classification"] = "public-non-secret"
    return mutate


def parser_rejects_comment_and_string_fabrication() -> None:
    with TemporaryDirectory(prefix="brynja-rust-contract-") as directory:
        root = Path(directory)
        source = root / "fixture.rs"
        source.write_text(
            '// struct Fabricated { invented: u8 }\n'
            'const TEXT: &str = "fn erase() {}";\n'
            'pub struct Real { field: u8 }\n',
            encoding="utf-8",
        )
        try:
            rust_contract.validate_type(root, "fixture.rs#Fabricated", {"invented"})
        except rust_contract.RustContractError:
            pass
        else:
            raise AssertionError("comment fabricated a Rust owner")
        try:
            rust_contract.validate_callable(root, "fixture.rs#erase")
        except rust_contract.RustContractError:
            pass
        else:
            raise AssertionError("string fabricated a Rust sanitizer")


def main() -> int:
    policy = model.read_policy()
    surfaces = model.read_surfaces()
    first = model.build_register(policy, surfaces)
    second = model.build_register(policy, surfaces)
    assert model.json_bytes(first) == model.json_bytes(second)
    assert len(first["capabilities"]) == 129
    assert len(first["api_dimensions"]) == 22
    assert len(first["current_secret_owners"]) == 8
    assert len(first["registered_secret_owners"]) == 0
    assert len(first["planned_secret_owners"]) == 75
    assert all(len(row["api"]) == 22 for row in first["capabilities"])
    assert all(row["consumer_links"] for row in first["capabilities"])
    assert all(row["explicit_rejections"] == list(model.REJECTIONS) for row in first["capabilities"])
    assert all(row["residual_risks"] == list(model.RESIDUALS) for row in first["planned_secret_owners"])
    assert all(row["lifecycle_edges"] == list(model.LIFECYCLE_EDGES) for row in first["planned_secret_owners"])
    assert all(row["state"] == "planned" for row in first["planned_secret_owners"])
    assert all("symbol" not in row and "sanitization_symbol" not in row for row in first["planned_secret_owners"])
    assert first["capabilities"][0]["operations"]
    hashes = {row["id"]: row for row in first["capabilities"]}
    assert hashes["algorithm.sha2"]["api"]["bit-input"]["owner"] == "0.24.7"
    assert hashes["algorithm.sha2"]["api"]["ownership"]["owner"] == "0.24.8"
    assert hashes["algorithm.sha3-shake"]["api"]["bit-input"]["owner"] == "0.24.9"
    assert hashes["algorithm.sha3-shake"]["api"]["ownership"]["owner"] == "0.24.10"
    model.validate_cleanup(policy, model.ROOT, adapter_available=False)
    parser_rejects_comment_and_string_fabrication()

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
        (fabricated_current_owner, "inventory is incomplete or duplicated"),
        (fabricated_sanitizer, "free Rust function is absent or duplicated"),
        (inconsistent_owner_fields, "owner fields differ from Rust struct"),
        (missing_registered_type, "Rust declaration HardenedSecretOwner"),
        (duplicate_registered_coverage, "capability coverage is duplicated"),
        (downgrade_template, "differs from secret template"),
        (remove_operation, "operation inventory drifted"),
    ):
        rejects(mutator, expected)
    downgraded = 0
    for profile, operations in model.contracts.OPERATION_CONTRACTS.items():
        for operation, contract in operations.items():
            if contract[0] == "typed-secret-owned":
                rejects(
                    downgrade_operation(profile, operation),
                    f"operation {operation} information flow drifted",
                )
                downgraded += 1
    assert downgraded == 22
    print(
        "cryptographic API-profile policy rejects twenty-three structural "
        "regressions and twenty-two secret-output downgrades"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
