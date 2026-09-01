#!/usr/bin/env python3
"""Canonical v0.24.6 owner identities and operation-flow contracts."""

CURRENT_OWNER_SYMBOLS = {
    "adapter.sanitized-secret": "crates/brynja-sanitization/src/lib.rs#SanitizedSecret",
    "core.abstract-secret-initialization": "crates/brynja-core/src/secret.rs#SecretInitialization",
    "core.abstract-secret-state": "crates/brynja-core/src/secret.rs#SecretState",
    "core.owned-secret-region": "crates/brynja-core/src/secret_memory.rs#OwnedSecretRegion",
    "core.raw-entropy": "crates/brynja-core/src/entropy.rs#RawEntropy",
    "core.secret-region-initialization": "crates/brynja-core/src/secret_memory.rs#SecretRegionInitialization",
    "core.secure-random": "crates/brynja-core/src/secure_random.rs#SecureRandom",
    "test.deterministic-random": "crates/brynja-test-support/src/deterministic_random.rs#DeterministicRandom",
}

CURRENT_CLEANUP_CALLS = {
    "adapter.sanitized-secret": {
        "crates/brynja-sanitization/src/lib.rs#SanitizedSecret::clear": None,
    },
    "core.abstract-secret-initialization": {
        "crates/brynja-core/src/secret.rs#SecretInitialization::drop":
            "crate::secret_destruction::run_destruction(",
    },
    "core.abstract-secret-state": {
        "crates/brynja-core/src/secret.rs#SecretState::drop":
            "crate::secret_destruction::run_destruction(",
    },
    "core.owned-secret-region": {
        "crates/brynja-core/src/secret_memory.rs#OwnedSecretRegion::clear":
            "crate::secret_memory_volatile::zeroize_region_volatile(",
        "crates/brynja-core/src/secret_memory.rs#OwnedSecretRegion::drop":
            "crate::secret_memory_volatile::zeroize_region_volatile(",
    },
    "core.raw-entropy": {
        "crates/brynja-core/src/secret_memory.rs#OwnedSecretRegion::drop": None,
    },
    "core.secret-region-initialization": {
        "crates/brynja-core/src/secret_memory.rs#SecretRegionInitialization::drop":
            "crate::secret_memory_volatile::zeroize_region_volatile(",
    },
    "core.secure-random": {
        "crates/brynja-core/src/secure_random.rs#SecureRandom::drop":
            "<E as SecureRandomEngine>::uninstantiate(",
    },
    "test.deterministic-random": {
        "crates/brynja-test-support/src/deterministic_random.rs#DeterministicRandom::clear_state":
            "brynja_core::clear_owned_region(",
        "crates/brynja-test-support/src/deterministic_random.rs#DeterministicRandom::drop":
            "brynja_core::clear_owned_region(",
    },
}

OPERATION_CONTRACTS = {
    "aead": {
        "generate-key": ("typed-secret-owned", "clear-complete-secret-destination", "not-applicable"),
        "import-key": ("typed-secret-owned", "clear-complete-secret-destination", "not-applicable"),
        "open": ("typed-secret-owned", "clear-complete-secret-destination", "before-output-release"),
        "seal": ("explicit-public-declassification", "unchanged-destination", "not-applicable"),
    },
    "asymmetric": {
        "decapsulate-shared-secret": ("typed-secret-owned", "clear-complete-secret-destination", "before-output-release"),
        "decrypt": ("typed-secret-owned", "clear-complete-secret-destination", "before-output-release"),
        "derive-shared-secret": ("typed-secret-owned", "clear-complete-secret-destination", "before-output-release"),
        "encapsulate-ciphertext": ("explicit-public-declassification", "unchanged-destination", "not-applicable"),
        "encapsulate-shared-secret": ("typed-secret-owned", "clear-complete-secret-destination", "not-applicable"),
        "encrypt": ("explicit-public-declassification", "unchanged-destination", "not-applicable"),
        "export-private": ("typed-secret-owned", "clear-complete-secret-destination", "not-applicable"),
        "export-public": ("explicit-public-declassification", "unchanged-destination", "not-applicable"),
        "generate-private": ("typed-secret-owned", "clear-complete-secret-destination", "not-applicable"),
        "generate-public": ("explicit-public-declassification", "unchanged-destination", "not-applicable"),
        "import-private": ("typed-secret-owned", "clear-complete-secret-destination", "not-applicable"),
        "sign": ("explicit-public-declassification", "unchanged-destination", "not-applicable"),
        "verify": ("no-output", "not-applicable", "before-output-release"),
    },
    "fixed-hash": {
        "hardened-derived-output": ("typed-secret-owned", "clear-complete-secret-destination", "not-applicable"),
        "public-digest": ("explicit-public-declassification", "unchanged-destination", "not-applicable"),
    },
    "hash-xof-family": {
        "hardened-secret-output": ("typed-secret-owned", "clear-complete-secret-destination", "not-applicable"),
        "public-fixed-output": ("explicit-public-declassification", "unchanged-destination", "not-applicable"),
        "public-xof-output": ("explicit-public-declassification", "unchanged-destination", "not-applicable"),
    },
    "keyed-construction": {
        "derive-secret": ("typed-secret-owned", "clear-complete-secret-destination", "not-applicable"),
        "generate-authenticator": ("explicit-public-declassification", "unchanged-destination", "not-applicable"),
        "verify-authenticator": ("no-output", "not-applicable", "before-output-release"),
    },
    "protocol": {
        "emit-public-wire": ("explicit-public-declassification", "unchanged-destination", "after-authentication"),
        "export-secret": ("typed-secret-owned", "clear-complete-secret-destination", "before-output-release"),
        "receive-secret-plaintext": ("typed-secret-owned", "clear-complete-secret-destination", "before-output-release"),
    },
    "public-component": {
        "public-component-output": ("public-non-secret", "unchanged-destination", "not-applicable"),
    },
    "public-format": {
        "decode-public": ("public-non-secret", "unchanged-destination", "not-applicable"),
        "encode-public": ("public-non-secret", "unchanged-destination", "not-applicable"),
    },
    "rejected": {
        "rejected": ("no-output", "not-applicable", "not-applicable"),
    },
    "secret-component": {
        "consume-secret": ("no-output", "not-applicable", "before-output-release"),
        "produce-secret": ("typed-secret-owned", "clear-complete-secret-destination", "before-output-release"),
    },
    "secret-format": {
        "decode-secret": ("typed-secret-owned", "clear-complete-secret-destination", "before-output-release"),
        "encode-secret": ("typed-secret-owned", "clear-complete-secret-destination", "not-applicable"),
    },
    "symmetric-cipher": {
        "decrypt": ("typed-secret-owned", "clear-complete-secret-destination", "not-applicable"),
        "encrypt": ("explicit-public-declassification", "unchanged-destination", "not-applicable"),
        "generate-key": ("typed-secret-owned", "clear-complete-secret-destination", "not-applicable"),
        "import-key": ("typed-secret-owned", "clear-complete-secret-destination", "not-applicable"),
    },
    "test-secret-support": {
        "export-test-secret": ("explicit-public-declassification", "unchanged-destination", "not-applicable"),
        "retain-test-secret": ("typed-secret-owned", "clear-complete-secret-destination", "not-applicable"),
    },
}

REVIEWED_SOURCE_PATHS = {
    "assurance/api-profile-contract/src/lib.rs",
    "crates/brynja-core/src/entropy/assurance_contract.rs",
    "crates/brynja-core/src/entropy.rs",
    "crates/brynja-core/src/secret.rs",
    "crates/brynja-core/src/secret/assurance_contract.rs",
    "crates/brynja-core/src/secret_destruction.rs",
    "crates/brynja-core/src/secret_memory.rs",
    "crates/brynja-core/src/secret_memory/assurance_contract.rs",
    "crates/brynja-core/src/secret_memory_volatile.rs",
    "crates/brynja-core/src/secure_random.rs",
    "crates/brynja-core/src/secure_random/assurance_contract.rs",
    "crates/brynja-hash-sha2/src/sha224.rs",
    "crates/brynja-hash-sha2/src/sha256.rs",
    "crates/brynja-hash-sha2/src/sha512_state.rs",
    "crates/brynja-hash-sha3/src/sponge.rs",
    "crates/brynja-sanitization/src/lib.rs",
    "crates/brynja-sanitization/src/assurance_contract.rs",
    "crates/brynja-test-support/src/deterministic_random.rs",
    "crates/brynja-test-support/src/deterministic_random/assurance_contract.rs",
    "scripts/cryptography/api_profile_contracts.py",
    "scripts/cryptography/api_profile_model.py",
    "scripts/cryptography/check-api-profile-contract.sh",
    "scripts/cryptography/check-secret-owner-compiler.py",
    "scripts/cryptography/rust_source_contract.py",
    "scripts/cryptography/secret_owner_compiler.py",
    "scripts/cryptography/test-api-profiles.py",
    "scripts/cryptography/test-secret-owner-compiler.py",
}
