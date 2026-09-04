#!/usr/bin/env python3
"""Canonical v0.24.14 owner identities and operation-flow contracts."""

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

SHA2_OWNER = (
    "crates/brynja-hash-sha2/src/hardened/owner.rs#"
    "brynja_hash_sha2::owner::HardenedSha2Owner"
)
SHA2_DROP = f"{SHA2_OWNER}::drop"
SHA2_WIPE = (
    "crates/brynja-hash-sha2/src/hardened/owner.rs#"
    "brynja_hash_sha2::HardenedSha2Owner::wipe"
)
SHA2_OWNER_RECORD = {
    "capability": "algorithm.sha2",
    "symbol": SHA2_OWNER,
    "fields": [
        "chaining_state:secret-derived",
        "partial_input:secret",
        "message_length:secret-derived",
        "phase:secret-derived",
        "message_schedule:secret-derived",
        "block_copy:secret-copy",
        "padding_block:secret-copy",
        "output_staging:secret-derived",
    ],
    "temporaries": [
        "round-scalars:register-copy-risk",
        "borrowed-input:caller-owned-copy-risk",
        "typed-output:caller-owned",
    ],
    "sanitization_symbol": SHA2_WIPE,
    "cleanup_callers": [SHA2_DROP],
    "evidence": [
        "crates/brynja-hash-sha2/tests/hardened.rs",
        "assurance/sha2-hardened-api/src/lib.rs",
        "scripts/zeroization/check-zeroization-codegen.sh",
        "scripts/sha2/check-sha2-hardened.py",
        "scripts/hash/check-final-acceptance.py",
    ],
    "storage": "crate-owned-fixed",
    "output_classification": "typed-secret-owned",
    "partial_failure_policy": "clear-complete-secret-destination",
}

SHA3_OWNER = (
    "crates/brynja-hash-sha3/src/hardened/owner.rs#"
    "brynja_hash_sha3::owner::HardenedFips202Owner"
)
SHA3_DROP = f"{SHA3_OWNER}::drop"
SHA3_WIPE = (
    "crates/brynja-hash-sha3/src/hardened/owner.rs#"
    "brynja_hash_sha3::HardenedFips202Owner::wipe"
)
SHA3_OWNER_RECORD = {
    "capability": "algorithm.sha3-shake",
    "symbol": SHA3_OWNER,
    "fields": [
        "sponge_lanes:secret-derived",
        "partial_input:secret",
        "message_length:secret-derived",
        "output_length:secret-derived",
        "cshake_setup_length:secret-derived",
        "cshake_domain:secret-derived",
        "phase:secret-derived",
        "suffix_staging:secret-copy",
        "padding_block:secret-copy",
        "squeeze_staging:secret-derived",
        "permutation_columns:secret-derived",
        "permutation_theta:secret-derived",
        "permutation_rearranged:secret-derived",
    ],
    "temporaries": [
        "round-scalars:register-copy-risk",
        "borrowed-input:caller-owned-copy-risk",
        "typed-output:caller-owned",
    ],
    "sanitization_symbol": SHA3_WIPE,
    "cleanup_callers": [SHA3_DROP],
    "evidence": [
        "crates/brynja-hash-sha3/tests/hardened.rs",
        "crates/brynja-hash-sha3/tests/cshake.rs",
        "assurance/sha3-hardened-api/src/lib.rs",
        "assurance/cshake-public-api/src/lib.rs",
        "scripts/sha3/check-sha3-hardened-codegen.sh",
        "scripts/sha3/check-sha3-hardened.py",
        "scripts/hash/check-final-acceptance.py",
    ],
    "storage": "crate-owned-fixed",
    "output_classification": "typed-secret-owned",
    "partial_failure_policy": "clear-complete-secret-destination",
}

KMAC_OWNER = (
    "crates/brynja-mac-kmac/src/core_state.rs#"
    "brynja_mac_kmac::core_state::KmacCore"
)
KMAC_DROP = f"{KMAC_OWNER}::drop"
KMAC_WIPE = (
    "crates/brynja-mac-kmac/src/core_state.rs#"
    "brynja_mac_kmac::KmacCore::wipe"
)
KMAC_OWNER_RECORD = {
    "capability": "algorithm.kmac",
    "symbol": KMAC_OWNER,
    "fields": [
        "hardened-cshake-state:secret-derived",
        "message-length:secret-derived",
        "key-strength-class:secret-derived",
    ],
    "temporaries": [
        "encoded-key-pending-byte:secret-copy",
        "verification-block:secret-derived",
        "comparison-difference:secret-derived",
        "borrowed-input:caller-owned-copy-risk",
        "typed-output:caller-owned",
    ],
    "sanitization_symbol": KMAC_WIPE,
    "cleanup_callers": [KMAC_DROP],
    "evidence": [
        "crates/brynja-mac-kmac/tests/api.rs",
        "crates/brynja-mac-kmac/tests/official_vectors.rs",
        "assurance/kmac-public-api/src/lib.rs",
        "assurance/kmac-conformance-rejected/src/lib.rs",
        "scripts/kmac/check-kmac-conformance-gate.sh",
        "scripts/kmac/check-kmac-codegen.sh",
        "scripts/kmac/check-kmac.py",
        "scripts/kmac/check-kmac-differential.py",
    ],
    "storage": "crate-owned-fixed",
    "output_classification": "typed-secret-owned",
    "partial_failure_policy": "clear-complete-secret-destination",
}

TUPLEHASH_OWNER = (
    "crates/brynja-hash-tuple/src/core_state.rs#"
    "brynja_hash_tuple::core_state::TupleCore"
)
TUPLEHASH_DROP = f"{TUPLEHASH_OWNER}::drop"
TUPLEHASH_WIPE = (
    "crates/brynja-hash-tuple/src/core_state.rs#"
    "brynja_hash_tuple::TupleCore::wipe"
)
TUPLEHASH_OWNER_RECORD = {
    "capability": "algorithm.tuplehash",
    "symbol": TUPLEHASH_OWNER,
    "fields": [
        "hardened-cshake-state:secret-derived",
        "pending-item-byte:secret-copy",
        "pending-item-width:secret-derived",
        "tuple-item-count:secret-derived",
        "streamed-item-remaining:secret-derived",
        "abandoned-item-state:secret-derived",
    ],
    "temporaries": [
        "encoded-item-length:secret-derived-clearing-owner",
        "borrowed-input:caller-owned-copy-risk",
        "typed-output:caller-owned",
    ],
    "sanitization_symbol": TUPLEHASH_WIPE,
    "cleanup_callers": [TUPLEHASH_DROP],
    "evidence": [
        "crates/brynja-hash-tuple/tests/api.rs",
        "crates/brynja-hash-tuple/tests/official_vectors.rs",
        "assurance/tuplehash-public-api/src/lib.rs",
        "scripts/tuplehash/check-tuplehash-codegen.sh",
        "scripts/tuplehash/check-tuplehash.py",
        "scripts/tuplehash/check-tuplehash-differential.py",
    ],
    "storage": "crate-owned-fixed",
    "output_classification": "typed-secret-owned",
    "partial_failure_policy": "clear-complete-secret-destination",
}

# Registration cannot define its own proof. Separate maps bind its compiler
# test, exact caller identity, and resolved sanitizer target.
REGISTERED_OWNER_CONTRACTS = {
    "registered.algorithm.sha2": {"record": SHA2_OWNER_RECORD},
    "registered.algorithm.sha3-shake": {"record": SHA3_OWNER_RECORD},
    "registered.algorithm.kmac": {"record": KMAC_OWNER_RECORD},
    "registered.algorithm.tuplehash": {"record": TUPLEHASH_OWNER_RECORD},
}
REGISTERED_OWNER_COMPILER_TESTS = {
    SHA2_OWNER: {
        "package": "brynja-hash-sha2",
        "contract_test": (
            "hardened::owner::assurance_contract::"
            "registered_algorithm_sha2_owner_contract_is_compiler_checked"
        ),
    },
    SHA3_OWNER: {
        "package": "brynja-hash-sha3",
        "contract_test": (
            "hardened::owner::assurance_contract::"
            "registered_algorithm_sha3_shake_owner_contract_is_compiler_checked"
        ),
    },
    KMAC_OWNER: {
        "package": "brynja-mac-kmac",
        "contract_test": (
            "core_state::assurance_contract::"
            "registered_algorithm_kmac_owner_contract_is_compiler_checked"
        ),
    },
    TUPLEHASH_OWNER: {
        "package": "brynja-hash-tuple",
        "contract_test": (
            "core_state::assurance_contract::"
            "registered_algorithm_tuplehash_owner_contract_is_compiler_checked"
        ),
    },
}
REGISTERED_CALLER_MIR_HEADERS = {
    SHA2_DROP: [
        "fn owner::<impl at crates/brynja-hash-sha2/src/hardened/owner.rs:78:1: 78:32>::"
        "drop(_1: &mut HardenedSha2Owner) -> () {"
    ],
    SHA3_DROP: [
        "fn owner::<impl at crates/brynja-hash-sha3/src/hardened/owner.rs:104:1: 104:60>::"
        "drop(_1: &mut HardenedFips202Owner<RATE>) -> () {"
    ],
    KMAC_DROP: [
        "fn core_state::<impl at crates/brynja-mac-kmac/src/core_state.rs:103:1: 103:99>::"
        "drop(_1: &mut KmacCore<S, RATE, STRENGTH>) -> () {"
    ],
    TUPLEHASH_DROP: [
        "fn core_state::<impl at crates/brynja-hash-tuple/src/core_state.rs:229:1: 229:24>::"
        "drop(_1: &mut TupleCore) -> () {"
    ],
}
REGISTERED_SANITIZER_MIR_IDENTITIES = {
    SHA2_WIPE: "HardenedSha2Owner::wipe(",
    SHA3_WIPE: "HardenedFips202Owner::<RATE>::wipe(",
    KMAC_WIPE: "KmacCore::<S, RATE, STRENGTH>::wipe(",
    TUPLEHASH_WIPE: "TupleCore::wipe(",
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
    "assurance/sha2-hardened-api/Cargo.lock",
    "assurance/sha2-hardened-api/Cargo.toml",
    "assurance/sha2-hardened-api/src/lib.rs",
    "assurance/sha3-hardened-api/Cargo.lock",
    "assurance/sha3-hardened-api/Cargo.toml",
    "assurance/sha3-hardened-api/src/lib.rs",
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
    "crates/brynja-hash-sha2/src/hardened/compress32.rs",
    "crates/brynja-hash-sha2/src/hardened/compress64.rs",
    "crates/brynja-hash-sha2/src/hardened/mod.rs",
    "crates/brynja-hash-sha2/src/hardened/output.rs",
    "crates/brynja-hash-sha2/src/hardened/owner.rs",
    "crates/brynja-hash-sha2/src/hardened/state32.rs",
    "crates/brynja-hash-sha2/src/hardened/state64.rs",
    "crates/brynja-hash-sha2/tests/hardened.rs",
    "crates/brynja-hash-sha3/src/sponge.rs",
    "crates/brynja-hash-sha3/src/cshake.rs",
    "crates/brynja-hash-sha3/src/sp800185.rs",
    "crates/brynja-hash-sha3/src/hardened/cshake.rs",
    "crates/brynja-hash-sha3/src/hardened/cshake/tests.rs",
    "crates/brynja-hash-sha3/src/hardened/fixed.rs",
    "crates/brynja-hash-sha3/src/hardened/mod.rs",
    "crates/brynja-hash-sha3/src/hardened/output.rs",
    "crates/brynja-hash-sha3/src/hardened/owner.rs",
    "crates/brynja-hash-sha3/src/hardened/permutation.rs",
    "crates/brynja-hash-sha3/src/hardened/sponge.rs",
    "crates/brynja-hash-sha3/src/hardened/xof.rs",
    "crates/brynja-hash-sha3/tests/hardened.rs",
    "crates/brynja-hash-sha3/tests/cshake.rs",
    "assurance/cshake-public-api/src/lib.rs",
    "assurance/kmac-public-api/src/lib.rs",
    "assurance/kmac-conformance-rejected/src/lib.rs",
    "crates/brynja-mac-kmac/src/core_state.rs",
    "crates/brynja-mac-kmac/src/output.rs",
    "crates/brynja-mac-kmac/src/packer.rs",
    "crates/brynja-mac-kmac/tests/api.rs",
    "scripts/kmac/check-kmac-codegen.sh",
    "scripts/kmac/check-kmac-conformance-gate.sh",
    "crates/brynja-hash-tuple/src/backend.rs",
    "crates/brynja-hash-tuple/src/core_state.rs",
    "crates/brynja-hash-tuple/src/item.rs",
    "crates/brynja-hash-tuple/src/secret_encoding.rs",
    "assurance/tuplehash-public-api/src/lib.rs",
    "scripts/tuplehash/check-tuplehash-codegen.sh",
    "crates/brynja-sanitization/src/lib.rs",
    "crates/brynja-sanitization/src/assurance_contract.rs",
    "crates/brynja-test-support/src/deterministic_random.rs",
    "crates/brynja-test-support/src/deterministic_random/assurance_contract.rs",
    "scripts/cryptography/api_profile_contracts.py",
    "scripts/cryptography/api_profile_model.py",
    "scripts/cryptography/check-api-profile-contract.sh",
    "scripts/cryptography/check-secret-owner-compiler.py",
    "scripts/cryptography/mir_cleanup_flow.py",
    "scripts/cryptography/rust_source_contract.py",
    "scripts/cryptography/secret_owner_compiler.py",
    "scripts/cryptography/test-api-profiles.py",
    "scripts/cryptography/test-mir-cleanup-flow.py",
    "scripts/cryptography/test-secret-owner-compiler.py",
    "scripts/sha2/check-sha2-hardened-codegen.sh",
    "scripts/sha2/check-sha2-hardened.py",
    "scripts/sha2/sha2_hardened.py",
    "scripts/sha2/test-sha2-hardened.py",
    "scripts/sha3/check-sha3-hardened-codegen.sh",
    "scripts/sha3/check-sha3-hardened.py",
    "scripts/sha3/sha3_hardened.py",
    "scripts/sha3/test-sha3-hardened.py",
}
