"""Composed HKDF owners: delegated field Drop, not an invented destructor.

Registration covers public owner and named operation-scratch clearing dispatch.
Whole-frame erasure, timing qualification and independent review are not claimed.
"""
import re
import tomllib

import rust_source_contract as rust

ID = "registered.algorithm.hkdf"
MODERN = "crates/brynja-crypto/src/hkdf/derive.rs"
LEGACY = "crates/brynja-legacy-hkdf/src/lib.rs"
RECORD = {
    "capability": "algorithm.hkdf",
    "symbol": MODERN + "#Prk",
    "fields": ["region:caller-backed-owned-secret-region", "local:algorithm-and-thread-local-marker"],
    "temporaries": ["block:Scratch<64>", "previous:Scratch<64>", "encoded:Scratch<514>",
                    "hmac:delegated-secret-owner", "caller-input-and-compiler-copies:outside-owned-storage"],
    "cleanup_model": "transitive-owned-fields-and-consuming-handoffs",
    "delegated_owners": ["core.owned-secret-region", "core.secret-region-initialization",
                         "registered.algorithm.hmac"],
    "cleanup_bindings": [MODERN + "#DerivedKey", MODERN + "#Scratch::drop",
                         LEGACY + "#Sha1Prk", LEGACY + "#DerivedKey", LEGACY + "#Scratch::drop",
                         "crates/brynja-core/src/secret_memory.rs#OwnedSecretRegion"],
    "compiler_checks": ["python3 scripts/hkdf/check-hkdf-owner-cleanup.py modern",
                        "python3 scripts/hkdf/check-hkdf-owner-cleanup.py legacy",
                        "python3 scripts/hkdf/check-hkdf-operation-cleanup.py modern",
                        "python3 scripts/hkdf/check-hkdf-operation-cleanup.py legacy"],
    "compiler_scope": "public-owner-and-operation-scratch-dispatch-x86_64-rust-1.90.0-and-1.99.1-abort-and-unwind",
    "qualification": "side-channel-qualification-and-independent-review-pending",
    "evidence": ["crates/brynja-crypto/tests/hkdf_derivation.rs",
                 "crates/brynja-legacy-hkdf/tests/derivation.rs",
                 "assurance/hkdf-owner-cleanup/src/lib.rs",
                 "scripts/hkdf/check-hkdf-owner-cleanup.py", "scripts/hkdf/hkdf_owner_codegen.py",
                 "scripts/cryptography/test-hkdf-owner-contract.py",
                 "assurance/hkdf-operation-cleanup/src/lib.rs",
                 "scripts/hkdf/check-hkdf-operation-cleanup.py", "scripts/hkdf/hkdf_operation_codegen.py"],
    "storage": "caller-backed-regions-with-fixed-operation-scratch",
    "output_classification": "typed-secret-owned",
    "partial_failure_policy": "clear-complete-secret-destination",
    "compatibility_profiles": [{"id": "legacy-sha1", "symbol": LEGACY + "#Sha1Prk",
                                "admission": "explicit-LegacyUse-no-modern-fallback",
                                "output": LEGACY + "#DerivedKey", "scratch_bytes": 20,
                                "qualification": "side-channel-qualification-and-independent-review-pending",
                                "routes": [{"id": "portable", "storage": "caller-backed-clearing-regions"}]}],
}
REVIEWED_PATHS = {
    MODERN, LEGACY, "scripts/cryptography/hkdf_owner_contract.py",
    "scripts/cryptography/test-hkdf-owner-contract.py",
    "assurance/hkdf-owner-cleanup/Cargo.toml", "assurance/hkdf-owner-cleanup/Cargo.lock",
    "assurance/hkdf-owner-cleanup/src/lib.rs", "scripts/hkdf/check-hkdf-owner-cleanup.py",
    "scripts/hkdf/hkdf_owner_codegen.py",
    "assurance/hkdf-operation-cleanup/Cargo.toml", "assurance/hkdf-operation-cleanup/Cargo.lock",
    "assurance/hkdf-operation-cleanup/src/lib.rs", "scripts/hkdf/check-hkdf-operation-cleanup.py",
    "scripts/hkdf/hkdf_operation_codegen.py",
}


def validate(root, owner, registered, current):
    def require(condition, message):
        if not condition:
            raise ValueError("HKDF composed-owner contract: " + message)

    require(owner == {"id": ID, **RECORD}, "canonical record changed")
    require(set(RECORD["delegated_owners"]) <= {row.get("id") for row in [*registered, *current]},
            "delegated clearing owner absent")
    for source, types in ((MODERN, ("Prk", "DerivedKey")), (LEGACY, ("Sha1Prk", "DerivedKey"))):
        text = rust.scrub((root / source).read_text())
        for kind in types:
            rust.validate_type(root, source + "#" + kind, {"region", "local"})
            region = r"OwnedSecretRegion<'a>" if kind != "DerivedKey" else r"Option<OwnedSecretRegion<'a>>"
            require(re.search(r"pub struct " + kind + r"<[^\n]+>\s*\{\s*region:\s*" + region + r",", text),
                    "owner must contain its exact clearing region")
            require(not re.search(r"\bDrop\s+for\s+" + kind + r"\b", text),
                    "direct destructor is not this composed contract")
    checks = tomllib.loads((root / "verification/checks.toml").read_text())["checks"]
    for component, family in (("hkdf", "modern"), ("legacy_hkdf", "legacy")):
        for check_id, script in (("owner-dispatch", "owner"), ("operation-scratch", "operation")):
            selected = [c for c in checks if c["component"] == component and c["id"] == check_id]
            require(len(selected) == 1 and selected[0]["command"] ==
                    ["python3", f"scripts/hkdf/check-hkdf-{script}-cleanup.py", family],
                    "scoped compiler check missing or replaced")
            require(selected[0]["category"] == "compiler", "compiler category changed")
