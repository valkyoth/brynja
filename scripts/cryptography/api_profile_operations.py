"""Canonical operation classification contracts for the API-profile policy."""

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
    "general-sha512-t": {
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
