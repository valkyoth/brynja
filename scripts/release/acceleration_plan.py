"""Bind opt-in acceleration usability and its pre-HMAC completion chain."""

from __future__ import annotations

import roadmap_schedule


FIRST = 30
LAST = 54
CONTRACT = (
    "Independent cryptographic review and FIPS validation are not prerequisites for ordinary opt-in acceleration.",
    "Cargo features select implementations, not proof of CPU support.",
    "No public route may require repository-only evidence cfgs or an independent attestation service.",
    "Future family design must inventory dedicated instructions, single-state SIMD, independent-message SIMD, hosted threading and ordinary/hardened public profiles.",
    "Add review-sized numbered patches before final family acceptance",
    "Final acceptance must exercise real package-external opt-in routes, not pass by skipping all backends.",
    "Freeze usable consumer tests before the final native sweep",
    "explicitly experimental static routes may carry QEMU-only correctness evidence with no native qualification.",
    "Validated-module restrictions remain certificate- and environment-specific.",
)
PROFILES = {
    30: ("default-off", "Portable/Prefer/Require", "without evidence-only cfgs"),
    31: ("no_std", "complete compiler target-feature bundles", "KATs"),
    32: ("scheduler/VM migration", "CPU and OS-state detection"),
    33: ("all six", "all 510", "byte/bit", "streaming"),
    34: ("sealed", "destruction", "typed secret output"),
    35: ("all four", "both SHAKE", "AVX2", "AArch64"),
    36: ("cSHAKE128/256", "function-name", "hosted"),
    37: ("hardened", "scratch", "destruction", "typed-secret"),
    38: ("KMAC/KMACXOF", "verification", "typed-secret"),
    39: ("TupleHash/TupleHashXOF", "item writers"),
    40: ("ParallelHash", "worker-result provenance", "std-threaded"),
    41: ("SHA-1", "legacy-only", "byte/bit"),
    42: ("hardened", "SHA-1", "typed output"),
    43: ("AVX2 eight-lane", "NEON four-lane", "hosted"),
    44: ("hardened MD5", "per-lane owners", "destruction"),
    45: ("SHA-224/256", "AVX2", "NEON", "independent-message"),
    46: ("SHA-512/t", "AVX2", "NEON", "SIMD"),
    47: ("Keccak", "independent-state", "batch APIs"),
    48: ("hardened", "batch APIs", "ParallelHash"),
    49: ("x86_64 SHA-512", "sha512 and avx/OS-state", "Rust 1.90"),
    50: ("RV64 Zknh", "experimental", "QEMU", "no automatic runtime dispatch"),
    51: ("facade features", "legacy crates", "independent publishing"),
    52: ("package-external", "every operational", "before the final native sweep"),
    53: ("exact-source", "AMD", "Intel", "AWS Arm", "Apple M2", "QEMU"),
    54: ("before HMAC", "public APIs", "separate", "FIPS status"),
}


def validate(entries, release_text, version_text, schedule=None):
    """Reject missing profiles, skipped readiness work and coupled claims."""
    schedule = roadmap_schedule.read() if schedule is None else schedule
    scopes = dict((v.removeprefix("v"), s) for v, _title, s in entries)
    records = {r["version"]: r for r in schedule["milestones"]}
    for text in (release_text, version_text):
        normalized = " ".join(text.split())
        for rule in CONTRACT:
            if rule not in normalized:
                raise ValueError("acceleration plan lost its availability contract")
    for patch in range(FIRST, LAST + 1):
        version = f"0.24.{patch}"
        if any(token not in scopes.get(version, "") for token in PROFILES[patch]):
            raise ValueError(f"{version} lost an acceleration usability profile")
        if f"0.24.{patch - 1}" not in records.get(version, {}).get("requires", []):
            raise ValueError("acceleration prerequisite chain was bypassed")
    if f"0.24.{LAST}" not in records.get("0.25.0", {}).get("requires", []):
        raise ValueError("HMAC bypassed acceleration usability closure")
