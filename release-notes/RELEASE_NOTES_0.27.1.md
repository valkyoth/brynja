# v0.27.1 candidate — portable AES-192 and AES-256 blocks

Internal development candidate; no crates.io publication is selected. Owner
pentest/retest, the clean-candidate finite final gate and exact-commit green
GitHub/CodeQL are still required. No security approval is inferred from tests.

## Implemented boundary

The default-off `hazmat-aes-block` feature on `brynja-crypto` or `brynja` now
exposes distinct `Aes192Key` / `Aes256Key` owners and optional caller-owned
`Aes192ExpandedKey` / `Aes256ExpandedKey` cached schedules. Key storage is
24/32 bytes and schedule storage is 208/240 bytes. Both widths implement exact
16-byte forward and inverse block operations with 12/14 rounds, including
AES-256's additional key-expansion SubWord step.

Secret output is guarded and cleared on admitted failure/unwind. Explicit
`PublicCiphertext` acknowledgement is required for public encryption, with
output committed only on success. There is no public decryption API. Keys,
schedules and output use caller storage without allocation. Cached schedules
retain key-equivalent material until clear/Drop; input copies remain the
caller's responsibility. Software owners remain non-Send/non-Sync.

Existing AES-128 and its trusted-provider contract retain their semantics;
provider encryption does not reject legitimate fixed-point outputs. The
external-provider interface remains AES-128 only. No HSM is required.

These are raw block primitives, not authenticated message encryption. No mode,
nonce management, padding, key generation, acceleration or TLS key schedule is
added. Higher layers must use an appropriate reviewed construction.

## Verification and limits

The [development record](../docs/assurance/aes-wide-development.md) describes
1510 authoritative single-block KAT records, full FIPS schedules, independent
forward/inverse comparisons, fault/unwind and ownership checks, mutation
controls, bounded proofs, selected Miri/ASan checks, fourteen-compiler consumers,
bounded emitted-code review and a separate 26-campaign timing screen. Each
registered result is scoped to its actual inputs; registration is not a pass.
Local runner observations are unauthenticated and are not certification.

The reviewed helper streams are limited to the recorded x86_64 compiler/profile
pairs. Timing is a bounded synthetic observation, not a constant-time proof.
Cortex-M consumer checks are compile-only. Clearing does not establish erasure
of compiler copies, spills, registers, paging, dumps, aborts or forgotten owners.
Physical side-channel and fault-injection resistance remain deployment concerns.

AES-family package-external acceptance, AESAVS MCT/MMT, broader AArch64 and
final-linked/LTO qualification and stronger fixed-versus-random timing remain
explicit v0.27.2 work. The broader AES-family requirement remains planned;
this candidate does not promote it to qualified status.

## Candidate workflow

The finite checklist retains targeted crypto/HKDF tests, lint/formatting,
bounded consumer endpoints, provider contracts, packaged HKDF compatibility,
requirements/registry controls, SBOM and dependency policy. It adds the wide-key
owner contract and current-compiler API diagnostics, not implicit Miri, sanitizer,
proof, timing, compiler-matrix or historical campaign reruns.

Packaged HKDF compatibility now admits exactly five fixture files for each AES
width in the composition crate, rejecting missing/extra/symlinked inputs and
archive drift. This is not AES-family package acceptance.

The facade version and isolated consumer pins advance to 0.27.1. Supporting
crate versions stay unchanged in this internal train. After owner review and
tested remediation, commit the accepted candidate, run the finite final gate,
wait for green GitHub/CodeQL and obtain explicit signed-tag authorization.
