# Brynja 0.24.26 Release Notes

Status: implementation and repository checks PASS; awaiting final owner sign-off

The supplied review of `908842f6` identified no defect requiring remediation.
Its informational notes are dispositioned in the permanent pentest report;
declassification intent, caller input budgets and sanitizer limitations are
clarified without changing Rust, CI or the release flow. Final owner sign-off
and release checks remain pending.

## Scope

The explicit default-off `general-sha512-t` feature in `brynja-hash-sha2`
now hashes messages for every t in 1..=511 except 384:

- `Sha512T`: incremental byte input, consuming byte/bit finalization, parameter
  and length queries and non-mutating length preflight. `sha512_t` and
  `sha512_t_bits` provide ordinary one-shot public-data hashing.
- `HardenedSha512T`: sealed secret-bearing state, consuming public/secret
  byte/bit finalization and cancellation. Four hardened one-shot functions
  preserve the same ownership boundary.
- `Sha512TSecretDigest`: parameter-bound borrowed secret owner; exact-width
  destination, canonical low unused bits, complete destination clearing on
  every error and Drop. Explicit consuming `declassify` requires
  `PublicDeclassification`, creates a public copy and clears the former owner.

Secret paths never stage output through `Sha512TDigest::from_bytes` or a public
digest. The importer remains for public bytes; raw slices cannot prove their
confidentiality at the type level. Secret outputs have no Copy, Clone, formatting,
equality, AsRef, Deref or implicit public conversion. Caller inputs and copies
remain caller responsibilities.

## Implementation and verification

General hashing reuses the existing SHA-512 compression/padding engines.
Hardened state reuses the registered SHA-2 owner and all eight mandatory clearing
regions; no unsafe, allocation, native instruction, optional cleanup or external
dependency is introduced. Public t-only IV derivation precedes secret input.

The candidate adds 4,590 independent byte/bit digest cases across all 510 t,
named-identity and million-byte checks, irregular streaming, all tail widths,
padding boundaries, overflow admission, destination errors, unwind and Drop.
Compiled mutations must fail real assertions, and downstream compile failures
test affine ownership, sealed capabilities and explicit declassification.
Source-bound MIR control-flow checks inspect consuming finalizers and
declassification under Rust 1.90.0/1.98.1 debug/release with unwind enabled;
existing owner checks retain the eight clearing calls in MIR/LLVM/assembly.
Scoped Miri/ASan coverage is registered for the new API. Actual completed runs
are recorded in the [candidate report](../security/pentest/v0.24.26.md).

## Limits and release flow

General SHA-512/t remains **In progress**: v0.24.27–v0.24.29 retain lifecycle,
package freeze and final family evidence. The six named SHA-2 APIs are unchanged.
Arbitrary t has no implicit HMAC, protocol, signature or FIPS admission; short
outputs have weak generic security bounds. No CPU backend becomes admitted.
No named independent cryptographic review or FIPS validation is claimed.

Ordinary state is not zeroized. Hardened cleanup does not promise erasure of
registers, compiler copies/spills, caches, swap, dumps, DMA or caller-owned copies,
and cannot run after forget, abort, double-panic termination or power loss.
Synchronous work is linear in input length; callers bound update chunks and
invalid secret destination sizes (clearing is linear in destination size).

The facade advances to 0.24.26 without reexporting the extension. Support-crate
versions and sanitization 2.1.0 remain unchanged. Zero crates are selected for
publication; the next scheduled checkpoint is v0.25.2. Obtain exceptional owner
pentest/retest, complete release checks, commit the report, wait for green
GitHub/CodeQL and explicit tag permission.
