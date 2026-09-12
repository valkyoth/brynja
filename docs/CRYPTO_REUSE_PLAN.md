# Reusable cryptography and public consumer APIs

Status: planned, pre-1.0. This document does not claim that any new operation
is implemented, independently reviewed or FIPS validated. It supplements the
numbered [release plan](RELEASE_PLAN.md) and its checked dependency graph.
It was added after the signed v0.24.39 tag; the tag and its evidence are unchanged.

## Ownership boundary

Brynja implements reusable cryptographic algorithms, arithmetic and security
utilities once, in first-party Rust. `eth` is a motivating requirements example,
not an implementation target of this plan. No changes, migration, dependency
replacement or release in `eth` or another consumer are required here.
Consumers can select Brynja's public APIs and own their protocol rules.
Production Brynja leaves must never
depend on `eth`, `k256`, `tiny-keccak`, another external cryptographic engine,
or a C/native cryptography library. Existing implementations can inform the
required operation inventory, but do not replace Brynja's complete API,
constant-work, cleanup or assurance requirements.

The inspected `eth` interfaces include optional `tiny-keccak` hashing, optional
`k256` prehash public-key recovery, and a public `subtle::Choice` export. Its
EVM core also contains first-party SHA-256, RIPEMD-160, BLAKE2 compression,
modular and curve arithmetic. `num-bigint` is currently a dev-only arithmetic
oracle. These observations explain the requested capabilities; they do not add
consumer work to the roadmap. Self-contained, pinned public API fixtures must
run without a live `eth` checkout or any other downstream project.

Brynja should make it possible for a consumer's selected runtime cryptographic
implementation closure to use independently selectable Brynja leaves; this
does not mean a single
monolithic package, no non-crypto dependencies, or removal of independent
test-only oracles. The existing sanitization admission boundary remains valid.
No new third-party runtime dependency is authorized by this roadmap.

## Numbered implementation chains

| Versions | Complete reusable capability |
| --- | --- |
| 0.378.0–0.378.8 | First-party constant-time utilities, fallible consumer boundaries, sizing/workspace and error-preserving adapters |
| 0.379.0–0.379.8 | Prehashed and recoverable secp256k1 signing, verification, key recovery and bounded batches |
| 0.380.0–0.380.7 | Distinct Concatenation and X9.63 KDF profiles, typed secret outputs and accelerated derivation |
| 0.381.0–0.381.8 | Fully specified ECIES suites, encrypt/decrypt, shared/authenticated information, resource bounds and accelerated composition |
| 0.382.0–0.382.7 | BN254 base/scalar/extension fields, validated G1/G2 operations, scalar multiplication and MSM |
| 0.383.0–0.383.7 | BN254 Miller loops, final exponentiation, pairing and multi-pairing/product verification |
| 0.384.0–0.384.7 | BLS12-381/BN254 scalar-field polynomial arithmetic, evaluation, interpolation and quotients |
| 0.385.0–0.385.7 | Exact finite-field FFT/IFFT subgroup/coset domains and coefficient/evaluation conversion |
| 0.386.0–0.386.7 | Explicit GF(256)/GF(65536) Reed–Solomon encoding, parity verification/update and erasure reconstruction |
| 0.387.0–0.387.7 | Prime-field evaluation-code extension, indexed recovery and consistency checking |
| 0.388.0–0.388.8 | Variable-width public modular arithmetic/exponentiation over arbitrary odd/even nonzero moduli |
| 0.389.0–0.389.7 | BLAKE2b/s compression APIs and explicitly bounded configurable-round BLAKE2b |
| 0.390.0–0.390.7 | Original Keccak-224/256/384/512 ordinary/hardened operational hardware/SIMD and downstream use |
| 0.391.0–0.391.7 | BLS12-381 complete consumer group/MSM/pairing and accepted hash-to-curve interfaces |
| 0.470.0–0.470.8 | Standalone package-external cryptographic API and final native acceptance, without downstream migration work |

Each chain has authority/API admission, individually scoped implementation
steps, secret/error lifecycle closure, a frozen portable public fixture,
hardware/single-state execution, SIMD/bounded scheduling, then final evidence.
Every admitted parameter and both operation directions must work; no placeholder
may be marked Fully implemented. If an implementation step grows beyond a
reviewable unit, insert another numbered step before it, not hidden follow-up
work after acceptance. Merely adding a trait is not completing its algorithm.

The original SHA/AES/HMAC/HKDF/PBKDF2/scrypt/RIPEMD milestones remain in place.
Original Keccak is still implemented at 0.352.x before its execution backfill.
Existing 0.371.x secp256k1, 0.376.x BLS arithmetic and 0.377.x hash-to-curve
precede these new consumers. BLS signatures move to 0.447.x; commitments/KZG
move to 0.448.x and explicitly require accepted FFT/polynomial/MSM owners.
Both BLS signatures and KZG gain dedicated hardware and SIMD integration
steps at patches .5/.6 before their final evidence at .7.
The final cryptographic consumer closure at 0.470.x precedes large protocols
starting at 0.471.x. Noise moves to 0.474.x: its complete protocol acceptance
remains there, not a circular prerequisite of the crypto-only closure.

The renumbering preserves stable capability IDs. Original unstarted minors
378–455 move up fourteen; original 456–480 move up fifteen. Final integrated
gates are now 491–495, before the unchanged 1.0 RC/final identities. Public
checkpoints remain explicitly listed on the closing patch of every fifth
minor; no existing tagged release or near-term 0.24.x work is renumbered.

## Error-preserving APIs are mandatory

- The current `eth` Keccak trait's `update` and `finalize` are infallible. Where
  the selected Brynja operation can fail, Brynja must expose a fallible public
  contract and demonstrate correct use in a standalone fixture. Adapting or
  revising an external trait is a downstream decision, not a deliverable here.
  Never hide errors, panic, return an
  all-zero digest, return stale output, or defer an error until after a digest
  has been accepted. Compatibility for a genuinely infallible portable contract
  must be justified separately, not implemented by discarding `Result`.
- Distinguish missing capability before execution from selected-backend failure.
  Prefer may select portable before work when support is absent. Require must
  reject absence. Quarantine, generation mismatch and failure after selecting
  a backend must not silently retry portable or let a partial operation succeed.
- Preserve public failure atomicity and full secret-destination clearing. Model
  streamed outputs that are already released separately; cancellation cannot
  retroactively erase caller copies. Preflight lengths/overlaps/workspace before
  mutation and retain terminal-state behavior across adapter layers.
- Raw BLAKE2 compression inputs are a separately classified public-input API,
  not an escape hatch for hardened hashes. Configurable rounds are not a claim
  of standard digest security. Public variable-time modular/MSM operations may
  not accept secret owners; hardened operations remain fixed-work and sealed.
- Scalar recovery, arithmetic and format policy are distinct. Brynja returns
  typed recovery identifiers and keys; `eth` interprets chain IDs, parity fields,
  low-s fork policy and address hashes. Generic modular arithmetic rejects zero
  modulus; `eth` applies its specified output semantics. No unconditional
  normalization in Brynja may change a consumer's accepted input set.
- First-party choice/equality/selection types need usable public operations,
  constant-time tests and explicit declassification. Do not leak `subtle` types
  through Brynja signatures. Any external API/SemVer transition away from such
  types is outside this roadmap.

## Complete acceleration and cleanup requirements

Inventory dedicated instructions separately from single-state and multi-message
SIMD. SHA/AES hardware, Keccak instruction assistance, field multiply/reduction,
carry-less arithmetic, SIMD butterflies and independent-message batches are
different capabilities; their existence is not interchangeable. Implement
useful available backends rather than adding a feature with no executable path.
No speedup is promised without measurements; no applicable dedicated instruction
is an honest result, not a reason to omit useful SIMD or portable APIs.

Use default-off leaf features, portable defaults, safe hosted CPU/OS-state
detection, exact static target bundles, startup tests and quarantine. Bind
scheduler/hotplug/VM migration assumptions. Test MSRV and current compiler,
full batches and tails, mixed lengths, invalid inputs, aliasing and actual work
counters. Never count skipped/unavailable kernels as accelerated PASS.

Secret execution needs the same complete internal sanitization as portable
execution, including owner-backed schedules/lanes, scratch, staging and output
on success, failure, cancellation, unwind and Drop. Inspect emitted code and
retain limits for compiler-created copies, registers, spills and platform state.
No cleanup duty depends on an optional external sanitization adapter.

Freeze real package-external acceptance before the native sweep. Collect on AMD,
qualifying Intel, AWS Arm and Apple M2 for applicable ISAs; separate correctness,
performance, side-channel observations, independent review and FIPS status.
Use the existing RISC-V experimental/static/QEMU policy and post-1.0 community
native qualification where suitable hardware is unavailable. Missing required
qualification blocks the affected operational claim, not portable support.

## Standalone acceptance and boundaries

At each family closure, run a pinned self-contained public consumer exercising
the complete reusable operation against packaged Brynja, with independent vectors,
fault injection and compiled ownership negatives. Run no_std/feature/dependency
checks and force portable plus each promised supported hardware/SIMD route.
The final 0.470.x fixture uses only Brynja runtime cryptography; external
independent oracles stay dev-only. Verify exact outputs, errors, accepted input
domains and resource limits, not just successful compilation. There is no
requirement to remove code or dependencies from any other repository.

Keep EIP encodings, precompile addresses/gas, fork rules, transactions, address
derivation, RLP/SSZ, blob/cell layouts, trusted network setup selection, wallet
paths and mnemonic/keystore conventions, RLPx, Discovery and libp2p bindings in
`eth` or appropriate optional downstream packages. This change does not add
BIP-32/39/44, ERC-2333/2335, Ethereum protocols or Snappy to Brynja. Reusable
KDF/curve/commitment operations underneath them belong in Brynja. Snappy is a
separate compression choice, not a missing cryptographic primitive.

For KZG, expose checked setup loading/validation and explicit setup trust,
coefficient/evaluation representations, single/multi-point openings and bounded
batch verification, with transcript-bound randomness and no false hiding claim
for plain KZG. Setup validation does not prove that toxic waste was destroyed.
BN254 compatibility must disclose its security limitations and never inherit a
BLS12-381 strength or approval claim. Field-level maps, hash-to-curve suites and
protocol-specific wire encodings remain distinct operations.

## Primary authority starting points

These are source-admission starting points, not a claim of already pinned or
implemented profiles. Freeze exact revisions, errata, normative dependencies
and all required operation/parameter profiles before implementation.

- [SEC 1 v2](https://www.secg.org/sec1-v2.pdf): ECDSA recovery, ECDH, X9.63 KDF and ECIES.
- [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html): BLAKE2 hashing and compression.
- [EIP-152](https://eips.ethereum.org/EIPS/eip-152): configurable compression conformance; framing and gas stay downstream.
- [EIP-196](https://eips.ethereum.org/EIPS/eip-196) and [EIP-197](https://eips.ethereum.org/EIPS/eip-197): exact alt_bn128 interoperability identity, alongside primary arithmetic/pairing authorities.
- [EIP-198](https://eips.ethereum.org/EIPS/eip-198): downstream public modular-exponentiation corner cases, not the reusable API definition.
- [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html): exact hash-to-field and hash-to-curve suites.
- [RFC 5510](https://www.rfc-editor.org/rfc/rfc5510.html): explicit Reed–Solomon field/code profiles; prime-field evaluation coding needs its own mathematical contract.
- [Keccak specifications](https://keccak.team/keccak_specs_summary.html): original padding and permutation identities, distinct from FIPS 202 digest domains.
