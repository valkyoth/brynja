# Opt-in acceleration closure inventory

Status: author inventory review for v0.24.55; final verification and exceptional
retest pending. This inventory grants no execution authority or qualification.

The [original usability audit](ACCELERATION_USABILITY_AUDIT.md) and
[v0.24.30 contract](../security/acceleration-availability.toml) are historical
baselines. Their candidate `is_admitted() == false` flags remain intentional;
they do not describe the separate callable execution/session APIs added since.
Do not flip those flags to report completion of these different APIs.

“Implemented opt-in” below means source and a normal public API exist under
their documented target/profile contract. It does not mean every host supports
that API, that a native timing/cleanup claim has been independently qualified,
or that the pending consolidation passed. Every row retains **no independent
cryptographic verification and no FIPS module validation**.

## Original eleven kernel rows

| Historical inventory ID | Current route and disposition |
| --- | --- |
| `sha256-x86` | Implemented opt-in SHA-NI ordinary and distinct hardened SHA-224/256 execution; static complete-target contract. |
| `sha256-arm` | Implemented opt-in Arm SHA2 ordinary/hardened SHA-224/256 execution; static or qualifying hosted authority. |
| `sha256-rv64` | Hardware-dependent owner deferral. Candidate/QEMU coverage is not operational or native qualification; no placeholder milestone required. |
| `sha512-arm` | Implemented opt-in Arm SHA512 ordinary/hardened SHA-384/512, named truncations and general-t execution; exact instruction bundle required. |
| `sha512-rv64` | Same hardware-dependent deferral as `sha256-rv64`; no hardened RV64 admission. |
| `keccak-x86` | Implemented opt-in AVX2 single-state Keccak session reused by SHA-3/SHAKE/cSHAKE and derived constructions; static deployment contract. |
| `keccak-arm` | Implemented opt-in Arm Keccak session for the same constructions; static or qualifying hosted authority. |
| `sha1-x86` | Implemented opt-in ordinary/hardened SHA-NI in isolated legacy packages, not the modern facade. Collision weakness unchanged. |
| `sha1-arm` | Implemented opt-in ordinary/hardened Arm SHA1 in isolated legacy packages. Collision weakness unchanged. |
| `md5-x86` | Implemented opt-in eight-message AVX2 with separate ordinary-public and hardened ownership APIs; isolated legacy packages. |
| `md5-arm` | Implemented opt-in four-message NEON with separate ordinary-public and hardened ownership APIs; isolated legacy packages. |

Source/API anchors: [static kernel identities](../crates/brynja-crypto-cpu/src/static_execution/kernel.rs),
[CPU exports](../crates/brynja-crypto-cpu/src/lib.rs),
[legacy SHA-1](../crates/brynja-legacy-sha1/README.md),
[legacy MD5](../crates/brynja-legacy-md5/README.md).
The original candidate counters are not a population count of these execution
APIs or of the later multi-buffer kernels.

## Later kernel and workload additions

| Workload | Current route and disposition |
| --- | --- |
| Dedicated x86 SHA512 | Implemented experimental opt-in `X86Sha512`, ordinary and hardened. Requires `sha512,avx2,avx` plus OS vector state; SDE/compiler observations, not dedicated-silicon qualification. SHA-NI or AVX-512 alone is insufficient. |
| Independent SHA-224/256 messages | Implemented opt-in eight-lane AVX2 / four-lane NEON; distinct public-only and clearing-owner APIs. |
| Independent SHA-512-family messages | Implemented opt-in four-lane AVX2 / two-lane NEON; distinct public-only and clearing-owner APIs. |
| Independent Keccak states | Implemented opt-in four-state AVX2 / two-state NEON; used by separate SHA-3/SHAKE/cSHAKE batch APIs and ParallelHash leaf grouping. |
| ParallelHash CPU parallelism | Implemented opt-in bounded OS workers, independently selected root/leaf acceleration and SIMD leaf groups. Threading alone is not SIMD. |
| Other vector widths / AVX-512 / RVV | Not implemented or claimed. CPU feature availability alone is not measured benefit or cleanup qualification. Retain the workload-specific measurement requirement from the original audit; no promised pre-HMAC route is represented by a stub. |

See [SHA-256 batches](sha256-batch-execution.md),
[SHA-512 batches](sha512-batch-execution.md),
[Keccak batches](keccak-batch-execution.md),
[dedicated SHA512](x86-sha512-execution.md) and
[threaded ParallelHash](../crates/brynja-hash-parallel-std/README.md).
Qualification-pending warnings remain in the READMEs until the corresponding
evidence is actually reconciled; this table does not erase them.

## All nine construction families

| Historical family | Public integration now present |
| --- | --- |
| `sha256` | SHA-224/256 ordinary and hardened `execution` APIs, explicit batch profiles and typed outputs. |
| `sha512` | SHA-384/512, named /224 and /256 plus all 510 valid general-t parameters; ordinary/hardened execution and family batching. |
| `sponge` | Four SHA-3 identities plus SHAKE128/256, byte/bit input and XOF output, ordinary/hardened execution and batching. |
| `cshake` | cSHAKE128/256 framing/customization and XOF output, ordinary/hardened execution and batching. |
| `kmac` | Four KMAC/KMACXOF identities, hardened accelerated execution, verification and scoped/setup ownership. No ordinary public-only Keccak detour for keys. |
| `tuple` | Four TupleHash/TupleHashXOF identities, accelerated exact-item writers/readers and scoped ownership. |
| `parallel` | Four ParallelHash/ParallelHashXOF identities, accelerated root/leaves, scheduling/streaming and separate std worker/batch APIs. |
| `sha1` | Isolated legacy ordinary/hardened byte/bit execution and explicit hosted adapter. |
| `md5` | Isolated legacy ordinary/hardened batch execution and explicit hosted adapter. |

The modern [facade exports](../crates/brynja-crypto/src/lib.rs) retain curated
default-off modules rather than exporting the historical candidate APIs as
the only path. The separate [strict facade](../crates/brynja-strict/README.md)
does not export the ordinary or legacy facade. Direct leaf consumers can still
choose weaker profiles; application dependency policy remains the caller's job.
Test-only KMAC conformance types remain outside the curated production surface.

## Dispatch and platform dispositions

- Generic portable constructors remain portable. Cargo features expose APIs;
  they do not prove CPU support or turn ordinary storage into secret storage.
- Static constructors require their complete build-wide feature contract and
  a compatible CPU/OS deployment for the authority's lifetime. No arbitrary
  safe boolean is accepted as proof.
- Generic x86 hosted raw execution still rejects the missing migration guarantee
  in [the platform boundary](../crates/brynja-crypto-cpu-std/src/execution/platform.rs).
  That is not absence of the static x86 implementation. Hosted AVX2 batching
  uses the explicit compiled-target contract, not generic CPUID as a migration
  guarantee; see [the batch boundary](../crates/brynja-crypto-cpu-std/src/sha512_batch/platform.rs).
- Qualifying AArch64 hosted detection relies on the documented OS feature ABI;
  cached detection is not a live revocation monitor. Unsupported/mismatched
  routes reject or report the documented initial portable fallback. Authority
  loss after admission remains terminal, not a hidden midstream fallback.
- GNU/Linux strict profiles use protected mappings and joined worker stacks on
  their supported x86-64/little-endian AArch64 targets. Original caller inputs,
  copies, privileged snapshots and fatal interruptions remain outside scope.
- Apple Silicon exposes a separate resident/clearing profile, **not** strict
  dump exclusion. Its scalar/Arm/NEON consumers have project-operated native
  observations. No Intel Mac support or native claim is inferred.
- Windows x64 has a separate VBS enclave API, with development-image evidence
  retained. Production signing/admission remains the consumer's responsibility;
  this is not production-signed or whole-image-erasure qualification. Windows
  ARM64 and Linux-style Windows host-slice strict sessions remain unsupported.

## Verification and remaining closure work

The [v0.24.54 record](native-evidence-v0.24.54.md) distinguishes forty
source-bound Linux/Apple captures, twelve consumer campaigns and retained
historical MD5/Windows observations. Snapshot integrity must still be validated
on the current candidate with the external approval digest; it is not runner
attestation or a fresh execution under a newer compiler.

The family-development checklist still applies: public API, portable behavior,
secret ownership, kernel registers, caller transfers, lifecycle, side channels,
x86/Arm/other targets, single-state SIMD, batch SIMD, threading, dispatch,
packaging, platform evidence and performance. The existing
[family review tool](../scripts/release/check-family-completeness.py) records
these dimensions; it is not a substitute for tests or independent review.
Native speedups and crossover decisions remain workload-specific. No blanket
“SIMD is faster” or complete caller/OS erasure claim is introduced.

Before closure, finish the exceptional metadata-proof retest, run frozen public
acceptance and the deferred all-family repository/compiler/Miri/Kani/ASan
checkpoint, reconcile every failed or unavailable task, and update the README
status inventory without promoting pending qualification. No new cryptographic
implementation gap was identified in this source/API inventory pass; that is
not a clean independent pentest or a completed verification sweep.

Future families, starting with HMAC at v0.25.0, register their own affected
commands and dependency relationships. Reuse unchanged hash/kernel observations;
rerun the actual changed implementation and affected consumers. Dedicated ISA,
SIMD and protected ownership remain explicit review dimensions rather than
automatic all-family recollection or a demand for unsupported hardware.
