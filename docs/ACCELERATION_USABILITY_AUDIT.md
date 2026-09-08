# Opt-In Acceleration Usability Audit

Status: planned remediation; runtime behavior is unchanged by this audit.
Basis: v0.24.29 candidate `236b0d12`, reviewed 2026-09-08.

## Decision

Brynja should offer usable, explicitly selected first-party Rust acceleration.
Project tests and reviewed project-owned evidence establish its operational
release status. Named independent cryptographic review and FIPS validation are
separate claims, not prerequisites for ordinary acceleration. They remain
required for any claim specifically promising such review or validation.

This does **not** make a Cargo feature proof of CPU support, excuse incorrect
code, waive secret-state cleanup, or permit a failed KAT. The old blanket
candidate lock remains in the implementation until the numbered replacements
below pass their tests. This document does not activate a backend.

## Current public capability audit

“Blocked” means ordinary downstream builds cannot select instruction execution,
even where tests can run the kernel with repository-only evidence settings.
These are availability gaps, not missing mathematical hash algorithms.

| Family / owning packages | Existing optimization | Downstream gap | Planned closure |
| --- | --- | --- | --- |
| SHA-224/256 / `brynja-hash-sha2`, `brynja-crypto-cpu` | x86 SHA, AArch64 SHA2, RV64 Zknh | Static/hosted routes blocked; hardened states portable | .33–.34, .50 |
| SHA-384/512, named /224 and /256, general SHA-512/t / same packages | AArch64 SHA512, RV64 Zknh | Static routes blocked; hosted SHA512 only reports/falls back; general-t hosted API incomplete | .33–.34, .49–.50 |
| SHA-3/SHAKE / `brynja-hash-sha3` | Isolated AVX2 and Arm SHA3 Keccak kernels | No public sponge integration; hardened states portable | .35, .37 |
| cSHAKE / `brynja-hash-sha3` | Same possible Keccak reuse | Ordinary and hardened public integration missing | .36–.37 |
| KMAC/KMACXOF / `brynja-mac-kmac` | Hardened cSHAKE reuse | Keyed accelerated owner and selection missing | .38 |
| TupleHash/TupleHashXOF / `brynja-hash-tuple` | Hardened cSHAKE reuse | Item-writer and reader acceleration missing | .39 |
| ParallelHash/ParallelHashXOF / `brynja-hash-parallel`, `brynja-hash-parallel-std` | Caller scheduling and bounded std threads work | Threads are not SIMD; accelerated workers/root and SIMD leaf grouping missing | .40, .47–.48 |
| SHA-1 / `brynja-legacy-sha1`, `brynja-legacy-sha1-std` | x86 SHA and AArch64 SHA1 candidates | Ordinary routes blocked, hosted selection incomplete, hardened portable | .41–.42 |
| MD5 / `brynja-legacy-md5`, `brynja-legacy-md5-std` | AVX2 eight-message / NEON four-message batches | SIMD blocked; hosted selector always portable; hardened batch portable | .43–.44 |
| Independent-message SHA-2 and sponge batches | Not implemented | Distinct from single-message instructions and ParallelHash tree hashing | .45–.48 |
| Constant-time/clearing foundations, bounded ASN.1/DER and record framing | Portable implementation | No blanket need for SIMD; optimization must preserve complete clearing, bounds and fixed-work contracts | Per-operation disposition at .30 and future-family rule |
| TLS/DTLS/QUIC/protocol placeholders, platform/provider contracts | No usable complete protocol engine | Not candidates for fabricated throughput or acceleration support claims | Reuse completed primitives in their existing future milestones |

All patch references in this audit mean **v0.24.x**, not published crate
versions. The precise scopes and prerequisites are in
[RELEASE_PLAN.md](RELEASE_PLAN.md) and
[the schedule register](../requirements/roadmap-schedule.json).

## Selection and security contract

- Default constructors and default feature graphs remain portable.
- Opt-in no_std features expose static, target-specialized execution; the
  executable platform must satisfy the complete target feature bundle.
- Separate opt-in hosted crates provide safe runtime detection where platform
  guarantees suffice. Unknown platforms retain portable support.
- `Portable`, `Prefer`, and `Require` are semantic modes, not final API spellings.
  Prefer reports fallback; Require returns a typed error when the requested
  route is unavailable or unhealthy. No silent downgrade after partial output.
- Capabilities must describe CPU instructions **and** required operating state.
  Thread affinity, scheduler and VM assumptions are explicit. A non-Send
  session does not prevent OS migration. No arbitrary safe boolean attestation.
- Secret-bearing APIs use sealed hardened owners. Every source-owned schedule,
  lane, buffer and staging region is destroyed through Brynja's reviewed
  clearing primitive or the admitted sanitization boundary where applicable.
  Features cannot disable cleanup. Compiler copies, registers, spills, caches,
  aborts and caller copies remain bounded residuals, not total-erasure claims.
- Per-operation reports distinguish dedicated instructions, single-state SIMD,
  independent-message SIMD, scalar tails and host threading. No promise that
  every algorithm benefits from both hardware instructions and SIMD.
- Operational readiness, experimental/emulated status, native measurement,
  independent review and FIPS validation are separate fields. No field
  automatically promotes another. A validated-module path remains bound to its
  actual certificate, implementation and operational environment.

## Missing ISA and batching opportunities

Dedicated x86 SHA-512 is a real missing kernel, not an absence of instructions
in the architecture. Rust documents its SHA-512 round intrinsic as stable since
1.89.0, with `sha512` and `avx` requirements; actual compilation and OS-state
checks across Brynja's supported line remain required.
[Rust intrinsic documentation](https://doc.rust-lang.org/core/arch/x86_64/fn._mm256_sha512rnds2_epi64.html).

SHA-2 multi-buffer and Keccak independent-state SIMD are additional workloads,
not faster replacements for every short one-shot hash. SSE2/SSE4 fallbacks,
AVX-512, alternative vector widths and RVV require measured justification and exact feature
contracts before adding kernels. Absence of benefit can be a documented
disposition; absence of implementation cannot be called support.

The available RISC-V machine lacks the relevant SHA crypto instructions.
Explicit RV64 Zknh target-specialized experimental use is planned with QEMU
correctness evidence, while native qualification and community assistance may
remain post-1.0. Generic RV64 does not imply Zknh or RVV. No untested native
timing or migration guarantee is inferred from emulation.

Executing unsupported target-feature code can be undefined behavior in Rust.
Linux's Arm64 feature ABI is designed to expose a system-safe feature set,
which can be used when its exact guarantee applies; this is more meaningful
than inventing a mandatory independent attestation service for ordinary users.
Other OS and VM guarantees must be checked individually.
[Rust target-feature rules](https://doc.rust-lang.org/reference/attributes/codegen.html#the-target_feature-attribute),
[Linux Arm64 feature ABI](https://www.kernel.org/doc/html/latest/arch/arm64/cpu-feature-registers.html),
[Linux Arm64 HWCAP](https://www.kernel.org/doc/html/latest/arch/arm64/elf_hwcaps.html).

## Future-family audit and enforcement

The following dispositions apply to every later implementation, including
catalogue/expansion families, not only the current hashes:

| Future scope | Required optimization/API review |
| --- | --- |
| HMAC, HKDF, KDFs, password hashing, prehash signatures | Reuse hardened accelerated hashes; preserve domain, truncation, memory/work bounds and output secrecy; no ordinary-state detour |
| AES/modes/GHASH/AEAD, CMAC and legacy block ciphers | Review dedicated ISA, carry-less multiply and independent-block SIMD; modes differ in parallelizability; preserve nonce rules, authentication-before-release and secret schedules |
| ChaCha/Salsa and other stream ciphers; Poly1305/MACs | Review vector blocks, multi-buffer work and arithmetic, exact counters/overlap/tails and constant-time verification |
| BLAKE and all other modern/legacy/research hashes and XOFs | Review single-state versus independent-state SIMD and tree APIs; preserve each standard's exact output and streaming semantics |
| CRC/checksum/noncryptographic hashing and codecs | Review applicable CRC/carry-less instructions, vector scanning and chunk combination without changing polynomial/encoding identity or making cryptographic claims |
| RSA, finite fields, ECC, signatures and PQC | Review limb multiply/carry, vector polynomial/NTT and batch verification opportunities; protect secrets, validation, batch soundness and algorithm-specific security assumptions |
| Formats, PKI and complete protocols | Reuse upstream selection and report it accurately; do not duplicate kernels; preserve parser bounds, handshake policy, cancellation and legacy/FIPS separation |

At family design, record each relevant scalar/dedicated/SIMD/batch/hosted and
ordinary/hardened profile with exact parameters and APIs. Existing CPU rows
remain useful; the later cross-backend gate is a regression/composition gate,
not the first permission for consumers to use earlier completed acceleration.
If an applicable optimization or integration does not fit its existing row,
insert concrete review-sized patch milestones **before** that family's final
acceptance and executable consumers. Do not treat “every admitted route” as
satisfied by skipping every implemented promised backend forever.

Older scope wording such as “independently admitted acceleration” refers to
separate readiness decisions for individual backends under this amended rule,
not a mandatory third-party cryptographic review. Immutable release scopes and
historical observations are retained; they do not override the new availability
contract for future work.

## Evidence and release flow

The backfill uses v0.24.30–v0.24.54: contracts and safe selection first, public
family integration and missing kernels next, packaged acceptance at .52,
native evidence at .53, final closure at .54 before HMAC. No new runtime route
is enabled by this planning update, and .29 still needs its own retest/evidence.

Freeze and run real public examples before the final native sweep. A changed
kernel, dispatch path, dependency, compiler or cleanup invalidates affected
evidence. Project-owned captures are reproducible observations, not independent
cryptographic audits. Exact source/binary/command/result binding is required;
a new remote-attestation or PKI service is not a release prerequisite.

Use native AMD, genuinely qualifying Intel, AWS Arm and Apple M2 where available.
Record missing ISA, experimental routes and QEMU separately. Keep lengthy
checks local/headless and impact-scoped at development tags; full gates remain
mandatory at public checkpoints. Unsafe, secret and execution-authority changes
retain exceptional pentests. Commit the report and gate result, wait for green
GitHub/CodeQL, then tag only on owner approval. No new publishing cadence is
introduced: the next scheduled crates.io checkpoint remains **v0.25.2**.
