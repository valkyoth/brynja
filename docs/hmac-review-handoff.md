# Modern HMAC review handoff

This describes the v0.25.0 development candidate, **not an approved native
receipt, release-gate PASS or publication authorization**. The supplied
two-tester review covers `v0.24.55..66e585f8`; the subsequent Claude retest of
`64bf5718` confirms the hosted portable-policy and pre-entry worker fixes without
new security findings. Fractional SHA-512/t remains an accepted, ungated
interoperability limitation. The [pentest ledger](../security/pentest/v0.25.0.md)
records the PASS disposition, both new informational notes and their exact
scope. The tester ran Linux SHA-NI, not macOS; author-operated Mac results
remain separate. No hash kernel or cleanup primitive is changed.

## Implemented scope

The [leaf](../crates/brynja-mac-hmac/README.md) implements ten named SHA-2/SHA-3
identities and all 383 admitted general SHA-512/t widths (128..511 except 384).
Keys are bytes; streaming prefixes are bytes; final messages can use canonical
typed SHA-2/FIPS 202 bits. Full tags preserve exact digest bits. Truncation is
an explicit, preselected whole-byte policy of at least 128 bits. There is no
fractional-key API or arbitrary bit-truncation policy. Empty keys are supported
mathematically, not recommended as secure keys.

Fractional `Sha512T<T>` HMAC is an explicit project-defined interoperability
profile: its outer hash consumes exactly T inner-digest bits, not the rounded
byte length. The distinct type is not a standardized-HMAC claim. Peers must
agree on that convention; prefer the named identities for standard protocols.

Portable, static and runtime owners have consuming finalization and separate
public tags, clearing secret tags and explicit verification decisions. Long-key
normalization, inner/outer ownership, failed-output behavior and retained
authority are exercised separately. `Prefer` can select portable before a key
is processed; a selected backend's failure never causes implicit fallback.

Hosted complete-request sessions use existing protected Linux or resident
Apple Silicon resources. The [strict facade](../crates/brynja-strict/README.md)
exports only the protected variant and rejects unsupported platforms. Mac
resident sessions are **not** strict sessions and do **not** exclude dumps.
No Windows enclave HMAC, legacy HMAC, independent-message SIMD HMAC or
multi-request worker pool is implemented or advertised by this milestone.

## Coverage, with distinct meanings

| Area | Author evidence and remaining limit |
| --- | --- |
| Functional construction | Seven RFC 4231 cases; 1,100 byte, 1,040 final-bit and 6,128 general-width differential cases. The separate Python models are author oracles, not an independent cryptographic review. |
| Ownership and failures | Live adapter-output checks, synthetic hash errors/unwind, diagnostic-checked negative consumers and successfully compiled behavioral mutants. Invalid public destinations remain unchanged; secret destinations clear. No observation of freed stack memory is used as proof. |
| Portable/static/runtime compiler callers | Bounded constructor, retained-state, input/suffix, consuming output, comparison and error/unwind graphs under Rust 1.90.0/1.99.1. See the precise [compiler contract](hmac-engine-cleanup.md). |
| Hosted compiler callers | Twelve compiler/target/panic configurations; 48 consumer and 48 output-loan probes, typed constructors/callees, worker captures, joined transactions and Result forwarding. Arm Linux/Apple emitted-code inspection is not native execution. See [boundaries and premises](hmac-execution-cleanup.md). |
| AMD Linux native | Portable, SHA-NI SHA-224/256, AVX2 Keccak, protected scalar/compiled paths, extracted archives and strict-facade consumers. No dedicated x86 SHA-512 silicon claim. |
| Arm Linux native | Neoverse-V2: all three SHA-256/SHA-512/Keccak routes, twelve leaf compiler/profile cases, hosted selection, protected scalar/compiled workers, strict facade and extracted-adapter handoffs. Source-archive and all 21 command/log records reconciled locally. |
| Apple Silicon native | Static and generic-build runtime SHA-256/SHA-512/Keccak, resident scalar/compiled workers and extracted consumers. Strict facade tests prove rejection, not strict execution. |
| Dedicated x86 SHA-512 | Explicit SDE Arrow Lake execution of six HMAC identities through leaf and protected sessions, debug/release on Rust 1.90.0/1.99.1. Eight test executions pass. This is emulation, not native instruction, resource-isolation or timing qualification. |
| Timing | Seventeen retained Linux/Apple observations, 768 ordered campaigns, 512 measured pairs/campaign, zero alarms at the documented threshold. Raw samples/statistics and fixture/harness hashes were rechecked; the campaigns were not rerun for documentation changes. This is not proof of constant time or a cache/branch analysis. |
| Other platforms | Cross-compilation establishes only build compatibility. No Windows HMAC execution record or native RISC-V qualification is claimed. |

Linux Arm protected workers were executed separately: Mac execution and
cross-compilation do not substitute for them. Current results are inventoried in the
[author observation index](../security/hmac/development-observations.json).
That index records local artifact digests and provenance, not authenticated
runner attestations or independently approved evidence. Raw files remain in the
local release-report archive and outside crates.io packages.

The [family development review](../security/hmac/family-development-review.json)
records each hardening/acceleration dimension using the existing manual review
tool. It is an author disposition, not independent sign-off. The modern package
checks pass; the broader modern/legacy publication-footprint audit remains the
already planned v0.25.2 follow-up, so the family report remains
`FOLLOW_UP_REQUIRED` until that checkpoint is completed.

## Why completed checks are not being restarted

The seventeen saved timing observations and earlier native/compiler results
remain historical records for their recorded sources. The remediation does
not change hash kernels or HMAC mathematics, but it does change the hosted
selection API, compiled-session pre-entry control flow, and the timing consumer's
selection match. Those affected bytes must not be represented as identical to
the original captures. Focused native recovery, fallback-policy, lifecycle,
package and emitted-compiler regressions are run for the remediation; this is
not a freshly completed timing campaign or full release sweep.

This is an author reconciliation, not a replacement for the existing planner's
receipt validation. A report, a hash beside a log, or a passing source-policy
check cannot by itself authorize reuse or prove that a test executed. Final
release checks still evaluate the actual changed dependencies and verifier
inputs; new HMAC work does not imply recollecting unrelated unchanged hashes.

## Review boundaries and accepted limits

- Check key normalization and exact inner-digest bit length, message/tag bounds,
  keyed-state ownership, callback errors, revocation/quarantine and transactional
  outputs. The composed owner is two retained hash states, not merely `Scratch`.
- Source branches/addresses in the framing layer depend on public algorithms,
  lengths, policies, resource status and cancellation. Verification accumulates
  all equal-length tag-byte differences before declassification; different
  public lengths reject. Public message/key lengths and routing are observable.
  This source assessment and the paired screen do not prove microarchitectural
  noninterference or bound every leak; the supplied remediation retest does not
  certify those properties.
- Compiler checks establish the specifically documented owned-storage and
  clear-dispatch relationships. They retain typed-callee and non-panicking
  cleanup premises; they do not establish arbitrary compiler-copy or full-frame
  erasure. Previously reviewed kernels remain separately scoped.
- Caller buffers and copies, caller-frame registers/spills, signal/OS context,
  fatal aborts, hibernation and privileged snapshots remain outside the guarantee.
  `panic=abort` cannot run Drop cleanup. Do not reopen these accepted limits as
  if the API promised their erasure; do report new violations of the stated scope.
- Optional ISA support requires the complete CPU/OS/deployment authority.
  Startup KATs and revalidation do not lock scheduling or prove VM migration
  safety. Unavailable instructions must not silently select another backend.
- Existing hash acceleration is reused for a **single** HMAC state. SHA-NI and
  Arm SHA instructions and the AVX2/Arm Keccak routes do not imply multi-message
  HMAC batching. Hosted workers provide protected execution, not a measured
  throughput speedup; no crossover or multicore scaling claim is made.

## Reproduction and next steps

The [inventory](hmac-development-inventory.md) links each existing check, and
the [timing guide](hmac-timing-observations.md) documents populations and limits.
The dedicated x86 composition check is explicitly opt-in and uses the owner's
licensed SDE installation; it never downloads or licenses the tool itself:

```sh
python3 scripts/hmac/check-hmac-x86-sha512.py --sde /path/to/sde64 --output target/hmac-sha512-sde.json
python3 scripts/hmac/test-hmac-x86-sha512.py
```

The supplied reviews, focused Claude retest and author checks are recorded
separately. Run the affected final release checks, then obtain
exact-candidate GitHub results and explicit tag
authorization. The v0.25.1 legacy implementation and v0.25.2 family/package
publication checkpoint retain their existing scope. No tag or publication has
occurred for this candidate.
