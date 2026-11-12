# AES acceleration range retest dispositions — 2026-11-12

The owner supplied Daybreak and Claude reviews of `v0.27.2..fd651e90`.
The [original report](reviews/aes-acceleration-range-2026-11-12.txt) is preserved
with SHA-256 `6408fdd3d2c5414d7f4168d4a9586168769081012064a69ecf780a92118c2917`.
Some location/remediation text in the supplied Claude report is truncated;
the original is retained as received. This document supersedes the earlier
working-tree review's pending candidate/owner-disposition statements, not its
historical results. Neither review demonstrated an AES arithmetic or
memory-safety defect. This is a remediation record, not independent approval.

## Daybreak 1 / Claude M-3 — operational fault detection: accepted repeat

Startup known-answer tests and software error guards do not detect silent
computational faults in every later block. This was already explicit and
remains a deployment restriction for hostile physical/fault environments.
The optional fault-detecting profile is assigned to **v0.27.7**, with a reviewed
bounded model, independently structured redundancy, schedule integrity,
withheld output and terminal quarantine. No HSM is made mandatory.

Do not add the suggested same-schedule encrypt/decrypt round trip as a claim
of independent fault protection: common-mode corruption or a bypassed
comparison can defeat it. The more demanding Daybreak sketch also needs a
real independent implementation and reviewed protection model, not just an
extra trait or error variant. These are not missing fixes to the current
single-block API's stated contract, nor waived faults in a claimed
fault-resistant implementation.

## Claude M-1 / M-2 — platform side channels: clarify, do not overclaim

The raw-kernel-only DIT boundary repeats an accepted limitation; widening it
through a new public closure API is not adopted in this patch. The specific
Apple DMP and Intel DOITM documentation gaps are addressed in
[platform timing guidance](aes-platform-side-channels.md) and the low-level
module documentation, using primary sources.

Do not infer that an arbitrary pointer-like load proves AES key extraction,
that DIT suppresses every Apple DMP, or that DOITM is required on every x86
processor. The report supplies no brynja exploitation experiment. Conversely,
the absence of an exploit here is not proof of resistance. The named platform
mechanisms remain real considerations for deployment qualification. The
owner's timing deferral does not authorize a whole-API constant-time claim.

## Claude L-1 — successful hosted construction of an unusable owner: fixed

Low-level construction deliberately preserves a quarantined owner so startup
failure is observable. That contract remains unchanged. The higher-level
hosted selector now requires a successful `owner.session()` before returning
`Route::Accelerated`. A returned unhealthy owner becomes a kernel error, with
no portable fallback in either Prefer or Require mode. Startup enable/KAT
failure may still be summarized as `Quarantined`; the change does not invent
an unavailable original failure cause. Reports remain observations, and later
quarantine still invalidates previously returned selections.

The existing selection regression now supplies **Ok(quarantined owner)**,
not merely an injected constructor Err, and asserts rejection under both
selection modes after `dit_mode()` mapping. These raw owners are constructed
with `IfAvailable` and then quarantined; this is not an end-to-end injection
of a `Require` startup DIT readback failure. It also checks healthy-owner
acceptance. The constructed-owner branches run with native static AES flags
or real hosted ARM admission; baseline x86 still reports unavailability.
Explicit `DitUnavailable` errors are also checked for no fallback.

## Claude L-2 — raw schedule lifecycle: accepted boundary, clearer warning

The low-level CPU module is already opt-in through `aes-static-execution`
(also enabled by `aes-runtime-execution`). Its Session operations deliberately
accept caller-owned buffers. Another feature label or hiding the methods
would not enforce clearing. A prominent Secret handling section now warns
that schedules are key-equivalent and are not cleared on success, error,
quarantine or drop; it directs ordinary callers to the clearing key owners.
No feature graph or public method is removed.

## Claude I-1 — post-transform health recheck: hardened

Expansion and block transformation now use the same `Operation::complete`
path: recheck session health/generation/admission, then mark completion.
Failure leaves Drop responsible for terminal quarantine. A regression injects
Testing, Quarantined and stale-generation states between entry and completion
and verifies rejection, quarantine and rejection of subsequent operations.
Existing all-width success tests exercise completion without quarantine.

This is defensive consistency, not a fix for a demonstrated concurrent
revocation race: authorities/sessions are thread-bound and these operations
do not call user callbacks. Raw caller buffers retain their documented cleanup
obligation if a post-execution error occurs; clearing owners withhold public
output and clear admitted secret storage on failure.

## Claude I-2 — informational scope and performance observations

- Single-block APIs, no VAES/multi-block pipeline and per-block inverse-key
  transformation are current performance boundaries, not AES correctness
  omissions. No unmeasured speedup factor or parallel mode implementation is
  promised by this retest.
- Hosted x86 unavailability is deliberate: current-core detection alone is
  not the required lifetime migration guarantee. Static acceleration remains
  explicit. A future supported hosted boundary requires its own review.
- An operation failure quarantines its authority and sibling sessions/keys,
  not unrelated authorities. Availability costs are intentional fail-closed
  behavior; no automatic retry or recovery is introduced.

## Validation and handoff

The following passed on the changed working tree:

- 995 verification-registry/tooling regression tests. Existing exact runner
  populations remain correct because the new cases extend existing Rust tests.
- Both Rust 1.90.0 and 1.99.1: static runners in baseline, native x86 AES and
  AArch64 QEMU configurations (7 baseline / 26 accelerated tests per run).
- Both endpoints: hosted runners on baseline x86 and AArch64 QEMU, including
  debug/release all-width known-answer consumers and six selection tests.
- Both endpoints: DIT scope/restoration and absent-DIT hosted tests under QEMU
  (11 tests each, with the required enabled/unsupported-CPU markers).
- Both endpoints: all-target/all-feature tests for `brynja-crypto`,
  `brynja-crypto-cpu` and `brynja-crypto-cpu-std`, with native x86 AES flags.
  Existing explicitly ignored hardware/oracle campaigns were not counted as
  executed; this is not a claim to run every optional campaign.
- Current-compiler Clippy for those three crates, all targets/features,
  `--no-deps -D warnings -A clippy::chunks_exact_to_as_chunks`. The last flag
  retains the already documented unrelated style-lint exception.
- Formatting, release-plan consistency and diff-integrity checks.

No new timing samples were collected, and no old linked/timing binary identity
is silently transferred to the modified source. QEMU is functional coverage,
not fresh native ARM qualification. No verification result is manually promoted
to a current pass. The existing scoped final-check, GitHub and explicit
tag-authorization workflow is unchanged. This follow-up changes lifecycle/API
code and should receive a bounded delta retest, not a repeat of the accepted
physical/timing findings or of unrelated hours-long hash campaigns.

## Owner-supplied focused retests and finalization

On 2026-11-12 the owner supplied two focused retests covering the follow-up
commits `fa1f56f5` and `2bb2177e`. Both confirm the hosted startup rejection and
post-operation authority checks and report no new serious coding flaw. The
first explicitly accepts the documented/deferred dispositions. The second
retains a High physical-fault risk under a military/physical threat model and
a Medium platform-side-channel qualification restriction for high-assurance
multi-tenant deployment. These are not newly fixed or reclassified findings:
the crate still does not claim those deployment guarantees. The owner asked
to proceed with final checks, commit and GitHub handoff on that basis.

The first retest reports native x86 AES tests and baseline hosted tests, with
no ARM hardware available. The second reports x86 tests, 2,078 NIST cases,
624 startup schedule-corruption cases, ARM Linux/macOS compile checks,
995 registry tests, 42 scoped-release tests, formatting, diff checks and a
cached advisory scan. These are reviewer-reported results, not new native ARM
observations collected during this finalization.

The small coverage-description overstatement above is corrected. A separate
strict Clippy invocation on the CPU crate exposes older hash style lints;
the unchanged finite gate's crypto-lint check targets the composition and
legacy HKDF crates with `--no-deps`, not that CPU feature configuration. No
lint suppression or gate change is introduced by this finalization.

The v0.27.3 candidate metadata, consumer pins, generated SBOM and this record
are an owner-authorized finalization delta, not a claim that the independent
reviewers examined changes made after `2bb2177e`. No production Rust logic,
dependency selection or timing evidence changes in that delta. Exact-candidate
final checks and GitHub remain separate from scoped review and tag approval.

The finite gate also found two stale API-profile source fingerprints, last
recorded before acceleration. Inspection against that recorded source shows
that `aes.rs` only adds the gated execution module and updates its scope docs;
`aes/tests.rs` adds the gated execution test module and its test-only revocation
checkpoint. The portable owners/arithmetic in those files are unchanged.
The two fingerprints and generated profile register are reconciled to these
already-retested sources, retaining the development-only AES disposition and
all validation rules. This is not a new accelerated-owner qualification claim
or a refresh of historical verification results. The existing profile mutation
tests and owner-contract checks validate the reconciled metadata.
