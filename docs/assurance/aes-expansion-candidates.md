# Isolated AES hardware-assisted expansion candidates

Status: integrated into explicit development execution routes; qualification unfinished.

The [x86 candidate](../../crates/brynja-crypto-cpu/src/aes/x86_expand.rs)
and [little-endian AArch64 candidate](../../crates/brynja-crypto-cpu/src/aes/aarch64_expand.rs)
generate complete forward schedules for AES-128, AES-192 and AES-256. They now
serve the explicitly accelerated owner routes through sealed authority/session
admission. Ordinary portable owners are unchanged. The low-level `Session`
adds exact-width `expand128`, `expand192` and `expand256` methods; callers own
and clear their buffers. No new Cargo feature or release gate is introduced.

## Construction and bounds

Both implement the word recurrence in Algorithm 2 of
[FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf).
The permitted key/schedule byte pairs are exactly `(16,176)`, `(24,208)` and
`(32,240)`, enforced at monomorphization. Both copy the original key into the
output before generating later words; all prior-word reads are therefore of
initialized bytes. Typed input/output borrows are disjoint. Four-byte unaligned
accesses allow byte-aligned caller buffers; AArch64 requires ordinary memory
supporting these accesses and a little-endian target.

On x86, replicating a word into all vector lanes before `AESKEYGENASSIST` with
zero immediate yields `SubWord` in the low word. The instruction semantics are
documented in the [Intel instruction manual](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf).
On AArch64, repeating a word in all four columns makes `ShiftRows` an identity;
`AESE` with a zero round key supplies the byte substitution. Little-endian word
rotation and the public round constant complete the recurrence. AES-256's
additional substitution is applied halfway through each key-width cycle.

The source contains no secret-indexed table. Branches and addresses depend on
public widths, offsets and round constants. Each function uses one opaque
assembly block without calls or stack access inside that block. Its scratch
GPRs/vector registers are explicitly overwritten before return. This does not
prove whole-call-frame, caller-copy, compiler-spill or physical erasure, and is
not a final-linked emitted-code or side-channel qualification.

The unsafe caller must guarantee the complete ISA bundle remains available
throughout execution on every eligible CPU. The isolated fixture uses a runtime
feature check under a stable test-host assumption; it is not production
migration-safe admission. Input/output secret lifetime management remains the
caller's responsibility. The fixture uses public test keys only.

## Registered checks

```sh
brynja-verify run aes --needed --category aes-expansion-candidate
```

Four configurations cover Rust 1.90.0 and 1.99.1 on native Linux x86 AES-NI and
AArch64 musl under QEMU. Emulation does not establish native ARM support,
performance or physical properties. The [runner](../../scripts/aes/check-aes-expansion-candidate.py)
requires the exact ten-test population and unique completion markers, including:

- Every generated schedule byte compared with the independent test-only
  finite-field reference for 568 AES-128, 700 AES-192 and 810 AES-256 NIST KAT
  records. Hardware rounds consuming those schedules must match the authoritative
  ciphertext/plaintext and reverse the operation without modifying the schedule.
- 774 generated keys: each byte value at every key position, plus uniform zero
  and uniform `ff`, across all widths; complete schedules compared.
- 768 key/output byte-alignment combinations with input immutability and output
  prefix/suffix canaries.
- The original five round-candidate tests, including their separate KAT and
  alignment checks, without substituting the new expansion for the reference.
- All three valid shapes compiled as a `no_std` library; five invalid shape
  instantiations must fail with the expected constant-evaluation diagnostic in
  the candidate source, not an unrelated compiler error.

The [runner regressions](../../scripts/aes/test-aes-expansion-candidate.py) reject
missing/duplicate markers, changed test names/counts, failed/ignored tests,
unrelated negative-compile diagnostics and ambient build overrides. They check
retention of failed/timed-out subprocess output and pin the registrations.
Commands, outputs and status are retained under `target/aes-expansion-candidate`.
The verifier records scoped local observations, not authenticated certification.

## Admission and owner integration

Startup compares all 176/208/240 generated schedule bytes with fixed expected
schedules, separately from the six block KATs that continue to use those fixed
schedules. Tests corrupt every expected byte in turn (624 cases), require
rejection, and verify that expansion startup failure quarantines the authority.
Session expansion checks health, generation and static/platform admission before
entry and rechecks authority after expansion. Wrong architecture, missing ISA,
testing, stale generation and quarantine must preserve low-level output.

Cached constructors and operation-local owners call those session methods into
clearing scratch. Existing operation guards quarantine on error or unwind;
admitted secret destinations clear and public output remains unchanged on
failure. Owners recheck authority after expansion before retaining or using a
schedule. Static acceptance requires four owner regression tests:

- 36 injected operation errors/unwinds across both expansion boundaries, three
  key widths and all three output operations;
- 12 cached-constructor errors/unwinds, with scratch and destination cleanup;
- all three cached key types reuse their schedule without entering expansion;
- 12 revocation-after-expansion cases covering cached constructors and all
  operation-local output paths, with no retained owner or released output.

The boundary hooks are test-only and surround an opaque assembly call. They do
not inject physical faults or Rust panics between assembly instructions. The
portable implementation retains its separate word-by-word injection coverage.
Live scratch observations do not prove register/spill cleanup.

Paired compiler probes reject wrong key/schedule widths and overlapping safe
borrows for every low-level expansion method. They extend checkout direct/facade
acceptance to 127 pairs per compiler, and archive-only no_std acceptance to 62
pairs per route/compiler, without relaxing existing ownership or feature probes.

## Remaining qualification

The pre-integration linked templates describe portable expansion and are not
evidence for this replacement. Review changed final-linked startup, dispatch,
constructor, caller, expansion and cleanup code deliberately; do not widen or
regenerate an allowlist just to regain a pass. Replay packaged AVS/differential,
no_std, sanitizer and feature acceptance on the integrated source. Then collect
native ARM and the other named platform observations. Performance diagnostics
and timing experiments remain separately declared; these correctness checks
collect neither. v0.27.3 remains in progress.

The broader [development ledger](aes-acceleration-development.md) and
[release plan](../RELEASE_PLAN.md) retain the unfinished v0.27.3 work.
