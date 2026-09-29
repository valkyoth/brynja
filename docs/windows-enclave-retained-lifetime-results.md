# Native host lifetime and receipt identity observations

Status: **research observations only**. Windows strict constructors still reject
Unsupported. This extends the experimental affine host, not production crates,
the enclave image or release-gate policy.

Host source: `6ab54ebd32f8d782933dd189688e34ef0c6dfd0b`.
The [observation record](../assurance/windows-protection-observations/retained-lifetime-6ab54ebd.json)
binds the committed source closure, generated inputs, libraries, executables and
two repeated native captures. Both use the unchanged development-signed
[cross-instance image](windows-enclave-retained-cross-results.md) from
`bce5cd2a9a76fb3908e421b0c8ed06d7b22de18e`. Native builds used transferred
source-bound archives, not the server's older Git checkout.

Complete artifacts are saved outside Cargo's target directory:

```text
release-reports/windows-azure-replacement-2026-09-29/retained-lifetime-complete.tar
SHA256 50d641038df0b5e080f22c9e304144d1ebfed4e6a9a3ffa468cfc0152fcce09b
```

## Identity and ownership boundary

The earlier host derived its private receipt identity from an allocation address.
That address could be reused after teardown. A checked atomic sequence now issues
a nonzero ID before native resource acquisition. Failed construction consumes the
ID too; close/drop never returns it. Zero, exhaustion and excessive contention
reject construction without falling back to an address or wrapping the sequence.
Reservation uses at most 64 compare/exchange attempts.

This is uniqueness within **one linked runtime in one process**, not persistent
identity, authentication, image verification or cross-process authority. It does
not change the enclave's separate live-mapping token identity. Independent copies
of the runtime, process restarts and hostile-host attestation remain outside this
claim. Diagnostic ID access and fault injection are private fixture operations,
not shipping APIs.

The affine result continues to borrow its session. Safe code cannot destroy or
close that session while its result remains live, or return a result past its
owner's lifetime. Closed sessions never reenter native code. A mismatched receipt
quarantines the session without committing public output. These ownership checks
complement the sequence; an ID alone is not a lifetime proof.

## Verification

Two Azure x86-64 Windows campaigns each completed **265 calls**, created/deleted
12 enclave instances and reported zero retained resources and cleanup errors on
the normal path. Each closes an old instance, requires the replacement host ID to
increase, injects a stale receipt, checks unchanged output and quarantine, then
confirms deletion. Native allocation-address reuse is not asserted: a separate
mock test deliberately returns the same address for every allocation.

Both campaigns reject four compiled host mutants: early completion, reopening,
ignored receipt and recycled constant identity. Their exact exit codes, operation
counts and resource counts match the recorded expectations. Startup failure
controls also pass. The deliberate deletion-failure control retains one uncertain
resource and reports three cleanup errors until child exit; this is an expected
failure path, **not successful cleanup**.

Focused local checks pass:

- Fifteen Rust tests at O0/O2, covering terminal close, forced address reuse,
  stale receipts, concurrent reservations and sequence exhaustion.
- Three counter mutants and two host-identity/receipt mutants rejected at both
  optimization levels.
- One positive ownership compilation and thirteen expected compilation failures.
- Native result-schema, counter, type and exit-code tamper checks.
- Three focused sequence tests under Miri strict provenance, including concurrent
  reservations, with `nightly-2026-09-11`. This is not Miri coverage of native FFI.

The native host builds without warnings under MSVC 17.14.41, O2, warnings-as-errors
and control-flow protection, using Rust 1.98.1 panic=abort libraries. The artifact
review matches current/committed source hashes, generated input/library hashes,
EXE/image hashes, raw captures, exact repeated outcomes, build logs and cleanup.
No probe children or ephemeral certificates remain. Earlier images are unchanged.

No image was rebuilt or signed for this step. The reused image retains its
development-only signing limitations and the host has Secure Boot disabled.
No new native unwind, dump, general residency, production deployment or Windows
AArch64 qualification is established. [Remaining work](windows-v02450-remaining.md)
still includes production owner/facade integration and image verification.
