# Native retained SHA-256 composition observations

Status: **research observations only**, not production Windows strict support.
The [retained composition component](windows-enclave-retained-rehash-design.md)
now runs in a separate signed development enclave image, driven by an affine
Rust host. Native campaigns use bounded public vectors, not application secrets.
Production crates and release-gate policy are unchanged.

Host and image source: `8251e89b5c8dd9caa409628c6d96d5953e645dd8`.
The [observation record](../assurance/windows-protection-observations/retained-rehash-8251e89b.json)
binds source hashes, generated build inputs, both campaigns, signed images,
executables and exact outcomes. The remote Git checkout remains older; these
images were built from the transferred, source-bound archives, not that checkout.
Complete artifacts are stored outside Cargo's target directory:

```text
release-reports/windows-azure-replacement-2026-09-29/retained-rehash-complete.tar
SHA256 7aa0708f74e47640374e15fc021a9229487f9feb3834c65e1436a60eb08a9260
```

## Operation boundary

`Pending::rehash(self)` consumes the pending host handle and returns a new pending
handle only after a validated completion. The operation hashes the retained
32-byte binary digest and replaces it inside its existing enclave-owned slot.
There is no intermediate public result copy. The operation is fixed; no generic
application callback or enclave-private host slice is exposed.

The worker validates the complete token, advances its checked generation and
reports the admitted workspace, candidate and staging addresses, scratch
clearing, generation transition, owner epoch and status. Scratch clearing is
checked before any additional defensive wipe. The host independently tracks the
generation and validates all report fields, bounds and disjointness. An observed
public-copy count must be zero for composition; ordinary final export must
report exactly one copy. Metadata reports are observations from the bound image,
not hostile-host attestation or secret provenance proof.

A diagnostic stale-token replay follows one successful rehash. The real worker
rejects it, clears and quarantines its retained owner; the host remains responsible
for confirmed destruction. Rehash failure cannot reopen the session. Public
output still commits only after the final export, verified owner destruction and
resource cleanup. Cancelled, dropped and forgotten pending results retain their
parent's cleanup obligation.

## Native verification

Two campaigns passed on the Azure x86-64 Windows development host. Each normal
campaign completed **261 enclave calls**, created/deleted ten instances and
reported zero retained resources or cleanup errors. Coverage includes:

- Twenty independent hashlib comparisons, each chaining one through four rehash
  operations after the initial digest. Original input is zeroed before chaining.
- Twenty cancellation cases, plus dropped and forgotten handles after rehashing.
- Stale-token rejection followed by confirmed cleanup, oversized input rejection,
  stale input epochs and actual invalid-address input/output-copy failures.
- Simulated lost completion, wrong receipts and parent-only destruction.

Three startup-failure controls cleaned up their partially created resources.
The simulated deletion failure correctly reported one retained resource and
three cleanup errors. It is not a cleanup success.

Seven compiled mutants were rejected in each campaign: three host mutants
(early output, reopening and ignored receipt identity) and four image mutants
(missing scratch clearing, ignored token, omitted result replacement and reused
generation). The scratch, token and generation mutants deliberately leave
uncertain resources retained until the test child exits; those controls are not
counted as successful clearing. The omitted-replacement mutant is caught by the
digest oracle rather than merely by a metadata check. Exact exits and counters,
not arbitrary nonzero results, are validated and recorded.

## Local checks and artifact review

- Eleven mocked Rust host tests at O0/O2, including each completion-report field
  and stale-token cleanup ownership.
- C report validation at O0/O2, including four compiled mutations of copy count,
  clearing, epoch and generation checks.
- Real retained-worker tests and three compiled scratch/token/generation mutants.
- Native result schema, counter, type and exit-code tampering tests.
- Earlier component coverage: 600 independent chained outputs, all partial-write
  boundaries, failure/unwind, ownership negatives and focused strict-provenance Miri.

The archive review checked committed/current source bytes, generated files, Rust
archives, signed DLL and executable hashes, raw captures and exact repeated
outcomes. Native MSVC build logs have no warnings or errors. All five SignTool
invocations signed their images but exited 2 with the VBS compatibility warning;
the wrapper exited 1 and its warning logs are preserved. This is explicitly
development-only signing, not a clean production signing result.

The ephemeral certificate/key was removed. No probe children remain active, and
all five earlier signed image hashes remain unchanged. No host configuration was
changed during this step.

## Remaining scope

Stale-token replay within one owner is not cross-instance proof. A later separate
image now has [two-live-enclave routing observations](windows-enclave-retained-cross-results.md),
without persistent or authenticated identity claims. Another separate image has
[native injected partial-copy coverage](windows-enclave-retained-partial-results.md).
Recoverable unwind remains component-test coverage; native builds use panic=abort. This new
image has no new dump, TLS or arbitrary-depth qualification. Production signing,
Windows AArch64, other algorithms, acceleration and facade integration remain
[pending](windows-v02450-remaining.md). Existing development-platform limitations,
including disabled Secure Boot, remain unchanged.
