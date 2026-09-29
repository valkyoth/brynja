# Rust-owned borrowed-input host observations

Status: **isolated public-vector research, not a shipping Windows secret API or
strict-platform qualification.** Production code, availability and release gates
are unchanged.

The host at commit `2924a2b956667b19bf33a80c0ac95e43d4c21f60` ran on the
disposable Azure Windows Server 2025 x86-64 development machine on 2026-09-29.
It used the unchanged [direct-copy worker image](windows-enclave-borrowed-input-results.md),
whose SHA-256 is
`97cd72cf14508361603bc0f453f545362bd23af638f8b300a608ee1a685d9470`.
No enclave image was rebuilt or re-signed for this campaign; the earlier
test-signing and compatibility-warning limitations still apply.

## What changed in the experiment

The private Rust adapter now constructs a 64-byte `Request<'input>` referring to
the original caller slice. It retains that borrow across the synchronous native
call while allowing the separate protocol ledger to process fixed callbacks.
The old 1072-byte payload serializer is absent from this generated private model,
not merely bypassed by one call site. The earlier host fixtures remain unchanged.

The native adapter does not dereference the input pointer or create ordinary
payload staging. Only metadata and explicitly public digest output use ordinary
host buffers. The worker copies the input directly into its preadmitted protected
snapshot. The C adapter checks the updated 1152-byte header/payload/command
region and requires one payload-copy acknowledgment for nonempty input, zero
for empty input. Acknowledgment is a fixed diagnostic protocol check, not proof
of source provenance or an authenticated channel.

The input descriptor cannot outlive the caller data, even after its pending
operation is dropped or forgotten. This was checked by compiled lifetime-negative
tests. The adapter, native resource and callback machinery remain private;
no new user-controlled transport or public callback API was introduced.

## Completed checks

Five Rust tests pass at O0/O2, exercising all 1025 input lengths, original-pointer
identity, metadata-only descriptor size, malformed entry, epoch/phase handling,
copy errors, transactional public output, scope abandonment and quarantine.
Early-output and ignored-cleanup mutants are rejected at both levels. A positive
lifetime probe compiles; eight lifetime/trait violations fail compilation.

The capture validator rejects 144 altered or type-confused counter fields and
eight extra-field records. A compiled C shim checks the generated executable's
exact success counters, rejects individual drift, and rejects the prior host's
now-obsolete 5-owner/63-call success shape.

The native MSVC build passed with `/W4 /WX`. Its main campaign made 64 calls:

- Twenty independent SHA-256 vectors each exercised public export, cancellation,
  and actual invalid-destination copy failure: 60 calls. Copy failure preserved
  the caller's public destination and left the healthy owner reusable.
- Four uncertain-completion controls covered callback denial, lost completion,
  withheld cleanup confirmation and corrupted copy-acknowledgment accounting.
  Each quarantined the owner, preserved caller output and rejected reuse without
  another native call.
- Six actual instances were created and deleted, including one Drop-only
  teardown; the main campaign recorded no retained instance or cleanup error.

Three separate startup-failure controls cleaned up their partially initialized
instances. The deliberate deletion-failure control instead recorded one retained
instance and two cleanup errors. That is the expected rejection, **not successful
destructor cleanup**; its child process then exited.

Three broken executables were rejected: early public-output commit, ignored
cleanup confirmation, and ignored copy-acknowledgment completion checks.

## Evidence and helper failure

The [reviewed record](../assurance/windows-protection-observations/borrowed-host-2924a2b9.json)
binds original sources, generated adapter sources, Rust archives, compiler,
eight executable identities, exact counters and post-run cleanup. These were
checked against the capture commit, current local source and local cross-build
artifacts. The original signed worker image remained unchanged.

The first Windows batch-helper attempt skipped its compiler commands; the runner
then rejected the missing executable. Quoting the empty flags assignment and
using conventional CRLF batch formatting corrected the helper. Initial failure
logs are retained alongside the successful build/run; no result was waived.

Raw artifacts are saved outside Cargo's cleanable `target/` directory:
`release-reports/windows-azure-replacement-2026-09-29/borrowed-host-2924a2b9.tar`,
SHA-256
`ff21d7f7f470d09b9ce56ffda361779069fa742665908820d937219ff02704e3`.
No capture process or temporary signing certificate remained.

## Remaining boundaries

This connects the Rust input borrow to the previously tested native copy path.
It does not qualify processing real secrets or every worker/runtime path.
Enclave-internal source rejection remains an outstanding native case.

Persistent protected result storage, opaque result ownership, in-enclave
composition and the eventual production API still need implementation and review.
The current result is scoped to one worker call and can only be cancelled or
explicitly exported as public output. Caller-owned input, application-created
copies, fatal aborts and the previously documented platform limitations remain
outside this experiment's protection claims.
