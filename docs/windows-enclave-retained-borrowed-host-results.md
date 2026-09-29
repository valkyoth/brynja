# Native affine borrowed-input host observations

Status: **research observations only**, not production Windows strict support.
The private Rust resource owner now accepts a borrowed input slice through a
synchronous metadata-only request and drives the existing
[borrowed-input retained worker](windows-enclave-retained-input-results.md).
This connects the previously separate native worker and affine host components.
The native campaigns use bounded public vectors, not confidential application
data. Production crates and release-gate policy are unchanged.

Host source: `5490e9d1d4ef41aa5eb0c880f92c92783a602ed3`.
Image source: `e88a7f6be397d69c350101bd6969721cfd8bc0b3`.
The [observation record](../assurance/windows-protection-observations/retained-borrowed-host-5490e9d1.json)
binds both campaigns, native executable hashes, image identity, source closure
and exact results. Complete artifacts are saved outside Cargo's `target/` tree:

```text
release-reports/windows-azure-replacement-2026-09-29/retained-borrowed-host-complete.tar
SHA256 11c8d9fb066aa0f559c81efcce98543c7b123ef281cb5a365295c8f68d5a3566
```

## Ownership and copy boundary

The source-bound builder derives a separate host from the earlier fixed-vector
adapter using checked replacement anchors. Earlier sources, artifacts and signed
images remain unchanged. The generated session's `begin(&[u8])` rejects input
larger than the 1,024-byte experimental capacity before changing generation or
entering the OS. Valid requests bind caller input to a private, synchronous
adapter call; request metadata carries the session's checked next generation.
The host transport independently tracks owner creation epochs and validates the
enclave's reported epoch. The enclave independently validates the copied header.

The input borrow ends when the copy/hash call returns. The pending result borrows
the session, not the original input, so the caller may modify or release its
buffer while the digest remains owned inside the enclave. Each native digest
case zeros that original buffer before export. The host never receives an
enclave-private slice or a secret result token. Original caller storage remains
outside the protected-memory boundary.

The fixed C adapter validates all eleven input-report fields, admitted buffer
bounds and disjointness, copy counts, epoch and clearing, in addition to the
existing worker/guard/residency reports. Callback, input metadata and public-output
addresses are revoked after each synchronous call, including failure paths.
Expected input rejection is reported to Rust, which quarantines the session but
retains responsibility for destroying the retained owner. Uncertain native
reports still prevent deletion from being used as a substitute for clearing.

Public export remains transactional: destruction and full-page clear/unlock/free
must complete and the identity/generation receipt must match before caller output
is committed. Dropping or forgetting a pending result does not reopen the session.
Its parent still owns cleanup. This protocol is not hostile-host attestation,
authentication, or general cross-instance composition.

## Verification

Two native campaigns passed on the existing Azure x86-64 Windows development
host. Each normal campaign performed **184 enclave calls**, created/deleted nine
host-owned instances and reported zero retained resources or cleanup errors:

- Twenty independent hashlib digest comparisons and twenty cancellation cases,
  including empty input, padding boundaries and full-capacity input.
- Oversized input rejected without native entry or generation consumption.
- Dropped/forgotten pending results, actual null-destination output-copy rejection,
  simulated lost completion and wrong-resource receipts.
- A deliberately stale input sequence and actual invalid-address payload-copy
  rejection, both followed by confirmed retained-owner destruction.
- Explicit close and parent-destructor cleanup.

Separate startup-failure controls each cleaned up their partially created owner.
The simulated OS-deletion failure correctly reported one retained resource and
three cleanup errors; it is not a cleanup success. Three compiled host mutants
(early output commit, reopening an abandoned result, ignoring receipt identity)
were rejected in both campaigns. Expected exits were `0, 0, 0, 0, 0, 97, 97, 97`.

Focused local verification passed:

- Ten Rust tests at O0/O2 covering borrowed-input lifetime, report tampering,
  quarantine, cleanup ownership, bounds, abandonment and deletion failure.
- Three compiled Rust mutants rejected at both optimization levels.
- One positive and twelve negative compile probes for session/pending ownership
  and Send/Sync/Copy/Clone/Debug restrictions.
- C input-report checks at O0/O2, including four rejected compiled mutants.
- Native-result schema/counter/exit tamper checks and earlier component/host tests.

Native MSVC builds used `/O2 /W4 /WX /MT /guard:cf`; Rust 1.98.1 used O2,
checked overflow and panic=abort. The archive review compared committed/current
source bytes, generated files, Rust archives, executable hashes, raw captures,
build logs and exact outcomes. No native build warning was emitted. No probe
child remains active. Existing signed input-worker and retained-worker hashes
are unchanged; no signing or host-configuration change was needed.

## Remaining scope

The existing development signing warning, disabled Secure Boot and platform
limitations still apply. These runs do not qualify production signing, Windows
AArch64, new dump protection, arbitrary worker depth/TLS/runtime copies or a
shipping confidential-input API. Partial-copy writes and recoverable unwind are
covered by component mocks, not these native panic=abort campaigns. Retained-result
composition, general cross-instance protocol controls, other algorithms and
production facade integration remain [pending](windows-v02450-remaining.md).
