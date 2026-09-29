# Retained secret-to-secret composition

Status: **component tests, focused Miri and Windows cross-compilation**, not
native enclave execution or production strict qualification. This adds a fixed
SHA-256 rehash operation to the isolated retained-owner model. The existing
[native borrowed-input host](windows-enclave-retained-borrowed-host-results.md)
and its signed image are unchanged; they do not yet expose this operation.

## Operation and ownership

The operation computes SHA-256 over the retained 32-byte binary digest, not its
hexadecimal encoding. The input remains in its existing exclusively owned slot;
the result replaces that slot without exporting an intermediate to the host.
The fixed owner method uses hardened secret finalization, never public export.

The builder includes three separately reviewed fragments in derived fixture
crates using exact source anchors. It does not edit the previous slot, digest or
placement sources, so earlier images and their source bindings remain intact:

- `persistent_transform.rs` adds a trusted secret-transformation seam to `Slot`.
- `retained_rehash.rs` supplies the fixed SHA-256 operation, using the real
  first-party in-place workspace and secret-output owner.
- `retained_placement_rehash.rs` delegates through the checked in-page owner.

The generic transform closure is only a trusted fixture/internal-operation seam,
not a proposed application callback API. Native integration must expose only the
fixed operation. The seam by itself is not a protection boundary against a
malicious implementation that deliberately copies its borrowed input elsewhere.

Admission consumes a Ready result and compares all four token fields. On success,
checked arithmetic advances its generation, the complete candidate replaces the
old digest, and a new token is returned. The old token cannot operate on the new
generation. Rejected tokens, generation exhaustion, operation failure and
recoverable unwind clear the old result and quarantine the slot. Attempts on
Idle/Closed/Quarantined states do not execute the operation; supplied scratch is
still cleared.

Two caller-supplied 32-byte scratch regions serve distinct roles: a candidate
for transactional replacement, and staging borrowed by the hardened secret-output
owner. Both are cleared through scoped ownership, including partial writes and
unwind. The SHA-256 workspace initializes its public IV before admission; no
extra post-operation wipe hides a failed workspace cleanup check. The retained
page is still destroyed and fully erased before the adapter may release it.

All storage must already be admitted by the platform adapter before handling real
confidential material. This component does not allocate, lock, attest or establish
worker-stack bounds. It does not erase caller-frame copies, abort state, signal
frames or privileged snapshots.

## Identity limits

Tokens remain public routing metadata, not authentication capabilities. Tests
reject tokens from owners assigned distinct identities, as well as stale and
tampered fields. Those tests do **not** prove native cross-enclave uniqueness:
the adapter must establish identities and instance routing rather than trusting
caller-supplied labels. The signed native image still needs a composition command
and integrated cross-instance rejection tests. No native cross-instance claim is
inferred from the component tests.

## Verification

```text
python3 scripts/cryptography/test-windows-enclave-retained-rehash.py
```

At O0 and O2, four slot tests and three real-hash/placement tests pass. The oracle
campaign covers 150 inputs and 600 independent hashlib outputs for one through
four rehash operations. Workspace and scratch cease to exist before final public
export. Cancellation and owner destruction clear the retained result.

Failure tests cover all 33 candidate-write boundaries, each followed by failure
or recoverable unwind; all token fields; distinct-owner and stale-token rejection;
generation exhaustion; and nonready state rejection. Five compiled mutants are
rejected at both optimization levels: missing scratch clearing, ignored token,
ignored operation failure, omitted result replacement and reused generation.
One positive and nine negative compile probes check that secret borrows cannot
escape, live source/scratch cannot be mutably aliased, and the slot remains
non-Send/non-Sync/non-Copy/non-Clone/non-Debug.

The source-bound builder supports the focused memory-model check:

```text
python3 scripts/cryptography/windows_enclave_retained_rehash_build.py <fresh-directory> --miri
```

All four slot tests and two focused real-hash/placement tests pass Miri with strict
provenance. The 600-output oracle campaign runs natively in the component test,
not under Miri. Each Miri subprocess is bounded to 180 seconds; expected executed
test counts are checked to reject vacuous filters. The build also cross-compiles
the derived libraries for Windows x86-64 with Rust 1.98.1. Its record explicitly
sets `native_executed: false` and `strict_qualified: false`.

This checkpoint's build record, generated sources, archives and Miri transcripts
are saved outside Cargo's normal target directory:

```text
release-reports/windows-azure-replacement-2026-09-29/retained-rehash-component-final/
release-reports/windows-azure-replacement-2026-09-29/retained-rehash-focused/
```

Next is native worker/host integration, source-bound storage and cleanup checks,
and actual cross-instance protocol testing. See the [remaining release work](windows-v02450-remaining.md).
No production crate, release gate or Windows availability claim changed.
