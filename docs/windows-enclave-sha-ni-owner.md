# Saved SHA-NI owner and decoder review

This completes the selected SHA-NI **normal-return owner/decoder review** on the
existing development image, building on the [lifecycle/receiver](windows-enclave-sha-ni-lifecycle.md),
[state](windows-enclave-sha-ni-state.md) and [engine/session](windows-enclave-sha-ni-engine.md)
reviews. It is implementation-author review, not independent retest or
whole-image qualification. No production implementation, saved enclave image
or release-gate policy changed.

The [observation](../assurance/windows-protection-observations/sha-ni-owner-review-20261005.json)
records exact identities and both host reports. The
[body inventory](../assurance/windows-protection-observations/sha-ni-owner-20261005.json)
binds begin, update, finish, rehash, request decoding, the partial-byte predicate
and two compiler-created cleanup funclets. Main function extents are separated
from funclets; complete associated exception metadata is matched to the image
without claiming that matching metadata proves OS-handler behavior.

## Request decoding and caller bounds

The emitted decoder requires version 13, route 1, reserved zero and nonzero
sequence. Operations are restricted to 11–16; payload length is at most 1,024,
the final-byte field fits a byte, source zero agrees with empty input, and
source-plus-length cannot overflow. The decoder never dereferences that source.
Begin, rehash and export require narrow identities; other requests require
identity zero. Non-input operations reject nonzero length or final-byte values.
Update requires an empty tail marker for empty input or eight valid bits for
nonempty input. Finish permits one through eight final bits for nonempty input
and requires zero for empty input.

The previously reviewed receiver copies the header and bounded payload through
the fixed OS adapter, decodes again and checks the copied length before dispatch.
Both actual decoder calls and all owner call destinations are bound here.
Private update/finish input bounds remain compiler preconditions enforced by
that receiver, not standalone checks preserved inside every optimized callee.

## Owner normal-return lifecycle

- Begin requires Empty admission and a narrow identity, constructs the state,
  drops any active previous fields before replacement and enters Streaming only
  after successful publication. Failed construction/admission cannot publish a
  usable replacement.
- Update requires Streaming admission and active state. Only engine success
  disarms the owner guard. Returned errors take/drop active fields, clear retained
  output and invalidate algorithm/authority metadata before quarantine.
- Finish validates the final-bit shape and canonical unused low bits through
  the bound secret-byte predicate. It takes the state before consuming it,
  checks the output width against the 32-byte destination, and enters Retained
  only after success. Rejection retains the guarded clearing/quarantine path.
- Rehash requires Retained admission and a narrow new identity. It constructs
  and consumes a fresh state over the retained digest into 32-byte temporary
  staging. Only successful completion permits clearing/replacing the old output
  and updating the identity. Staging is cleared on success and returned errors;
  unsuccessful operations quarantine and clear the old owner as well.

All four identity/width dispatch tables (one finish table and three rehash
tables) are checked in object and linked image, including all relocation and
subtable destinations. Existing cancellation and explicit-public-export paths
remain covered by the lifecycle/receiver review. Public output already copied
to the host is not promised rollback.

Compiler-created enum copies are not described as individually wiped in full.
Typed workspace/scratch destruction clears owned active regions; enclosing
protected-window clearing and page teardown cover inactive copies and padding.

## Frames and exception limits

With `H` the protected 64-KiB window's high address, the reviewed owner steady
stack pointers are `H-5552` for begin, `H-3568` for update, `H-3648` for finish
and `H-5696` for rehash. The decoder reaches `H-1520`. Copied state, temporary
digest and selected metadata regions are mapped within the enclosing window.
Deeper state/engine paths retain their separately recorded geometry; this is
not a maximum whole-image depth result.

The emitted finish funclet calls the owner guard; the rehash funclet first
clears temporary staging and then calls that guard. Their bodies and metadata
are bound, but this **does not qualify arbitrary OS-exception invocation**, fatal
aborts, asynchronous interruption or privileged snapshots. It does not broaden
the supported normal-return cleanup boundary.

## Reproduction and results

```sh
python3 scripts/cryptography/test-windows-enclave-sha-ni-owner.py
python3 scripts/cryptography/windows_enclave_sha_ni_owner.py \
  release-reports/windows-local-20261004 --mutate
```

Eight focused tests pass on Linux and Windows with identical parsed reports.
Each host rejects all 3,083 actual body-byte and 112 dispatch-table byte mutants.
These enforce review identity and table binding, not independent algorithm
correctness. Semantic instruction, function-label, relocation, frame and claim-
boundary regressions supplement those checks.

The existing native Linux SHA-NI component campaign was rerun separately: nine
component tests and four placement tests pass; fifteen component plus three
placement compiled mutants and thirteen ownership negatives are rejected.
This is ordinary-process component execution, not new enclave execution.
Its report and the offline results are preserved outside Cargo target directories
under `release-reports/windows-worker-review-20261005/`.

Next are other distinct family workers, indirect SIMD dispatch, remaining
runtime/loaded-SDK reconciliation and final whole-image scope reconciliation.
See the [remaining-work checklist](windows-v02450-remaining.md).
