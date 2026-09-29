# Borrowed input with a retained result

Status: **research component with native worker observations**, not a shipping
API or Windows strict qualification. The [new native campaign](windows-enclave-retained-input-results.md)
connects this component to a separate enclave image through a bounded Python
driver. A separate [native affine Rust host integration](windows-enclave-retained-borrowed-host-results.md)
now connects lifetime-bound caller input to this worker; it remains research-only.

## Descriptor and lifetime

`retained_input.rs` defines a 32-byte metadata-only request: version, operation
sequence, payload length and source address. It borrows the original caller input
without serializing any payload bytes into a host request array. Empty inputs use
the canonical zero-length/zero-address representation. Length is bounded to the
research fixture's 1,024-byte capacity, pointer arithmetic is checked, and the
descriptor is neither Send, Sync, Copy, Clone nor Debug.

The descriptor is **not authority or authentication**. The future private native
adapter must retain the request and original input borrow through its synchronous
call. Copying metadata does not extend that borrow or make the encoded address
safe to dereference. Only the platform copy API may dereference it. Original
caller storage remains outside protected enclave ownership.

Admission compares the copied sequence against independently maintained private
operation state. Reading the expected sequence from the same host header would
make this check vacuous and is not an acceptable integration. Sequence matching
does not replace instance ownership, replay state or platform admission.

## Worker composition

`retained_borrowed_digest.rs` combines an existing in-page retained owner with a
preallocated input snapshot, hardened SHA-256 workspace and staging buffer. All
must already be in independently admitted storage before real confidential input
could be accepted. This component does not allocate, lock or attest that storage.

It validates an already-copied header before requesting a payload copy. Nonempty
payloads are copied exactly once through the trusted fixture seam; empty inputs
perform no copy. Only the admitted byte count is hashed. The resulting digest
stays in the retained owner after snapshot/workspace/staging return, using the
existing secret-output path rather than public finalization.

The full snapshot and staging regions are cleared on success, rejection and
recoverable unwind. Every unsuccessful worker attempt quarantines the retained
owner, including an unexpected Busy attempt; any preexisting result is then
unavailable. The future host must still reject normal Busy requests before worker
entry. No post-hash workspace wipe is added to conceal an implementation cleanup
failure: the workspace is initialized to zero before the attempted operation,
then its own scoped implementation performs cleanup.

The generic copy closure is an isolated testing/integration seam, not a proposed
application callback API. The production-facing design still needs a private,
fixed OS adapter. Copy success cannot authenticate or atomically snapshot a
maliciously racing host. Fatal abort and caller-created copies remain excluded.

## Verification

```text
python3 scripts/cryptography/test-windows-enclave-retained-borrowed.py
```

Six tests pass at O0 and O2, including 150 Python-hashlib oracle cases, padding
boundaries, full-capacity input, canonical empty input, sequence/version/bounds
rejections, pointer overflow, partial writes at seven boundaries followed by
failure or unwind, Busy quarantine, and full scratch clearing. A caller-buffer
mutation after return leaves the retained digest unchanged. Raw workspace checks
use the existing source-bound layout validation; production component code
forbids unsafe Rust.

Five compiled mutants are rejected at both optimization levels: missing snapshot
clearing, ignoring copy failure, repeated input copying, hashing full capacity
instead of admitted length, and omitted quarantine. A positive downstream consumer
compiles; nine trait/lifetime/privacy/metadata-mutation examples are rejected with
their expected diagnostics.

The component-only Windows build record explicitly says `native_executed: false`
and `strict_qualified: false`. The separate native-worker record covers header
copying, private epoch checks, snapshot bounds, real invalid-address copy errors,
stale-sequence rejection and cleanup. The affine host integration now has native
observations too. Cross-instance protocol controls, retained-result composition and the broader
[v0.24.50 work](windows-v02450-remaining.md) are still pending. Release gates and
production Windows availability are unchanged.
