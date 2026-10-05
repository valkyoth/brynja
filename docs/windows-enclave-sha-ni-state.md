# Saved SHA-NI state construction and consumption review

This is implementation-author inspection of the unchanged saved development
image, not a new native campaign, independent retest or whole-image guarantee.
It extends the [lifecycle/receiver review](windows-enclave-sha-ni-lifecycle.md)
for `sha2/mod.rs::open_sha_ni`. Image and object identities are retained in the
[observation](../assurance/windows-protection-observations/sha-ni-state-review-20261005.json).
No production implementation or release-gate policy changed.

## Constructor and copied storage

The emitted constructor checks authority health and the selected kernel before
its startup KAT. KAT rejection clears compression scratch and invalidates the
authority. Successful SHA-224 and SHA-256 construction uses separately bound,
readonly IV constants and matching initialization/publication instruction ranges.
The review binds both constants in the object and final image, not merely their
symbol names. Revalidation failure clears the temporary scratch and workspace.

The constructor has a 7,800-byte frame, including saved XMM6 storage. It makes
several compiler-generated session/workspace copies before publishing the state.
The 1,024-byte block region is initialized before publication; distinct metadata
and padding regions are not described as wholly initialized or erased. The
saved XMM6 value and all earlier moved copies are **not individually wiped**.
Normal enclosing protected-window cleanup remains responsible for these bytes.

The review binds actual begin/rehash caller extents, their prologues and their
constructor call targets. This does not qualify every branch or exception handler
in those owner operations. The constructor and rehash references also resolve
to the same exact saved `__chkstk` body; its execution-context qualification
remains separate.

## Consuming finalization and output

The finalizer initializes a 32-byte staging buffer and moves the engine into
its 2,104-byte frame. SHA-224 and SHA-256 require their respective output widths.
The private emitted function has an LLVM length range of `[0, 33)`; review
pins that precondition rather than claiming it safely accepts arbitrary lengths.

On the successful path, digest bytes are copied out before workspace/scratch
destruction, then transferred through the equal-length copy adapter. The
digest result and full staging buffer are cleared. Rejected output shapes and
backend errors retain the corresponding cleanup paths. The private byte-copy
helper is bound to its no-stack body and RAX/RCX/RDX clearing. None of this is
a claim that every byte of the original or moved enum is individually erased.

The actual engine-finalization target is recorded, but its internal operation
semantics and startup-KAT internals are not qualified by this state review.

## Selected stack geometry

With `H` the high address of the 64-KiB protected stack window:

| Selected path | State-function steady RSP |
| --- | ---: |
| begin → constructor | `H-13360` |
| rehash → constructor | `H-13504` |
| finish → state finalizer | `H-5760` |
| rehash → state finalizer | `H-7808` |

Reviewed copied regions and saved-vector storage fit those frames. These are
selected caller paths, **not maximum transitive depth**: deeper engine, KAT and
kernel frames still need reconciliation. Whole-image, handler, runtime-selector
and loaded-application SDK qualification remain open.

## Reproduction

```sh
python3 scripts/cryptography/test-windows-enclave-sha-ni-state.py
python3 scripts/cryptography/windows_enclave_sha_ni_state.py \
  release-reports/windows-local-20261004 --mutate
```

Eight focused tests pass on both Linux and Windows, with identical parsed
saved-image reports. All 2,286 actual body-byte mutations are rejected per host.
These are review-identity mutations, not cryptographic-behavior tests. Additional
tests exercise instruction landmarks, call edges, parameter bounds, both IVs,
frame geometry and the explicit limits of the report. Existing unchanged native
component results are reused; no new enclave execution is claimed.

Raw reports remain outside Cargo target directories at
`release-reports/windows-worker-review-20261005/offline/sha-ni-state-*.json`.
See the [remaining-work checklist](windows-v02450-remaining.md).
