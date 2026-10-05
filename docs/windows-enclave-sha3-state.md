# Saved scalar SHA-3 state construction and consumption

This implementation-author review extends the
[owner-operation review](windows-enclave-sha3-operations.md) for the same saved
scalar SHA-3 development image. It covers the emitted state constructor,
fixed-output finalizer and XOF-finalizer dispatcher. It does not qualify all
transitive sponge, prefix, output or permutation helpers, or arbitrary exception
paths. No production code, native image or release-gate policy changed.

The [observation](../assurance/windows-protection-observations/sha3-state-review-20261005.json)
binds reviewer sources, image/object identities and matching parsed reports from
Linux and Windows. The [specification](../assurance/windows-protection-observations/sha3-state-20261005.json)
pins complete bodies, relocations, frames and both tables. Inspected assembly
sequences and immediate scratch-erasure checks supplement these identity pins;
they are not a general compiler or cryptographic proof.

## Construction

The constructor rejects either setup string above 8,192 bits and rejects nonempty
setup for non-cSHAKE identities. Its eight-entry table selects four fixed hashes
and the two cSHAKE rates, with SHAKE using the corresponding empty-setup path.
The table relies on the private LLVM algorithm precondition `[0,8)`, enforced
by the previously reviewed owner decoding; arbitrary ABI callers are not covered.

Fixed hashes initialize empty states. Nonempty cSHAKE setup uses rate encodings
`01 a8` or `01 88`, encoded strings, a bounded pending byte and rate padding.
The emitted constructor checks the resulting prefix byte count against its
expected padded length before publishing state. Prefix errors clear the pending
byte and active sponge before returning Crypto; successful setup also clears
the pending byte. Public bounded setup lengths and their arithmetic are not
described as secret erasure.

Successful construction moves sponge fields through temporary stack regions
into the result. Those earlier copies are not all individually erased. The
enclosing protected-window cleanup remains necessary, as does full owner-page
cleanup for inactive enum bytes.

## Fixed-output consumption

The finalizer creates a 1,024-byte staging region, copies the current 1,136-byte
state and sets the original discriminant to Empty before dispatch. It admits
only the four fixed-hash variants and exact output widths 28, 32, 48 and 64.
Its private compiler output-length precondition is `[28,65)`, supplied by the
reviewed owner width selection. It is not an unrestricted slice-entry guarantee.

Each branch checks accumulated complete-byte addition with carry before update.
Partial-byte handling, the three-bit SHA-3 suffix and the terminal rate bit are
present in the emitted finalization paths. SHA3-256 calls a separate finalizer;
the other three rates inline the padding/permutation steps. Each of the fifteen
inlined scalar permutation call sites immediately clears scratch regions of
40, 40, 200 and 168 bytes before the next branch. The reviewer checks the full
call-site population, rate-loop widths and final-bit positions. This does not
qualify the permutation callee's internals.

Successful digest staging passes through the typed-output completion helper,
wipes the consumed active sponge and copies the result into the owner's retained
output. The temporary typed output is cleared when dropped. Returned errors
also reach cleanup; all returns clear the complete 1,024-byte staging region.
The prior copied state at frame offset 2,160 and inactive original bytes still
rely on enclosing-window/page reclamation, not just the active sponge wipe.

## XOF dispatch, connections and frames

The XOF dispatcher accepts only X/Y states, calls the correct 128/256 in-place
transition and maps its result. The transition internals remain a separate
review obligation. Constructor/finalizer incoming edges are reproduced from the
already reviewed owners; outgoing references are bound to the actual saved
cleanup, memory, prefix and sponge bodies. Eight additional callees receive
identity-only bindings, explicitly not semantic qualification.

The constructor uses a 2,792-byte fixed frame and the fixed finalizer a
3,368-byte frame, including saved registers. Selected rehash-to-finalizer depth
reaches `H-8320`, and begin-to-constructor reaches `H-6672`, where `H` is the high
address of the protected window. Local state/staging regions fit these frames.
Deeper callee frames remain open: neither value is maximum whole-image depth,
nor a guarantee for instrumented builds or arbitrary OS exceptions.

## Reproduction and results

```sh
python3 scripts/cryptography/test-windows-enclave-sha3-state.py
python3 scripts/cryptography/windows_enclave_sha3_state.py \
  release-reports/windows-local-20261004 --mutate
python3 scripts/cryptography/test-windows-enclave-sha3-stream.py
```

Eight focused tests pass on Linux and Windows. Each host rejects 10,496 actual
body-byte mutations and 48 table-byte mutations. Independent-of-hash regressions
remove admission/cleanup sequences, change every permutation-site erasure,
alter private preconditions and call connections, and check frame/window limits.
Parsed reports match and are retained outside Cargo target directories under
`release-reports/windows-worker-review-20261005/offline/`.

The Linux component campaign again passes seven component tests, one placement
test, ten compiled mutation rejections, 628 cSHAKE, 76 NIST, 96 hashlib and 512
retained-rehash cases, plus streamed setup. This is ordinary-process testing,
not a new native enclave run or independent retest. See the
[remaining checklist](windows-v02450-remaining.md) for the open qualification work.
