# Saved scalar sponge finalization and squeezing

This implementation-author review extends the [update review](windows-enclave-sha3-update.md)
for the same saved scalar SHA-3 development image. It covers six emitted bodies:
finalization and typed-secret squeezing at rates 136/168, plus both cSHAKE
absorption-to-squeezing transitions. It does not qualify the remaining terminal
output adapters, scalar permutation internals or the whole image.

The [observation](../assurance/windows-protection-observations/sha3-finalize-review-20261005.json)
binds source identities and matching Linux/Windows reports. The
[specification](../assurance/windows-protection-observations/sha3-finalize-20261005.json)
pins complete instruction bodies, relocations and frames. Actual caller/callee
addresses disambiguate the rate-specific bodies. Normalized pair comparisons
allow only reviewed rate constants or destinations, retaining shared backing-
buffer checks and clearing lengths. These checks supplement manual inspection;
they are not a general machine-code correctness proof.

## Finalization and transition

The emitted finalizers retain the partial-byte/suffix metadata in owned staging,
copy complete buffered bytes, mask the partial byte and insert the selected
suffix. They absorb a padding block when the suffix reaches the rate boundary,
including when its final bit lands exactly at that boundary, before adding the
terminal high bit to the final rate byte. Separate bit-concatenation tests cover
every buffered length, partial width and the SHA-3, SHAKE and cSHAKE suffixes.

Each finalizer has three static permutation call sites. Every site immediately
clears 40-, 40- and 200-byte permutation scratch plus the 168-byte padding region.
Completion changes phase, resets the squeeze cursor, clears partial input,
padding and squeeze staging, then tail-calls the four-byte suffix eraser after
restoring the frame. Active sponge lanes remain live for squeezing. No blanket
claim is made that caller frames or all restored registers are erased here.

The cSHAKE transition rejects non-absorbing states and checks the final input's
complete-byte addition before update. It selects `04/3 bits` for customized
cSHAKE and `1f/5 bits` for the SHAKE-equivalent path. Only successful finalization
clears setup-length/customization metadata and commits the squeezing lifecycle.
Update rejection returns an error without pretending that finalization occurred.

These are private typed paths: valid owner invariants, canonical partial input
and exclusive borrows are required. The saved LLVM ABI restricts suffix values
to `[4,32)` and widths to `[3,6)`. The reviewed callers select the actual suffix
pairs; arbitrary calls to the private symbols are not admitted or qualified.

## Squeezing and failure ownership

The squeezer checks the 128-bit output counter before copying. Nonempty requests
reject a cursor beyond the rate, permute at the rate boundary, and fill staging
in bounded pieces. Each permutation immediately clears its three scratch regions
before resetting the cursor. Typed-output writes check region presence, checked
initialized-length addition and capacity before copying. Successful chunks commit
their initialized extent and clear all 168 staging bytes. Output-write rejection
also clears staging.

The total output counter commits only after every chunk succeeds. Earlier chunks
may have been written before a later capacity error; the typed initialization
owner and enclosing failure cleanup remain responsible for that partial output.
Invalid-state or impossible equal-length-copy failures are not represented as
local staging erasure. Zero-length requests do not inspect the cursor or output
region. The metadata model tests these distinctions rather than promising
rollback or a cleanup operation on every return.

## Frames and reproduction

The transition frames are 72 bytes; finalizer and squeezer frames are 168 bytes,
including saved registers. Selected call paths reach `H-8496` for rehash through
fixed finalization, `H-2944` for owner squeeze and `H-5072` for rehash through the
cSHAKE transition. These values are not maximum whole-image depth. Deeper callee
frames and arbitrary OS exception cleanup remain separate obligations, and
enclosing-window reclamation is still required.

```sh
python3 scripts/cryptography/test-windows-enclave-sha3-finalize.py
python3 scripts/cryptography/windows_enclave_sha3_finalize.py \
  release-reports/windows-local-20261004 --mutate
cargo +1.98.1 test --locked --offline -p brynja-hash-sha3 --lib hardened::sponge
python3 scripts/cryptography/test-windows-enclave-sha3-stream.py
```

Nine focused review tests pass on each host, rejecting 3,712 actual body-byte
mutations each. They also reject removed semantic/erasure sequences, weakened
private compiler preconditions and changed call destinations. Parsed reports
match under `release-reports/windows-worker-review-20261005/offline/`.

Nine actual Rust sponge tests pass on Linux. The unchanged worker campaign also
passes seven component tests, one placement test, ten compiled mutant rejections,
628 cSHAKE, 76 NIST, 96 hashlib and 512 retained-rehash cases, plus streamed setup.
This is saved-image review and ordinary-process testing, not a new native enclave
run or independent retest. No production code or release-gate policy changed.
See the [remaining checklist](windows-v02450-remaining.md).
