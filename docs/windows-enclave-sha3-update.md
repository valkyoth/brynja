# Saved scalar sponge-update review

This implementation-author review extends the [prefix review](windows-enclave-sha3-prefix.md)
to all five emitted scalar sponge-update rates: 72, 104, 136, 144 and 168 bytes.
These serve the fixed SHA-3 and SHAKE/cSHAKE paths in the same saved development
image. It does not qualify finalization, squeezing or permutation internals.
No production code, native image or release-gate policy changed.

The [observation](../assurance/windows-protection-observations/sha3-update-review-20261005.json)
records source hashes and matching Linux/Windows reports. The
[specification](../assurance/windows-protection-observations/sha3-update-20261005.json)
binds complete instruction bodies, relocations and fixed frames. The reviewer
also checks that the five normalized bodies differ only at the explicitly
reviewed rate constants and division sequences; it does not normalize away the
shared 168-byte backing-buffer bound or stack allocation.

## Admission and absorption

The emitted update first adds the input length to the 128-bit message counter
using carry propagation and rejects overflow before writing owner state. It
then fills any partial block, absorbs complete blocks directly from the input,
and copies only the remaining tail into the partial buffer. Counter bytes are
committed on successful completion. Copies use equal admitted lengths; complete
block loops feed the secret XOR helper with source offset zero, count eight and
destination offset zero. The ignored XOR status is valid under these fixed
arguments and nonoverlapping borrows, not an authorization to ignore arbitrary
helper failures.

This private path assumes the owner invariant `buffered < RATE` and valid Rust
borrows. Its backing-slice check is not a general validator for forged owners.
Rejected counter admission preserves state, but the helper is not described as
transactional for every possible internal failure after earlier absorption.
The previously reviewed caller handles terminal failures and owner reclamation.

The compiler partitions full blocks using unsigned multiply-high/shift sequences,
not hardware division. Their actual instructions and constants are pinned.
Separate regression models compare their results with integer division over
small lengths, power-of-two boundaries, large values, 10,000 seeded random values
and neighboring block boundaries. This is substantial differential coverage,
not an exhaustive proof over all 64-bit lengths. Buffer-partition checks cover
every valid buffered length, all lengths through two rates and large boundaries.

## Cleanup and frames

Each rate has two static permutation call sites: a completed buffered block and
the direct-input loop. Both immediately erase the 40-, 40- and 200-byte
permutation scratch regions. The buffered path additionally clears the entire
168-byte partial-input region and resets its used length. The reviewer checks
the complete ten-site population, erasure lengths and order. Retained sponge
state and an unfinished tail remain live by design until later owner cleanup.

All five update bodies and their actual incoming calls are tied to the saved
image. Their four outgoing destinations are the already reviewed copy/XOR/clear
helpers and the scalar permutation, whose identity is bound but whose internals
are not qualified by this review.

Each update has a 136-byte fixed frame including saved registers. A selected
rehash-to-fixed-finalizer path reaches update RSP `H-8464` and XOR leaf entry
`H-8536`, where `H` is the protected window's high address. The counter, remaining
length and pointer stack slots are inside that window. These slots and saved
caller registers still rely on full-window reclamation. The permutation's entry
and home space are bounded, but its deeper footprint remains open; these values
are not maximum whole-image depth or arbitrary-exception qualification.

## Reproduction and results

```sh
python3 scripts/cryptography/test-windows-enclave-sha3-update.py
python3 scripts/cryptography/windows_enclave_sha3_update.py \
  release-reports/windows-local-20261004 --mutate
cargo +1.98.1 test --locked --offline -p brynja-hash-sha3 --lib hardened::owner
python3 scripts/cryptography/test-windows-enclave-sha3-stream.py
```

Eight focused tests pass on each host; each rejects 3,801 actual body-byte
mutations. Independent-of-hash tests alter semantic sequences, every scratch
erasure instruction, arithmetic partitioning, rate connections and the allowed
normalization. Parsed reports match under
`release-reports/windows-worker-review-20261005/offline/`.

Three actual owner tests pass on Linux, including counter rejection without
mutation. This pass also reruns the four Rust prefix tests and the unchanged
worker campaign: seven component tests, one placement test, ten compiled mutant
rejections, 628 cSHAKE, 76 NIST, 96 hashlib and 512 retained-rehash cases, plus
streamed setup. No new native enclave execution or independent retest is claimed.
See the [remaining checklist](windows-v02450-remaining.md).
