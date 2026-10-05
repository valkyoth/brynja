# Saved scalar streamed cSHAKE setup

This implementation-author review covers six emitted streamed setup bodies:
`push`, `bits` and `advance`, each at rates 136 and 168. It extends the
[owner-operation review](windows-enclave-sha3-operations.md) and connects to the
reviewed [sponge updates](windows-enclave-sha3-update.md) and
[transfer helpers](windows-enclave-sha3-transfers.md). It does not qualify scalar
permutation internals, complete runtime behavior or the whole image.

The [specification](../assurance/windows-protection-observations/sha3-setup-20261005.json)
pins all six bodies, relocations and unwind frames. The
[observation](../assurance/windows-protection-observations/sha3-setup-review-20261005.json)
records matching Linux/Windows saved-image reports. Actual incoming owner calls
and outgoing helper addresses bind the rate-specific bodies. Push and bit-packer
pairs differ only in their rate-specialized symbols; advancement has genuinely
different frame/remainder code and is inspected separately, not normalized away.

## Input, phase and cleanup

Push checks the required setup phase, checked subtraction from the declared
remaining bit count and the complete-byte source extent. Byte-aligned pending
state uses the bulk update path; unaligned state concatenates bits through the
owned one-byte pending buffer. A partial final source byte is accessed only
within the typed input extent. The remaining length commits only after input
absorption, and advancement must also succeed before the operation is complete.

Every returned push failure enters the setup cleanup path: wipe any present
sponge, remove the optional owner, volatile-clear the pending byte, reset used
bits and all four public length counters, clear customization and mark the setup
dead. The emitted option teardown can call the sponge wipe twice; both calls
are bound to the reviewed eraser. A failed setup cannot be reused.

The inner bit helper checks width 1–8 and pending use below eight. Each transfer
is bounded by both remaining source bits and available pending capacity. A full
pending byte is flushed only after checked emitted-count addition and owner
presence checks. Successful update clears that byte before committing the count
and resetting use. Inner failures can retain partially accumulated data: the
enclosing operation, not the bit helper, owns failure cleanup. The tests preserve
this distinction instead of asserting a nonexistent local wipe.

## Advancement and public lengths

Nonzero remaining input prevents advancement. Exact name completion emits
`left_encode(custom_bits)` and switches to customization. Exact customization
completion flushes a pending byte, zero-pads to a rate multiple and requires
the emitted count to equal the precomputed expectation before marking complete.
All emitted-count additions are checked. The encoded public length and the
168-byte public zero buffer reuse stack storage at different points.

Rate 136 computes the remainder inline: split off the low three bits, fold the
remaining limbs modulo 17, then use reciprocal multiplication for division by
17. The instruction-shaped model agrees with Python modulo across 100,000 seeded
128-bit values, low values and power-of-two/maximum boundaries. This differential
check supplements inspection; it is not an exhaustive proof over all 128-bit
values. Rate 168 calls the same linked `__umodti3` address already identified by
the owner review. Its operands are declared public setup counts; the runtime
helper's internals remain a separate, explicit obligation.

Private typed-input validity, canonical partial bits and initialized owned
pending storage are preconditions. These checks do not admit fabricated private
ABI calls or prove caller-supplied data provenance.

## Frames and validation

Push frames are 120 bytes, bit-helper frames 104, and advancement frames 344/376
for rates 136/168. Selected setup-chunk paths reach `H-2384`/`H-2416` at sponge
update. The overlapping public encoding/padding slot starts at `H-2096` on both
paths. These are selected paths, not maximum whole-image depth; enclosing-window
clearing remains responsible for caller copies and stack reuse. Arbitrary OS
exceptions are outside this normal-return inspection.

```sh
python3 scripts/cryptography/test-windows-enclave-sha3-setup.py
python3 scripts/cryptography/windows_enclave_sha3_setup.py \
  release-reports/windows-local-20261004 --mutate
cargo +1.98.1 test --locked --offline -p brynja-hash-sha3 --lib hardened::cshake::setup
```

Eight focused review tests pass on each host; each rejects 2,537 actual body-byte
mutations, plus changed relocations, semantic/clearing sequences, call targets
and frame extents. The bit-packer model is checked against independent bit-list
concatenation for every source byte, pending offset and valid width. Overflow,
missing-owner and update-failure cases retain the modeled pending data until
outer cleanup.

Four actual Rust setup tests pass on Linux: fragmented domains against contiguous
references, successful/failed source-erasing completion, error/unwind terminal
cleanup and corrupted completion-shape rejection. This adds no production or
release-gate changes, fresh native enclave run or independent retest. See the
[remaining checklist](windows-v02450-remaining.md).
