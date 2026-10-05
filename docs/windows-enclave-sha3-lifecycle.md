# Saved scalar SHA-3 lifecycle review

This implementation-author review covers cancellation, quarantine, active-state
destruction and page teardown in the saved `sha3/mod.rs::open` development image.
It extends the [worker boundary review](windows-enclave-worker-reconciliation.md),
not the supported platform claim. It is **not** complete SHA-3 worker qualification,
independent retest or an arbitrary OS-exception guarantee. No production code,
saved enclave image or release-gate policy changed.

The [observation](../assurance/windows-protection-observations/sha3-lifecycle-review-20261005.json)
binds exact object/image identities, reviewer sources and identical parsed
Linux/Windows reports. Six complete bodies and relocations are pinned;
separately tested instruction shapes, call destinations, table relocations and
erasure-range coverage preserve the reviewed interpretation. These checks
detect drift; they are not independent cryptographic proofs.

## Cancellation and quarantine

Cancellation admits only Setup, SetupRetained, Streaming, Squeezing, RetainedMore
or RetainedFinal. A nonzero requested sequence must equal the stored sequence
plus one. Although the machine addition wraps, the separate zero rejection
prevents rollover from `u64::MAX`. Success stores the new sequence, clears active
state and output, and returns to Empty. Invalid phases or sequences also clear,
but set Quarantined and retain the old sequence.

Quarantine and owner clearing call the actual state destructor at owner offset
1,024, replace its discriminant with Empty, erase the full 1,024-byte output
region and reset width, last-bit and algorithm metadata. Quarantine also sets
phase 7. Neither resets the sequence. The worker's actual calls to these bodies
and the receiver's cancellation call are bound to the same linked image.

## Active state destruction

The eight-entry linked table selects Empty, four fixed-hash variants, two XOF
variants and the first setup variant. The valid remaining setup discriminant
takes the adjacent default branch. This assumes a valid initialized Rust enum,
not arbitrary memory corruption.

Fixed-hash workspaces begin one byte after the state tag; SHAKE/cSHAKE workspaces
begin two bytes after it. Setup variants contain an optional workspace at offset
84. When present, setup destruction wipes it before dropping the Option, causing
a second wipe before storing None. It also volatile-clears the pending secret
byte. Declared-length counters and other public setup metadata use ordinary
stores; those stores are not called volatile erasure.

The shared sponge wipe covers thirteen regions whose union is all 1,040 owned
bytes: lanes, partial input, three length fields, domain/phase, suffix/padding/
squeeze staging and permutation scratch. All twelve calls and the final tail
jump reach the exact volatile byte clearer. Missing, overlapping or shortened
regions and changed callees fail the checker. The variant table is checked in
both COFF and linked image.

## Storage and stack limits

Active clearing does not erase all inactive enum bytes or owner padding. The
worker performs typed destruction, clears its live pointer and volatile-clears
the entire 4,096-byte owner page. This enclosing teardown is part of the boundary.

On the selected cancellation/setup-destructor path, with `H` the protected
64-KiB window's high address, cancellation reaches `H-1584`, sponge wiping
reaches `H-1696`, and the non-tail clearer entry reaches `H-1704`. Destructor and
wipe tail jumps restore their frames first. Saved caller registers still depend
on full-window clearing. This is **not maximum whole-image stack depth**; other
operations, constructor/finalizer copies and deeper callees remain open.

## Reproduction and results

```sh
python3 scripts/cryptography/test-windows-enclave-sha3-lifecycle.py
python3 scripts/cryptography/windows_enclave_sha3_lifecycle.py \
  release-reports/windows-local-20261004 --mutate
```

Ten focused tests pass on Linux and Windows with matching parsed reports. Each
host rejects 774 actual body-byte and 32 table-byte mutations. Tests also cover
sequence boundaries, valid destructor variants, erasure coverage, incoming and
cleanup calls, page teardown and scope limitations independently of body hashes.

The existing scalar SHA-3 Linux component campaign passed: seven component tests,
one placement test, ten compiled mutants rejected, 628 cSHAKE, 76 NIST and 96
hashlib cases, 512 retained-rehash cases and streamed setup. This is ordinary-
process execution, not a new native enclave run. Saved-artifact reports remain
outside Cargo target directories in
`release-reports/windows-worker-review-20261005/offline/`.

Next are the remaining SHA-3 operations, distinct accelerated/family workers and
runtime/whole-image reconciliation. See the [checklist](windows-v02450-remaining.md).
