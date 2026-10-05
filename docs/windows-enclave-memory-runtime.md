# Saved scheduler memory-runtime review

This extends the [session/runtime review](windows-enclave-session-runtime.md)
for the same original scheduler image and object. The
[observation](../assurance/windows-protection-observations/memory-runtime-20261005.json)
binds the root constructor's actual `memcpy` and `memset` targets, their complete
code ranges and two REP tail helpers. It is an author inspection aid, not a new
release gate, native campaign or whole-image qualification.

## Dispatch and storage

The four reviewed ranges total 2,617 bytes. Eight immutable, non-executable
dispatch tables contain 128 four-byte RVAs. Their complete contents, image-base
calculation, index loads and indirect transfers are checked; all targets remain
inside the corresponding reviewed helper. The short-length tables cover 0–15
bytes. The vector-tail tables use only indices 0–8 for valid loop remainders;
the other entries remain pinned but are not evidence of reachable cleanup paths.

The longer copy paths select SSE, AVX, REP or backward copying using public
length/address relationships and mutable runtime feature/threshold selectors.
The fill paths have corresponding scalar, SSE, AVX and REP choices. Four selector
locations are recorded as mutable, non-executable data. Their **live values and
initialization are not proved** by their on-disk bytes. These helpers read those
locations; they do not copy payload into them. No additional function calls or
unreviewed direct callees occur within this selected helper population.

Scalar and vector paths allocate no local stack frame. They copy directly
between the supplied regions or fill the supplied destination. The REP copy
tail saves RSI/RDI in 16 bytes; the REP fill tail saves RDI in eight bytes. These
are tail branches, not nested calls, and their save slots are restored rather
than erased. In the selected root-constructor geometry, the saves start at
window-high minus 19,160 and 19,152 respectively. This accounts for those local
saves, not every caller's lifetime or maximum transitive depth.

**Copying is not register erasure.** The small copy cases leave payload in
volatile GPRs; SSE/AVX copying leaves payload in low vector lanes. AVX returns
use `vzeroupper`, which clears upper halves, not the low 128 bits. Non-temporal
paths use `sfence` before returning through their valid tail paths. The fill
value can also remain in working registers. The enclosing return-boundary
register cleanup and stack-window clear are therefore still required. These
runtime helpers are not interchangeable with the volatile secret clearer.

The main helpers have zero-frame version-1 unwind records. The REP helpers have
version-2 metadata. All exact runtime extents and metadata bytes are bound;
frame sizes above come from reviewed instructions. The existing limited unwind
decoder was **not** expanded or weakened, and no exception-cleanup semantics are
claimed from this metadata binding.

## Checks and limits

Eight focused tests pass on Linux and Windows. The actual-image inspection
rejects 2,617 single-byte body changes and 512 dispatch-table byte changes on
each host, producing identical parsed reports. These are artifact-identity
regressions, not cryptographic comparisons or native execution of the helpers.

The separate forward-vector arithmetic model checks all destination-alignment
residues for 16- and 32-byte widths, lengths 33–1,024, and selected larger
boundary lengths through 65,536: 48,144 combinations. It checks that modeled
head, loop and tail spans stay within the supplied length, cover it without
gaps and select only tail indices 0–8. It does not model arbitrary pointer
wraparound, invalid buffers, the complete backward-overlap algorithm, CPU
feature initialization or OS faults. Whole-file/body binding preserves the
manual instruction review; the model is not a machine-code interpreter or
general proof of `memmove` correctness.

Normal-return caller cleanup, final root/SDK return reconciliation and coverage
of other image families still need completion before independent retest.
Arbitrary exceptions, fatal termination and privileged snapshots remain outside
the promised cleanup boundary. No production code, signed image or release gate
changed; completed enclave and dump campaigns were retained without rerunning.

```sh
python3 scripts/cryptography/test-windows-enclave-memory-runtime.py
python3 scripts/cryptography/windows_enclave_memory_runtime.py SAVED_OBJECT SAVED_IMAGE --mutate
```
