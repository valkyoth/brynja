# Saved Windows scalar SHA-3 inner-chain completion

The scalar `sha3/mod.rs::open` **inner-worker review is complete for the saved
image**, with shared runtime and whole-image obligations explicitly separate.
This is implementation-author assurance, not an independent retest, fresh native
campaign, production-signing approval or whole-image cleanup qualification.

The [chain reviewer](../scripts/cryptography/windows_enclave_sha3_chain.py)
reproduces the existing lifecycle, owner, state, transfer, prefix, update,
finalization, terminal-output and streamed-setup reviews. It then enumerates
every executable section in the actual Rust worker COFF object. All **55 emitted
functions** have a review assignment and are reachable from `RetainedWork`;
every inner reference resolves to the same reviewed image address. Missing,
extra, unreachable and unassigned functions fail the reconciliation. Data
tables remain bound by their existing semantic reviews, not treated as callees.

The saved build manifest also binds 158 source/build inputs. All match the
current checkout byte-for-byte, including the worker, crypto implementation,
manifests and build helper. The [completion record](../assurance/windows-protection-observations/sha3-chain-review-20261006.json)
identifies the artifacts and both reproduced reports. Historical reports retain
their original narrower scope; this composition closes their scalar inner-path
obligations rather than rewriting those reports as whole-image passes.

## Permutation and erasure

The last crypto body is the 795-byte emitted scalar Keccak permutation. The
[permutation reviewer](../scripts/cryptography/windows_enclave_sha3_permutation.py)
checks its entire opaque instruction schedule, not just marker presence:

- All five column parities and theta corrections; all 25 rho/pi placements;
  all five chi columns across five rows; and 24 iota rounds.
- Rotation offsets generated from the coordinate recurrence, and 192 bytes of
  round constants generated independently with the Keccak LFSR. Both object
  data and the actual immutable linked table must match.
- Fixed memory extents: 200-byte state, 40-byte columns, 40-byte theta and
  200-byte rearrangement scratch. Typed exclusive Rust borrows establish the
  disjoint initialized regions; arbitrary private-ABI pointer calls are not
  admitted by this review.
- Complete scratch clearing after the last round, then zeroing of all five
  working GPRs (`rax`, `rcx`, `rdx`, `r10`, `r11`) before return. No stack access,
  call or vector operation occurs inside the opaque block.

The 24-byte compiler frame saves three incoming nonvolatile registers before
secret processing. After erasure the epilogue only restores these saved values
and returns. Those incoming caller values and any caller-created spills still
require the enclosing stack-window reclamation; they are not claimed erased by
this leaf. This scalar body does not use SIMD and needs no AVX transition wipe.
The state is the intended output and remains live until its owner's cleanup.

## Buffer destructor and normal failures

The other remaining body is the 43-byte `Buffers` destructor. Its complete
instruction sequence clears the 96-byte header at offset 1024, then tail-calls
the reviewed volatile clearer for the 1024-byte payload at offset zero. Its
fixed frame is 40 bytes. A finite normal-control-flow check verifies that every
return after buffer construction passes one of the two actual destructor sites:
the common rejection/quarantine path or the completed-operation path.

Earlier owner/state reviews supply cleanup for invalid phase or sequence,
length/accounting rejection, failed absorption, setup completion, finalization,
squeeze and public export. This composition binds those calls to their actual
reviewed bodies. A failed inner setup bit operation need not wipe locally:
the enclosing operation owns its terminal cleanup. Existing worker/oracle tests
and compiled mutants continue to check that distinction. No production behavior
or release gate was changed to obtain this result.

## Local frame contribution and shared boundaries

Every emitted inner frame is recorded. The only saved vector slot in this
population is the already reviewed setup `xmm6` slot at offset 5984 inside its
6072-byte frame. Caller slots are not hidden by a scalar-only label.

Treating even tail calls conservatively as nested calls yields 8464 bytes below
the Rust worker entry, or `H-8568` including the previously reviewed wrapper
offset. The selected conservative chain passes through receive, retained rehash,
fixed finalization, rate-136 finalization and the XOR helper. This is a **local
contribution**, not maximum whole-image depth: external callees are excluded
from this arithmetic, not assigned a zero total footprint. Recursion or an
unassigned inner edge is rejected. Full-window clearing remains required.

The following exact saved-image boundaries are assigned to completion package 8:

| Boundary | RVA | Remaining shared obligation |
| --- | ---: | --- |
| `__chkstk` | 46112 | Probe implementation and complete stack-depth reconciliation |
| `__umodti3` | 41040 | Public-length remainder runtime and its frame contribution |
| `memcpy` | 50928 | Complete shared runtime/caller reclamation composition |
| `memset` | 52656 | Complete shared runtime/caller reclamation composition |
| `PublicSha3Input` | 43872 | Transport/SDK and loaded-image composition |
| `PublicSha3Output` | 44256 | Transport/SDK and loaded-image composition |
| `PublicSha3Source` | 44416 | Transport/SDK and loaded-image composition |
| `PublicSha3Observe` | 44192 | Transport/SDK and loaded-image composition |

Existing memory and transport bindings are reused, not discarded. Assignment to
package 8 does not waive qualification, add a release gate or claim arbitrary
OS-exception cleanup. Accelerated SHA-3 and other distinct family workers remain
their own work; this scalar result is not automatically transferred to them.

## Validation

```sh
python3 scripts/cryptography/test-windows-enclave-sha3-chain.py
python3 scripts/cryptography/windows_enclave_sha3_chain.py \
  release-reports/windows-local-20261004 --mutate
cargo +1.98.1 test --locked --offline -p brynja-hash-sha3 --lib hardened::sponge
cargo +1.98.1 test --locked --offline -p brynja-hash-sha3 --lib hardened::cshake::setup
python3 scripts/cryptography/test-windows-enclave-sha3-stream.py
```

All ten review suites (88 tests total) pass on Linux and Windows. Matching
parsed reports reproduce the nine prior reviews and reject 35,759 body-byte
mutations plus 240 dispatch-table byte mutations per host. Of those, 838 body
mutations cover the newly reviewed permutation/destructor. Byte mutations bind
reviewed identity; separate semantic tests reject changed round schedules,
constants, wipes, return paths, call targets, inventory and frame assumptions.

Linux actual Rust verification passes nine sponge and four setup tests. The
private worker campaign passes seven component tests, one placement test and
ten compiled behavioral mutants, covering 628 cSHAKE cases, 76 NIST cases,
96 hashlib comparisons and 512 retained-rehash cases. This does not replace
the existing Windows native campaign or the forthcoming independent retest.
