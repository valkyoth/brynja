# ARM crossover caller and timer review — 2026-11-12

This is a bounded, offline manual review of the two retained crossover
executables, not an executed timing observation or a constant-time approval.
It completes the caller/timer inspection prerequisite in the
[crossover design](aes-slot-crossover-design.md). A concrete host/run declaration
must still be frozen before sampling. The four earlier non-noise ARM alarms
remain open.

## Exact artifacts

The [correctness record](../../assurance/aes-native-observations/v0.27.3/crossover-fixture-correctness-20261111.json)
identifies the source archives, generated fixture, tests, oracle checks and
complete disassemblies. Both binaries use fixture SHA-256
`f759f123e4e319fbf9d0476aeeebf0ffe9e09884117a796b48f51642bfb0df13`.

| Compiler / retained directory suffix | Executable SHA-256 | Disassembly SHA-256 |
| --- | --- | --- |
| 1.90.0 / `check-1.90.0-direct-54r30qhe` | `0050c9f0eb43abe2fb1899d55333e32ee5bebe5a08ac5cad683094ac9ce639b8` | `19b177916a63f11685ba2748fea6af18f1e6573b6a43e969080394439c890e77` |
| 1.99.1 / `check-1.99.1-direct-lhr5i615` | `453e4171a40f00763d635e7245f90293f0e26cbe36e0f5e3f87999db218e4934` | `528ea2b23fc5a84b23d2fe247ece9c392f87fe3ecede3db6939dd2d4fa367494` |

Full demangled assembly is retained in
`target/aes-crossover-native-20261111/<directory-suffix>.asm`. Binaries are under
that directory's `target/aes-accelerated-fixed-random/<directory-suffix>/`.
These are local artifacts, not a durable external evidence archive. Addresses
below apply only to these exact GNU/Linux AArch64 executables.

The earlier exact-body checks matched all six round/expansion bodies per
binary, with 2,610 rejected instruction mutations in total. That automated
result is separate from the manual caller-path review here. The inspectors'
musl-labelled ELF mapping establishes ISA/body mapping, not musl ABI or whole
GNU-process qualification.

## Crossover setup and trial arguments

The measurement `Slots::round` body is `bedc..c2f0` on 1.90.0 and
`af28..b32c` on 1.99.1 (the latter is the `closure#2` specialization).
Both were inspected through their normal cell traversal and failure exits.

- Public pattern bits select the mapping and first class. Each stage copies
  two keys and blocks into slot zero and then slot one; the slot stride is
  48 bytes. The stores are at `c028/c04c/c070/c08c` and
  `b06c/b090/b0b4/b0d0`, respectively. Neither class is always written last.
- The cell's slot is computed from class XOR mapping. The key pointer and
  block pointer (key base plus 32 bytes) are selected from that slot. Address
  comparisons precede the trial calls; mismatch takes an error exit rather
  than substituting a measurement or retrying a cell.
- The indirect trial calls are `c114/c1e8` and `b168/b22c`. They pass the
  authority, public `cached` owner and operation strings, key/block pointers,
  and `measuring = true`. Class and slot are not arguments to the AES trial.
- Elapsed values are stored in class/slot-indexed result cells after return.
  The second mapping is then visited. There are no clock calls in either
  `Slots::round` body. Slot materialization, address validation and result
  bookkeeping therefore lie outside the trial's clock interval.

The source driver prepares the corpus and order before traversal and emits
sample rows after collecting a control's population. This review does not
claim that setup outside a timer has no cache, predictor or environmental
effect on the following operation. Balancing and identical-input controls
investigate some such effects; they cannot eliminate them by assertion.

## Actual measured paths

| Compiler / cached operation | Constructor before timing | Clock boundary / four-operation loop | Selected operation and cleanup |
| --- | --- | --- | --- |
| 1.90.0 / AES-192 decrypt-block | Call `eb74` to expanded-key constructor `129d8` | Start `eb98`; loop bound at `ef30`; elapsed call `ef40` | Public decrypt selection leads to `ed10`, calling `12b58` with direction one. Returned secret output is cleared at `edc4` within the loop. Schedule clearing at `ef68` is after elapsed time. |
| 1.90.0 / AES-256 public-block and public-key | Call `102e8` to constructor `12ec8` | Start `1030c`; loop bound `106a0`; elapsed call `106b0` | Public prefix selection at `103a0..103bc`; state/generation/backend and 240-byte schedule checks precede the block load `10590`. Call `105e8` reaches matched round body `134f8` with direction zero. Public copy `105f8` and scratch clear `105fc` are timed; schedule clear `106d8` is not. |
| 1.99.1 / AES-192 decrypt-block | Call `e624` to constructor `115a4`, then `e670` to cached timer `9850` | Start `987c`; loop bound `9e9c`; stop `9ea8` | Public mode dispatch reaches `9a60`, calling secret method `11474` with direction one. Returned secret output clears at `9b18` inside the timer; schedule clear `e720` follows timer return. |
| 1.99.1 / AES-256 public-block and public-key | Call `ec54` to constructor `11a98`, then `eca0` to cached timer `a804` | Start `a830`; loop bound `ae50`; stop `ae5c` | Public prefix comparison at `a8d8`; state/generation/backend and 240-byte schedule checks precede staging `a9c8`. Call `ab14` reaches matched round body `11e84` with direction zero; public copy `ab24` and scratch clear `ab28` remain timed. Schedule clear `ed50` follows timer return. |

The two public modes share the same AES-256 successful measured path; their
input corpora differ. Public-key still constructs the schedule before the
clock, so this experiment does **not** measure expansion latency. Expansion
may nevertheless affect the subsequent machine state.

The complete AES-192 secret methods `12b58..12c84` and `11474..115a0`
clear the destination first, check public authority/schedule metadata, stage
the 16-byte block, call the matched round body (`13460` / `11d84`), copy the
result and clear scratch. The direction passed on this path is one. Successful
measuring paths skip hexadecimal formatting using the public measuring flag
(`ed4c`, `10618`, `9aa8`, `ab48`). Error formatting is not a retained successful
sample.

The complete clearing/copy helpers at `12250/12264` and `10ce0/10cf8` use
length/offset loops and base-plus-offset accesses. No content-derived branch
or memory index was identified in those helpers or the inspected successful
cached paths. The public mode strings, schedule lengths, owner state,
generation, direction and repetition count account for the decisions inspected.

## Disposition and limits

No caller/timer defect requiring a fixture change was identified in this
bounded review. The two retained binaries can be named in the proposed finite
experiment without rebuilding merely to get different timing results.
Before running, recheck their hashes and the actual host/affinity, then freeze
the finite run list, commands, timeout and analysis policy. If the retained
host or binaries are unavailable, document that rather than silently using a
different build or adding runs.

This is not a complete audit of the loader, clock implementation, syscall
latency, all error/unwind paths, speculative effects, physical side channels,
or arbitrary consumer builds. It does not explain or clear the earlier alarms.
All four conditional comparisons and the identical-input controls remain
required by the design; no post-outcome threshold or sample filtering is added.

On 2026-11-12, SSH to the retained ARM host `13.60.220.169` timed out both
inside and outside the sandbox. No crossover measurement was started. The
native experiment is pending host availability, not failed cryptographic
verification. Publication policy and production code are unchanged.
