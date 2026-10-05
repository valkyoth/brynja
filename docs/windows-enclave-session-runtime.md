# Saved scheduler session and runtime review

This is a selected, author-reviewed extension of the
[root initialization review](windows-enclave-root-setup.md), not whole-image
qualification or a release gate. The
[observation](../assurance/windows-protection-observations/session-runtime-20261005.json)
binds the same saved Rust object and signed scheduler image. No production
source, image or gate was changed, and the completed native enclave/dump
campaigns were not repeated.

## Session entry and kernel return

The 107-byte emitted static `KeccakSession::permute` checks health and generation
before dispatch. For valid kernel enum values in this **AVX2-only image**, Arm
routes return `WrongArchitecture`, the two unavailable x86 SHA routes return
`MissingTargetFeatures`, and only `X86Keccak` enters the permutation. Every
rejection returns before loading or writing caller payload. This is not a claim
about forged enum values, another feature bundle or dynamic CPU revocation.

The successful path calls the exact linked secret kernel, then the previously
reviewed seven-region scratch wipe, then returns success. Its compiled frame
saves RSI and allocates 32 bytes. It has no exception cleanup handler. The
source-level recoverable Rust-unwind test must not be confused with arbitrary
Windows exception cleanup in this optimized image.

The 1,142-byte linked kernel imports 200 bytes into scratch, executes its fixed
24 rounds, commits 200 bytes, clears all 576 scratch bytes, clears YMM0–3 and
its working EAX/ECX/EDX/R8D registers, resets arithmetic flags and executes
`vzeroupper`. The complete 24-entry round table is bound as immutable,
non-executable data. There are no calls or stack accesses inside this opaque
working region; whole-body pins preserve that manually inspected fact. This
extension does not replace the earlier cryptographic differential testing.

**Outside that region**, the Windows ABI prologue saves XMM6–15 in 160 bytes of
a 168-byte frame. The epilogue restores those incoming caller registers without
erasing their save slots. These are not newly computed kernel spills, but they
may contain caller residue. Their normal-return erasure depends on the enclosing
clearing window. The session's later scratch wipe is sequential, not nested
inside the kernel frame. Instruction bytes and decoded unwind records agree on
both frame sizes and all ten vector-save offsets. Relative frame geometry is
not a maximum root-to-kernel stack-depth proof.

## Public remainder and stack probe

The root's actual `__umodti3` target is a 213-byte linked runtime body, not an
import inferred from its name. At this constructor call, both high input words
are explicitly zero; the divisor is the public rate, 136 or 168. The bounded
customization length gives a public numerator of at most 1,043. This selects
the single unsigned 64-bit division path and returns the remainder in XMM0,
without calling another routine. The helper saves/restores RSI and RDI but
does not clear those slots. Its other general-u128 arithmetic paths are byte
bound, not independently established as correct by this selected-path review.

The 78-byte `__chkstk` target saves R10/R11 in 16 bytes and restores them without
erasing those slots. Its constructor call occurs **before** subtracting the
7,672-byte allocation and rounding the frame to 32-byte alignment. The model
places the probe saves at window-high minus 11,488, and the remainder saves at
window-high minus 19,160. Both fit the selected root window.

The probe also reads the stack limit through `GS:0x10` and can write zero to
successive page addresses. Those addresses depend on live OS state and are not
qualified merely by bounding its register-save slots. Guard-page faults and
arbitrary exceptions remain outside a normal-return cleanup guarantee.

## Validation and remaining scope

Ten artifact-free inspector/model tests pass on Linux and Windows. They reject
changed landmarks, branches, reference operands, frame/save declarations,
invalid authority-model inputs, altered round constants and ambiguous, truncated
or writable code mappings. Separately, actual saved-image inspection rejects
all 1,540 single-byte body-pin mutations on each host and produces identical
reports. Pin mutations are review-identity checks, not cryptographic test cases.

The four existing native Keccak unit tests also pass on both hosts under Rust
1.98.1 with `+avx2`. They include 1,024 differential permutations with an explicit
execution marker, scratch clearing, rejected authority and recoverable Rust
unwind/quarantine checks. These are ordinary native process tests, not VBS
exception tests. The previous 240-entry component source closure still matches
on both hosts; the Keccak test source was separately SHA-256 checked.

The next boundaries are `memcpy`/`memset` and their dispatch tables, outer-root
return/SDK reconciliation, and coverage of the other image families. No claim
is added for arbitrary exceptions, fatal termination, caller-created copies,
all SDK storage, other platform builds or production signing.

```sh
python3 scripts/cryptography/test-windows-enclave-session-runtime.py
python3 scripts/cryptography/windows_enclave_session_runtime.py SAVED_OBJECT SAVED_IMAGE --mutate
```
