# Saved Windows AVX2 SHA-3 inner-chain completion

The `sha3/mod.rs::open_avx2` inner-worker review is complete for the saved
development image. Shared runtime, enclosing stack-window reclamation and
whole-image qualification remain separate obligations. This is an author
review, not an independent retest or production-signing approval. No production
implementation or release gate changed.

The [reviewer](../scripts/cryptography/windows_enclave_sha3_avx2_chain.py) binds
the saved COFF object, assembly, LLVM IR, build manifest and linked image.
All 254 saved source/build inputs still match the checkout. It enumerates
53 main functions and eight cleanup funclets from the actual emitted object;
52 main functions are reached through normal references, while the remaining
operation drop glue is reached through cleanup metadata. All 61 bodies are
bound to their actual image addresses. Missing or additional functions, changed
references and unassigned data fail reconciliation.

The [completion record](../assurance/windows-protection-observations/sha3-avx2-chain-review-20261006.json)
identifies the exact artifacts and reports. The frozen
[body/reference specification](../assurance/windows-protection-observations/sha3-avx2-chain-20261006.json)
records reviewed identity; hashes alone are not a semantic proof. The
[semantic checks](../scripts/cryptography/windows_enclave_sha3_avx2_shapes.py),
source/assembly review and actual behavioral tests supply the complementary
checks described below.

## Complete inner-path accounting

| Group | Normal-return obligation and result |
| --- | --- |
| Worker, decoder, receiver and buffers | Page/window non-overlap, canonical request decoding, matching header snapshots, bounded payloads, exact output identity/shape and one post-construction return dominated by buffer destruction |
| Resident construction, quarantine and drop | Aligned 4096-byte backing page; authority constructed before its borrowing owner; failed KAT clears the page; destruction drops the owner before clearing the complete page |
| Owner admission and operation guard | Exact phase, nonzero monotonic sequence, healthy X86Keccak authority; failures clear/quarantine; successful cancellation clears and permits reuse |
| Begin, setup, setup chunk and completion | Exact algorithm/rate, prefix lengths and arbitrary-bit packing; excess/incomplete setup rejects; intermediate copies remain inside the bounded protected window |
| Update, finish, squeeze and retained rehash | Checked input/output accounting, staged public output, fixed/XOF identity, terminal/continuing phase distinction and complete staging cleanup |
| State construction and transitions | SHA-3/SHAKE/cSHAKE domain separation, empty-N/S SHAKE equivalence, startup kernel KAT, correct rate/width tables and clearing before replacement |
| Engine, prefix and secret-memory helpers | Reproduced opcode, branch and reference checks for 20 identical prior-reviewed bodies; actual calls rebound in this image rather than inferred from source names |
| Session and AVX2 kernel | Health/epoch/kernel checks, exact dispatch, caller scratch wipe and complete opaque round/register-erasure schedule |
| State/core/operation drop glue and eight funclets | Actual drop targets and associated unwind metadata are bound; this does not establish arbitrary Windows exception cleanup |

The three indirect transfers are intra-function dispatches: two in `receive`
and one in `Owner::finish`. Both linked table sections (76 and 16 bytes) are
checked cell-by-cell using their actual subtable bases; every destination stays
inside its reviewed function. There are no unassigned indirect calls.

Immutable object constants must match read-only linked bytes, including rates,
output widths, allowed phases and public KAT values. Mutable `LIVE` metadata
contains only resident pointers/identity, not a hidden cryptographic state.
Private IR bounds include at most 1024 input bytes, algorithms 0–7, a 32-byte
aligned 2048-byte owner, a 608-byte session and a 200-byte state. These are
contracts of the checked decoder and typed callers, not admission for arbitrary
calls into private ABI symbols.

## Authority, output and lifetime boundaries

The baseline C entry guard requires AVX, AVX2, OSXSAVE and the appropriate
XGETBV state before entering the accelerated worker. Its existing instruction-
entry and operation-allowlist mutations were rerun. Authority construction and
the session's public zero-state KAT precede secret input. Authority epoch,
health and exact kernel identity are rechecked on dispatch; revocation never
authorizes a portable fallback.

The worker's 1024-byte payload and 112-byte header are cleared on normal
post-construction returns. Fixed and XOF output staging is cleared on rejection
and completion, and terminal operations clear their owned state. Public export
checks the stored algorithm, output length and terminal flag, then rechecks
authority after the copy callback. A failed callback invalidates retained state;
it cannot retract bytes that an external destination already received.

The resident page keeps authority and owner at offsets 0 and 32 with distinct
lifetimes. Complete-page clearing covers inactive variants and padding as well
as active state. Focused strict-provenance Miri checks the actual placement and
destruction logic using explicit non-cryptographic doubles; it is not an
interpreter run of AVX2 assembly or of the Windows enclave.

## Kernel and Windows ABI cleanup

The complete opaque instruction schedule is checked: input copy, theta,
coordinate-generated rho/pi, five bounded AVX2 chi rows, 24 iota rounds, state
commit, all 576 scratch bytes cleared, and working-register erasure. Round
constants come from the independent LFSR model; the public zero-state KAT is
also recomputed by a small coordinate model. Both match actual image data.

The kernel accesses a 200-byte state and bounded scratch regions. Its last
vector row reads bytes `[440,472)` and `[448,480)`; the scalar tail reads at
472. No stack access or call occurs inside the opaque block. YMM0–YMM3 and
RAX/RCX/RDX/R8 are zeroed, flags are overwritten deterministically, and
`vzeroupper` immediately precedes the end marker. Remaining registers hold
pointers or public constants, not kernel working values.

The Windows prologue reserves 168 bytes and saves incoming XMM6–XMM15 values
before secret work. After erasure, the epilogue restores only those incoming
values; it does not reload a secret kernel result. Those save slots still
require enclosing-window reclamation. The public startup `known_answer` body
also has nonvolatile vector saves. Neither is silently excluded from the frame
inventory or claimed individually erased.

Owner/state construction and retained replacement contain compiler-created
aggregate copies, including 992-byte state copies. Their fixed/aligned frames
are accounted for, but those copies are not all individually erased. The
normal-return whole-window cleanup obligation remains mandatory.

## Local frame contribution and shared work

Every body has a fixed frame contribution recorded. Dynamic alignment is
bounded to 32 bytes, conservatively charging another 31 bytes; tail calls count
as nested calls. The maximum local contribution is 12,276 bytes below worker
entry, or **`H-12380`** with the wrapper offset. Its conservative path is worker,
receiver, retained rehash, state construction, setup, initial KAT and AVX2
kernel. Shared callees are excluded from this arithmetic, not assigned a zero
total footprint. This is not a maximum whole-image depth claim.

These exact saved-image boundaries belong to completion package 8:

| Boundary | RVA | Shared obligation |
| --- | ---: | --- |
| `memset` | 47280 | Runtime frames and enclosing-window reclamation |
| `memcpy` | 45552 | Runtime frames and enclosing-window reclamation |
| `memcmp` | 48208 | Public KAT comparison runtime and frame contribution |
| `__umodti3` | 26880 | Public-length arithmetic runtime and frame contribution |
| `PublicSha3Input` | 30240 | Transport/SDK and loaded-image composition |
| `PublicSha3Output` | 30624 | Transport/SDK and loaded-image composition |
| `PublicSha3Source` | 30784 | Transport/SDK and loaded-image composition |
| `PublicSha3Observe` | 30560 | Transport/SDK and loaded-image composition |

The existing C wrapper and transport bindings are reproduced against this same
image. Funclet/xdata identity binding does not qualify `__CxxFrameHandler3`,
arbitrary SEH, fatal aborts or interrupted cleanup. Other workers may reuse
identical bodies only after their own incoming context and linked destinations
are reconciled; this review is not blanket qualification for KMAC or batching.

## Validation

```sh
python3 scripts/cryptography/test-windows-enclave-sha3-avx2-chain.py
python3 scripts/cryptography/windows_enclave_sha3_avx2_chain.py \
  release-reports/windows-local-20261004 --mutate
```

Linux and Windows pass all ten new review tests and produce identical parsed
reports. Each rejects 22,527 actual body-byte and 92 actual dispatch-table-byte
mutations. These counts establish identity sensitivity, not 22,619 independent
semantic proofs. Separate regression cases reject changed kernel instructions,
register restores, constants, indirect destinations, missing destruction,
unbounded frames and changed admission/cleanup landmarks.

Fresh Linux AVX2 component runs pass 11 tests (21 compiled behavioral mutants
and six ownership negatives), five resident/wire tests (25 compiled mutants
and seven ownership negatives), and the serialized worker test (nine Rust
mutants and 18 C-entry-gate mutants). Coverage includes 628 cSHAKE cases,
76 NIST bit cases, 96 hashlib comparisons, 512 retained-rehash cases and 578
fractional-setup cases. The focused placement-only Miri test passes and rejects
three lifetime/provenance mutants. These are component runs, not fresh enclave
qualification; saved Windows native evidence remains separately identified.
