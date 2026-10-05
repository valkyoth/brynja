# Saved worker runtime and transport reconciliation

The [2026-10-05 record](../assurance/windows-protection-observations/worker-reconciliation-20261005.json)
records an extended offline author-review pass. It closes scalar SHA-2's
runtime/export connections and binds the other families' entry, transport and
memory-call boundaries. **It does not complete their transitive machine-code
cleanup qualification.** No production code, signed image, native VBS campaign
or release-gate policy changed.

## Connections closed

The [scalar primitive review](windows-enclave-sha2-primitives.md) is reproduced
before connecting all forty emitted Rust memory calls and five transport calls:
source lookup, two input copies, observation and explicit export. Exact caller
bytes, relocations, actual callee addresses, C adapters, SDK thunks and named
saved SDK exports must agree. No C-object memory calls were omitted.

Ordinary memory routines are not volatile erasers. Their payload registers and
saved slots depend on the outer clearing window and return-boundary register
clear. The selected frame extensions fit the 64-KiB window: output adapter
H-2,672, SDK copy H-2,720; the prior primitive chain reaches H-5,416. Live runtime
selector values and application-image loaded-IAT attestation remain separate.
Host copy-out remains nontransactional.

All eighteen sequential images contain the four reviewed memory-runtime bodies.
Rebinding normalizes only twenty enumerated image-relative operands. Complete
bytes, eight read-only dispatch tables, selector placement and raw unwind records
are checked per image. Raw metadata identity is not exception qualification.

The seventeen non-bounded images each have six C adapters: source getter, input,
output, observer, source setup and control readout. Their 102 bodies reduce to
27 distinct byte/relocation templates. Named exports anchor setup/readout; other
leaf bodies use actual relocated global identities. Input/output each have a
complete 40-byte frame. SDK directions and imported identities are checked.

Rust linkage covers all 97 direct transport calls in 36 complete caller bodies,
including KMAC's one-byte comparison output and unrolled SIMD input copies.
The C wrapper's actual worker target and direct selected Rust edges must agree.
Memory linkage covers **590 calls in 175 caller bindings**, using actual runtime
extents, including interior cleanup ranges. One code section is not assumed to
mean one function. Byte-identical KMAC bodies require incoming anchors; associated
xdata is bound without claiming handler semantics. This closes call identity,
not each call's pointer/length or spill proof.

## Source lifecycle review

Saved worker/resident sources match current reviewed bytes. Seven scalar entries
share one lifecycle pattern; ten accelerated/SIMD entries share another.

- Scalar teardown destroys the active owner, clears pointer identity, then
  volatile-clears all 4,096 backing bytes, including padding/inactive state.
  Private admission still relies on the serialized C boundary.
- Accelerated residents place authority and owner in disjoint page regions.
  Constructor failure clears the page. Destruction drops the borrowing owner
  before its authority, then clears the page. Globals hold pointer metadata.
  Repeated admission or page-identity rejection quarantines an existing owner.
- Entries check copied buffers against the admitted window. Failed receive or
  clear/readback observation quarantines the owner. Buffer destructors retain
  early-return cleanup; compiler copies/spills still require the outer clear.
- Stream/sequential receivers decode fixed copied headers and bounded payloads.
  KMAC comparison exports its explicit decision byte. SHA-256/512 SIMD receive
  eight/four ordered messages; Keccak receives up to twelve ordered nonempty
  message/name/customization pieces, skipping empty pieces.
- SIMD cancellation closures are internal, not host callbacks. Construction
  selects the compiled-target revalidator. Source reasoning alone does not prove
  every emitted indirect call's provenance or stack geometry.

| Route | Header bytes | Payload capacity | Entry fixed frame bytes |
| --- | ---: | ---: | ---: |
| scalar SHA-2 / SHA-NI | 48 / 64 | 1,024 | 1,160 / 1,208 |
| scalar SHA-3 / AVX2 | 96 / 112 | 1,024 | 1,208 / 1,256 |
| scalar KMAC / AVX2 | 96 / 112 | 1,024 | 1,208 / 1,256 |
| scalar TupleHash / AVX2 | 96 / 112 | 1,024 | 1,208 / 1,256 |
| sequential SHA-2 batch / SHA-NI | 128 / 144 | 1,024 | 1,240 / 1,288 |
| sequential SHA-3 batch / AVX2 | 288 / 304 | 1,024 | 1,400 / 1,448 |
| sequential ParallelHash / AVX2 | 112 / 128 | 1,024 | 1,224 / 1,272 |
| eight-lane SHA-256 AVX2 | 288 | 8,192 | 8,600 |
| four-lane SHA-512 AVX2 | 160 | 4,096 | 4,376 |
| four-lane Keccak AVX2 | 384 | 12,288 | 12,792 |

Entry allocations include pushes, **not** maximum transitive depth. Inner SIMD
frames can realign the stack and contain indirect dispatch calls.

## Validation and remaining scope

All ten existing accelerated/SIMD worker campaigns passed again on native Linux
x86-64, rejecting 233 compiled worker/transport-gate mutations. SIMD campaigns
passed 402 SHA-256, 602 SHA-512 and 520 Keccak oracle cases. These are ordinary-
process component tests, not new VBS execution or independent review.

Five new offline suites pass 23 tests on each of Linux and Windows. All five
parsed reports match. Byte mutations reject 47,106 memory-body, 9,898 C-adapter
and 39,708 Rust-boundary changes per host. These measure binding sensitivity,
not cryptographic correctness. Other regressions reject malformed archives,
bad operands, omitted/intersecting runtime ranges, wrong frame/image identities
and missing anchors. Full reports, test binaries and logs are local under
`release-reports/windows-worker-review-20261005/`, outside `target/`; the committed
record carries their hashes. The five new developer review scripts are not gates.

Still open: transitive state/owner cleanup, indirect SIMD dispatch and maximum
stack-depth reconciliation inside remaining workers; compiler-runtime comparison,
arithmetic/probing contexts; and live runtime/SDK claim boundaries. Concurrent
ParallelHash retains its prior separate source-bound scope. Independent retest
and final verification follow this reconciliation. No whole-image, arbitrary-
exception, fatal-exit, production-signing or Windows ARM64 claim is added here.
