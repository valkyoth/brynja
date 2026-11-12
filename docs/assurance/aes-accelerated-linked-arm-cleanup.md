# Accelerated AArch64 linked cleanup review

This development slice checks the complete volatile-clear helper and the two
destruction bodies retained in the packaged AArch64 ELF consumer. It replays
the [three round-kernel checks](aes-accelerated-linked-kernels.md). It is not
native hardware qualification, a review of constructors or operation callers,
or a proof of register/spill erasure. No production Rust changes are needed.

## Reproduction and artifacts

```sh
brynja-verify run aes --needed --category aes-linked-arm-cleanup
```

Four configurations select Rust 1.90.0 or 1.99.1 and static or hosted admission.
Each packages the current sources into isolated direct/facade consumers and
builds abort/unwind profiles: sixteen fresh fat-LTO, opt-level 3,
codegen-units 1, overflow-checked executables. The target is
`aarch64-unknown-linux-musl`; execution uses `qemu-aarch64 -cpu max`, explicitly
not a physical CPU observation. Hosted builds have global AES disabled and use
the existing admitted runtime route; this check does not review that admission
implementation. No timing experiment is run.

The linked runner retains ELF images, full disassembly, symbol tables, graph
metadata, build/execution logs and per-consumer JSON reports under the printed
`target/aes-accelerated-linked/` directory. Reports bind the executable and
inspection-tool hashes. The dedicated marker is
`AES_ACCELERATED_ARM_CLEANUP_LINKED_PASS`, not the kernel-only marker.

## Inspected dataflow

The helper receives the live region pointer in `x0` and byte count in `x1`.
It returns without a store for zero length. Otherwise it decrements the count,
writes a zero byte, advances the pointer by one and repeats until the count
reaches zero. The stores are present in the final executable and are not
replaced by a library call. No branch or address depends on the old secret
contents. The Rust compiler fence is a compiler barrier, not a hardware memory
barrier or a cache flush; no such hardware effect is claimed.

Rust 1.90.0 combines the store and pointer increment in `strb wzr, [x0], #1`.
Rust 1.99.1 uses `strb wzr, [x0]` followed by `add x0, x0, #1`.
The five/six instruction helpers are 20/24 bytes respectively. Every instruction
word and operand, including the local forward and backward branch offsets, is
fixed by an independently reviewed template.

LTO merges the raw-key and cached-key destruction wrappers into the retained
`lifecycle::aes128::destroy_key` body. Returned secret blocks retain a separate
`lifecycle::destroy_block` body. Their instruction streams are identical within
each compiler/panic profile, apart from relocation to the same clear helper.
The usual three-instruction form tests the optional owned pointer, tail-branches
to the clear helper when non-null and otherwise returns. It preserves `x0/x1`.
Rust 1.99.1 unwind retains a six-instruction form: it first tests the public
explicit-clear boolean in `w2`, then follows either of two equivalent pointer
checks and clear edges. Neither form branches on secret contents.

The fixture exercises explicit clear and ordinary Drop for all six key-owner
types, checks their full caller-owned buffers for zeros, and checks both routes
for returned secret blocks. It also executes six known-answer operations per
key width and existing quarantine/rejection checks. This execution coverage is
not an independent machine-code review of every caller that supplies a pointer
or length. Constructors, cached/ephemeral callers, dispatch and expansion need
their separate ARM review. Arbitrary downstream inlining is outside scope.

## Fail-closed checks

`aes_accelerated_linked_arm_cleanup.py` admits only the two compiler endpoints,
the two panic profiles and static/hosted admission. It requires exactly one
clear helper and the two expected retained destruction symbols, in supported
Rust manglings. Duplicate, unknown, empty, unaligned or overlapping bodies fail.
Cleanup bodies and round kernels must also be mutually disjoint.

Disassembled bytes must match the ELF's uniquely mapped, file-backed,
read/execute AArch64 ranges. The decoder must cover the whole symbol extent in
four-byte instructions. Local branches have exact encodings and exact numeric
and symbolic destinations. The external tail branch is encoded from the
actual clear-helper address, with signed B-range and alignment checks. The
clear body itself is reviewed before its callers: a matching symbol name or a
valid branch address is insufficient. No instruction or operand is wildcarded,
and there is no automatic policy refresh.

Each real executable undergoes one textual mutation per cleanup instruction
and one encoded-byte mutation per byte, with the ELF changed consistently for
the latter. All must fail specifically at the exact-stream check:

| Compiler/profile | Clear bytes | Each destruction body | Rejected cleanup mutations |
| --- | ---: | ---: | ---: |
| 1.90.0 abort/unwind | 20 | 12 | 55 |
| 1.99.1 abort | 24 | 12 | 60 |
| 1.99.1 unwind | 24 | 24 | 90 |

The replayed kernel checks reject another 570 mutations per executable.
Regression tests independently pin literal clear/destruction bytes and decode
branch destinations, reject a changed clear store behind valid call edges,
and cover symbol population, mapping, extent, branch annotation, configuration,
dependency ordering and registry scope. Synthetic fixtures test the reviewer;
they do not constitute approval of a production build.

The bounded result does not establish exception-table dispatch, clearing on
abort, protection against `mem::forget`, compiler spill/register cleanup,
power/EM resistance or physical-fault detection. It adds no publication gate,
HSM requirement or deployment profile. Remaining work is tracked in the
[acceleration development record](aes-acceleration-development.md).
