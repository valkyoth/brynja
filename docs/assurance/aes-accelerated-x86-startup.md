# Static x86 startup review

This v0.27.3 development check covers package-external static x86 startup on
Rust 1.90.0 and 1.99.1, direct/facade consumers, abort/unwind, opt-level 3,
fat LTO, one codegen unit and overflow checks. A separately baseline-compiled
host probe must report AES and SSE2 before any target-feature-enabled consumer
is executed. The specialized builds use `+aes,+sse2`. Static deployment still
requires the caller's environment to preserve that ISA contract for its lifetime.
This does not admit hosted x86 selection: its migration guarantee remains absent.

## Inspected complete startup bodies

MSRV emits 185 instructions / 913 bytes; current emits 172 / 845. Both panic
strategies and both package routes match their compiler's policy after validated
relocation binding. Both allocate 296 bytes and preserve the callee-saved
registers. The wrong-backend guard precedes every expansion, comparison and
round call. It returns the None discriminant (2) without a usable authority.
MSRV uses a taken admission branch plus a rejection jump; current branches
directly to the rejection epilogue, with the discriminant preloaded in r14b.

The admitted path constructs sequential public keys of 16/24/32 bytes at RSP
and initializes temporary schedules at RSP+48 with lengths 176/208/240. Three
width-bound expansion calls produce those schedules. Each whole schedule is
compared against its independently fixed reference through bcmp with the exact
length in EDX. Its function pointer is loaded once and preserved in R12 (MSRV)
or R14 (current) across the three comparisons; only afterward is that register
reused. The complete pinned instruction stream fixes this dataflow.

Six width/direction-bound round calls use the fixed expected schedules, not the
just-generated output. Encryption starts from the fixed plaintext; decryption
starts from the corresponding fixed ciphertext, independently of encryption.
Direction operands are zero/one. SSE byte comparisons and mask reductions check
all sixteen bytes of the AES-128/192 answers; current does the same for AES-256.
MSRV uses two immediate 64-bit comparisons for each AES-256 answer instead.
Every schedule and block comparison feeds the final condition: health=1 only
when all match, health=2 otherwise; generation=2. The admitted discriminant is
zero even on quarantine, so startup failure is not mistaken for pre-admission
unavailability. MSRV copies public-answer bytes into padding; that is not a
secret-clearing guarantee.

The fixture checks both backend enums, healthy startup, all three cached-key
round trips and clearing, explicit quarantine and generation advancement.
Opaque caller-key operations retain generic kernel bodies under LTO. Kernel
expansion and round reviews are replayed on each actual linked binary.

## Actual-byte binding and runtime trust

All startup instructions, encodings, local branch destinations, registers,
lengths, directions and state stores are pinned. Only validated RIP/call
displacements normalize. Read-only mappings must contain exact known-answer
reference bytes or the fixed sequential-key halves. References use the same
fixed arrays as the [ARM startup review](aes-accelerated-startup.md), never a
newly learned image hash. Direct kernel calls bind width, symbol, address and
reviewed executable bytes. All instruction and code-byte mutations must fail.
All 720 distinct referenced public bytes also have rejection controls.

The bcmp GOT load is bound through loader-consumed PT_DYNAMIC metadata, not a
disassembler annotation. RELA, SYMTAB and STRTAB pointers must be mapped and
bounded; the slot must have one zero-addend GLOB_DAT relocation to the undefined
global function `bcmp`, and initially contain eight zero bytes in an aligned
writable file-backed mapping. Duplicate slots, PLT relocation conflicts,
alternative REL/RELR tables, malformed names and tables are rejected. The
three register-indirect calls must use the loaded pointer. Synthetic regression
tests exercise malformed metadata and cannot approve production code.

This identifies the runtime dependency, **not** an independent review of libc's
selected bcmp implementation or the loader. Both remain trusted, as does the
OS execution environment. Public KAT comparison need not be secret constant
time; this does not qualify libc comparisons for secret data. Native execution
here is only on the local probed host, not evidence for every planned CPU.

## Executed controls

The unmodified executable must pass first. Then 628 isolated binary copies
each change one public reference byte: all 624 schedule bytes and one byte in
each of four block references. Each must retain an admitted generation-2
quarantined owner, reject its session and print only the required marker.
A crash, healthy result or pre-admission rejection fails the check. Original
binary and inspection-tool hashes are checked after execution. These are
software mutation controls, not physical fault-injection qualification.

```sh
brynja-verify run aes --needed --category aes-linked-x86-startup
```

Capture-only is diagnostic and cannot emit the registered success marker.
No new publication gate, physical protection, spill erasure or timing claim is
introduced. See the [development ledger](aes-acceleration-development.md) for
the remaining native configurations and qualification work.
