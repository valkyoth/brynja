# Accelerated AES: bounded AArch64 constructor review

This development review covers the six package-external raw/cached key
constructors in the final-linked accelerated AES fixture, the complete copy
helper, and their expansion and clearing dependencies. It does not qualify
operation callers, arbitrary downstream inlining, every fixture call site,
exception-table dispatch, native hardware, register/spill erasure, timing or
physical fault resistance. No production Rust changes are part of this step.

Run the independent registered checks with:

```sh
brynja-verify run aes --needed --category aes-linked-arm-constructors
```

The four registrations cover Rust 1.90.0 and 1.99.1, static and hosted admission,
and four fresh consumers each: direct/facade, abort/unwind, release LTO on
`aarch64-unknown-linux-musl`, executed under QEMU. This is emulated ELF coverage,
not a replacement for the planned native Apple/AWS observations.

## Inspected data flow

All three raw constructors clear the entire caller-owned key destination before
checking authority health and the admitted instruction bundle. Hosted admission
also checks its runtime bundle. Success retains the authority and generation,
copies exactly 16, 24 or 32 key bytes, and binds the destination pointer and
length to the returned owner. Rejection stores the error result and tail-branches
to the reviewed clear helper with the original destination and complete extent.

The cached constructors likewise clear the full destination before admission.
They initialize the entire temporary schedule (176, 208 or 240 bytes), call the
matching width's hardware expansion implementation, then re-check authority
health, generation and kernel/admission before publishing the owner. Success copies
the complete schedule to the owned destination, clears the temporary schedule,
and retains the authority, generation, pointer and extent. Post-expansion failure
clears the temporary schedule, quarantines the authority when necessary and
clears the complete destination. Stack frames and saved-register slots differ
by key width; the complete bodies, including those offsets, are pinned.

The temporary schedule starts at SP and occupies 176/208/240 bytes. The frames
are 240/272/304 bytes; saved registers start after the schedule, at SP+176/208/240.
Zero-vector stores cover the entire schedule before expansion; the hardware
routine receives the raw key in x0 and temporary schedule in x1. Successful
copying and every temporary/destination clearing call use the complete extent.
Post-admission errors distinguish unhealthy, revoked-generation and wrong-kernel
states; hosted builds also enforce platform admission. These are typed-enum
checks, not a claim to tolerate arbitrary corruption of authority storage.

The 1.90.0 unwind bodies add landing-pad paths which preserve the exception,
quarantine idempotently, clear the temporary and caller destination, then call
the bound `_Unwind_Resume`. The 1.99.1 bodies have no such emitted calls. This
reviews pad instructions and call edges, not the exception tables selecting them.

The 21-instruction copy helper copies public-length eight-byte chunks followed
by a byte remainder. It clears its transfer/offset/remainder registers and flags
before returning. This is not a claim that all caller registers or prior spill
slots have been cleared. Safe ownership supplies the non-overlap contract.

Compiler-specific boolean tests, register restoration, failure representations
and width-dependent frames are separate policies, not ignored differences.
The reviewed constructor sizes and control-flow populations are:

| Compiler/admission/profile | Raw instructions / local branches | Cached instructions / local branches |
| --- | --- | --- |
| 1.90.0 static abort | 45 / 5 | 95, 96, 97 / 14 |
| 1.90.0 static unwind | 45 / 5 | 129, 130, 131 / 17 |
| 1.90.0 hosted abort | 50 / 7 | 105, 106, 107 / 18 |
| 1.90.0 hosted unwind | 50 / 7 | 139, 140, 141 / 21 |
| 1.99.1 static both | 45 / 5 | 95, 96, 97 / 14 |
| 1.99.1 hosted both | 47 / 6 | 99, 100, 101 / 16 |

Each raw body has two calls and one external clearing tail branch; each cached
body has six calls (twelve for 1.90.0 unwind) and no external tail branch. Separate abort/unwind hashes
are used where emitted bodies differ. Policies were pinned after whole-body
inspection; changed code requires explicit re-review, not automatic refresh.

## Dependency and image binding

The reviewer requires exactly six constructors, one copy helper and three
width-specific hardware expansion bodies, with strict symbol parsing
and non-overlapping extents. It replays the existing
[ARM cleanup and kernel review](aes-accelerated-linked-arm-cleanup.md).
Expansion bodies must pass the [hardware expansion review](aes-accelerated-linked-expansion.md),
including exact executable bytes, complete instruction templates and all-width
negative controls. Width is bound from the checked body, not trusted from a
generic mangled name. Portable inverse/expansion functions are no longer admitted
as cached-constructor dependencies.

MSRV unwind additionally requires exactly one executable, aligned, 184-byte
`_Unwind_Resume` runtime symbol. Its static/hosted image hashes are pinned for
these link layouts, and each byte is independently mutated. It is a trusted
runtime boundary: pinning its bytes does not qualify libunwind or its callees.
The cached-caller reviewer shares this binding rather than keeping a second copy.

Instruction words must match actual executable ELF bytes. Local branches retain
their exact offsets. External call encodings and disassembly annotations must
agree on the exact reviewed helper address and symbol; only these bound
relocations are normalized. The shared portable observer permits an external
`b` only when a caller explicitly supplies an allowed tail-call role. Its
default still rejects external branches. Constructors opt in only to the
reviewed clear helper; an unknown role, wrong encoding, mismatched annotation,
non-executable target or overlapping extent fails closed.

## Regression coverage and limits

Every constructor/copy instruction is independently replaced, and every byte is
independently changed in both the supplied body and the ELF. All controls must
be rejected for the relevant policy/encoding reason. Each consumer rejects
2220 such controls for static admission (2730 for 1.90.0 unwind), 2445 for
1.90.0 hosted abort, 2955 for 1.90.0 hosted unwind, or 2310 for 1.99.1 hosted.
Hardware expansion adds 735 rejections per consumer, and MSRV unwind adds 184
runtime-boundary rejections; cleanup and round-kernel controls are also replayed.

Unit tests cover configuration selection, strict symbol populations, wrong
widths and changed expansion bytes, overlapping extents, exact copy bytes, helper address binding, default
tail rejection, changed B/BL encodings, and failure of a required dependency
before any constructor can pass, plus panic-profile separation and mandatory
unwind-runtime binding. No synthetic test policy is accepted by the
production reviewer. Runtime fixture checks exercise construction, quarantine
rejection, explicit clear and ordinary Drop, but are not an emitted-code proof
of every call site.

This bounded review does not close the remaining accelerated operation-caller,
platform-admission, expansion/performance, native or predeclared timing work.
See [development status](aes-acceleration-development.md).
