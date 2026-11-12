# Accelerated AES: bounded x86 constructor and destruction review

This v0.27.3 development slice reviews six package-external constructor bodies
and the two retained destruction bodies in the accelerated linked fixture.
It covers AES-128/192/256 operation-local and cached owners, plus the shared
returned secret-block owner. Production Rust and its inlining policy are
unchanged. These are exact named compiler/profile observations, not a promise
about arbitrary downstream inlining or whole-program erasure.

```sh
brynja-verify run aes --needed --category aes-linked-lifecycle
```

Each compiler endpoint (1.90.0 and 1.99.1) builds and executes four packaged
direct/facade consumers with abort/unwind, opt3, fat LTO, one codegen unit and
overflow checks. Static x86 AES-NI admission is required. Archived source and
dependency-graph checks precede offline builds. Complete executable/disassembly,
symbol, relocation, tool identity, execution and review records remain under
`target/aes-accelerated-linked/`. Capture-only runs cannot report a review pass.

## Constructor inspection

`lifecycle::aes{128,192,256}::new_key/new_cached` receive opaque authority,
raw-key and caller-storage arguments. All six complete bodies are pinned.

- Every constructor clears the entire destination before inspecting authority
  health and kernel selection. On admission rejection it emits an error
  representation, clears the destination again and returns without reading the
  raw key. The raw-key form uses a validated tail jump to the volatile zeroizer
  on this exit; it does not skip cleanup after restoring its frame.
- Successful raw-key admission snapshots the generation and copies exactly
  16/24/32 bytes through the reviewed core copy helper. The returned owner stores
  the admitted authority, generation, destination pointer and exact length.
- Cached construction zero-initializes a complete 176/208/240-byte stack
  schedule and passes the typed raw-key pointer to matching reviewed hardware
  expansion. It then rechecks authority health, the captured generation and
  kernel selection. Success copies the entire schedule to caller storage,
  clears the temporary schedule, then stores authority/generation and the full
  destination pointer/length in the returned owner.
- Post-expansion admission failure emits an error, clears the temporary schedule,
  quarantines the authority and clears caller storage. It cannot retry through
  another backend. Rejected initial admission does not itself quarantine an
  otherwise unchanged authority.

Raw-key constructor streams remain unchanged and identical between panic
profiles for each compiler. Cached construction now has a distinct 1.90.0
unwind stream: its emitted landing pad quarantines, clears the entire temporary
schedule, clears the entire caller destination, preserves the exception pointer
and calls a validated `_Unwind_Resume` PLT/GOT import. A second quarantine check
does not re-quarantine an already disabled authority. No exception-table
dispatch proof or cleanup after process abort is claimed. The 1.99.1 cached
streams are identical between profiles and contain no such pad.

The cached constructor's stack frame is exactly 176/208/240 bytes, initialized
with complete vector stores. Its typed input is already a fixed-size array;
there is no dynamic key-length argument to hardware expansion. Post-expansion
rejection leaves the returned owner empty and branches through complete
destination clearing. Only success copies the schedule and publishes the full
owner descriptor. The expansion/copy/clear callees are replayed from reviewed
policies. Branches depend on authority metadata, not key bytes; the older
compiler's kernel comparisons assume the typed enum invariant. This does not
add fault detection or prove behavior after arbitrary memory corruption.

| Constructor | Instructions (128/192/256) | Bytes (128/192/256) | Calls / tail edges |
|---|---|---|---|
| Raw key | 49 / 49 / 49 | 146 / 146 / 146 | 2 / 1 |
| Cached schedule, both compilers abort and 1.99.1 unwind | 92 / 94 / 96 | 349 / 365 / 381 | 6 / 0 |
| Cached schedule, 1.90.0 unwind | 109 / 111 / 113 | 424 / 440 / 456 | 9 / 0 |

Compiler-specific authority tests and error discriminants remain in the exact
text and byte policies. Width-specific copies, schedule initialization and
cleanup sizes are not wildcarded. Actual decoded direct-call and tail-jump
destinations must bind to the expected reviewed helpers and matching expansion.

## Retained destruction bodies

LTO merges the six source-level key destruction wrappers into the retained
`lifecycle::aes128::destroy_key` body. `lifecycle::destroy_block` remains a
second body. The exact eight-symbol population (six constructors plus these
two destruction bodies) is required; unexpected merging/splitting or symbols
fail review rather than being silently accepted.

For both 1.90.0 profiles and 1.99.1 abort, each destruction body is ten bytes:
test the owned-region pointer; if non-null, conditionally tail-jump to the
volatile zeroizer; otherwise return. The original pointer and length arguments
are preserved. In 1.99.1 unwind, each body is 24 bytes: it retains the public
explicit-clear selector, but both arms still pass the unchanged pointer and
length to the same zeroizer, with a null-region return. Explicit `clear()` and
normal `Drop` therefore reach the same complete-region clearing operation.

These tiny streams use an independently specified instruction/byte template,
including exact local branch displacements and checked rel32 edges to the
file-backed executable zeroizer. The general instruction observer is **not**
relaxed to allow arbitrary conditional external jumps. The zeroizer itself is
rechecked by the prior dependency review.

This reviews the retained bodies, not every call site in the larger fixture
functions. Runtime coverage checks both source destruction choices for all six
owner types and for secret output; constructor policies bind the region lengths
that those owners retain. An empty optional region does not imply a valid new
empty key: all public constructor storage types have fixed nonzero size.

## Execution and rejection controls

The fixture retains its six positive encryption/decryption operations per width.
Additional lifecycle checks exercise both explicit clear and normal Drop for
raw-key/cached owners, consume a known-answer secret block through each
destruction choice, and verify every byte of caller storage is zero afterward.
Both constructor forms are called again after quarantine with prefilled
destinations; rejection must clear them. Public rejection still preserves output.
Opaque arguments prevent the fixture from replacing these operations with
compile-time constants. These are ordinary execution checks, not physical fault
or injected-unwind observations.

Every constructor instruction and byte is independently mutated, totaling 1962
controls per executable, or 2238 for 1.90.0 unwind. Both destruction bodies add
26 controls, or 64 for 1.99.1 unwind. The required lifecycle totals are 1988 for
either abort profile, 2264 for 1.90.0 unwind and 2026 for 1.99.1 unwind.
Encoded mutations also
change the matching executable byte, avoiding rejection solely from a
file/disassembler mismatch. Unit tests separately check symbol population,
overlap, helper binding, executable mapping, instruction partitions, modes,
dependency failure, profile separation, mandatory unwind-import binding and
literal branch encodings. Synthetic constructor streams
are rejected by all production policies; test-local policies only exercise the
validation machinery. There is no policy-learning or refresh option.

The [public operation review](aes-accelerated-linked-ephemeral-public.md) and
its entire previous operation/expansion dependency review are replayed in each
binary without refreshing those policies. Source and fixture changes must
still pass fresh real builds. ARM lifecycle, broader admission/platform review,
native timing, performance and compiler-copy/spill limitations remain in the
[development work list](aes-acceleration-development.md). No release gate,
physical-security requirement or certification claim is added here.
