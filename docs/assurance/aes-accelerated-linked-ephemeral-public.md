# Accelerated AES: bounded x86 per-operation public-output review

This v0.27.3 development slice reviews the full `public128`, `public192` and
`public256` package-external fixture functions. Each calls the corresponding
operation-local `Aes*Key::encrypt_block_public`; that library body is inlined
into the fixture boundary. The fixture uses `inline(never)` and opaque arguments
to retain a reviewable operation boundary. Production code and its inlining
policy are unchanged. This does not qualify arbitrary downstream inlining,
constructors, destructor entry points, ARM callers or whole programs.

```sh
brynja-verify run aes --needed --category aes-linked-ephemeral-public
```

Both pinned compilers build and execute direct/facade consumers with abort and
unwind profiles: opt3, fat LTO, one codegen unit, overflow checks and static
x86 AES-NI admission. Packaging and offline dependency graph checks are shared
with the other accelerated campaigns. The runner retains executable hashes,
tool hashes, disassembly, symbols, relocations, execution logs and review JSON
under `target/aes-accelerated-linked/`. Capture-only output is never a pass.

## Inspected data and control flow

The operation's inputs are an opaque key-owner reference, a 16-byte input and
a mutable 16-byte destination. The caller's destination is not pre-cleared.

1. Check authority health, saved generation and selected kernel before reading
   the owned key or creating a schedule. Initial rejection returns without
   modifying output or unnecessarily quarantining an already-rejected session.
2. Zero the entire temporary schedule at stack offset 16: 176, 208 or 240 bytes.
   Check that the owned key pointer is present and its length is exactly
   16/24/32 bytes before passing it to matching-width hardware expansion. A
   missing or wrong-length region clears the entire schedule and quarantines
   the authority, without reading key bytes or writing output.
3. Recheck health, generation and kernel after expansion. A rejection clears
   the whole schedule, quarantines the authority, and returns without writing
   output. Only the successful path stages the input at stack offset zero.
4. Call the matching AES-NI kernel with the public direction argument zero
   (encryption). Only after that call returns does one 16-byte vector store
   publish the staged ciphertext to the caller's destination. Clear staging
   and the entire schedule before returning success. There is no portable
   block-encryption fallback and no public decryption path.

Branch conditions in these wrapper bodies use public authority metadata,
region presence, length and post-expansion admission, not key bytes. Width variants change
frame allocation, zero-initialization stores, cleanup lengths and local branch
offsets; each entire variant has its own text and encoding policy. The compiler
versions use different Result layouts; the success/error discriminants are
retained exactly rather than normalized away.

The frames are 192/224/256 bytes for AES-128/192/256; staging and schedule
regions do not overlap. Unlike the secret-output wrappers, these inlined public
callers still invoke the round kernel directly rather than an outlined session
method. The accepted kernel selector is x86; older compiler comparisons rely
on the typed two-variant enum invariant, not arbitrary corrupted byte values.

Rust 1.90.0's unwind stream includes separate entry paths for expansion and
round-call failure: both quarantine and clear the schedule, while the latter
also clears live staging. Both resume through the checked PLT/GOT import.
There is no output store on these paths. This binds the emitted pads, not exception-table
dispatch or the unwinder's implementation. The 1.99.1 bodies have no such pad;
their abort/unwind layouts are separately pinned. No cleanup on process abort,
register erasure, spill erasure or physical fault resistance is claimed.

## Dependency and negative controls

Every binary replays the existing [per-operation secret and expansion
review](aes-accelerated-linked-ephemeral.md) and [cached public
review](aes-accelerated-linked-public.md). Those include cached secret callers,
hardware expansion, six outlined secret-path session bodies, matched round
kernels, copying and volatile clearing. The actual-width expansion bodies are
bound to each public wrapper separately. There is no scalar-inverse dependency
on this accelerated path. Dependency policies are replayed, not learned from
the executable under test.

| Compiler / panic | Instructions (128/192/256) | Bytes (128/192/256) | Public-wrapper mutations rejected |
|---|---|---|---:|
| 1.90.0 / abort | 96 / 98 / 100 | 350 / 366 / 382 | 1392 |
| 1.90.0 / unwind | 117 / 119 / 121 | 450 / 466 / 482 | 1755 |
| 1.99.1 / abort | 98 / 100 / 102 | 353 / 369 / 385 | 1407 |
| 1.99.1 / unwind | 96 / 98 / 100 | 349 / 365 / 381 | 1389 |

Each instruction is mutated individually. Each encoded byte is also changed
with its matching executable byte, so the test cannot succeed merely by
noticing a file/disassembler disagreement. All mutations must fail. Symbols,
extents, executable mappings, local branches and actual call destinations are
validated; no unrecognized call is admitted. Unit tests exercise wrong-width
callees, extra/missing callees, malformed/overlapping/duplicate symbols,
unsupported modes and dependency rejection. Synthetic streams only exercise
test-local policies and are explicitly rejected by every production policy.
There is no automatic policy refresh.

The executable still checks six positive operations per width against known
answers. Both public-output owner forms are now also exercised after quarantine
with prefilled output that must remain byte-identical. Secret-output rejection
and both constructor-rejection clearing checks remain active. These behavioral
checks do not replace machine review of constructors or destructors.

The remaining platform, lifecycle, native timing and performance work stays in
the [development work list](aes-acceleration-development.md). This is a bounded
local observation, not signed certification evidence or release approval.
