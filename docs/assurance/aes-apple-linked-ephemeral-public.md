# Apple retained per-operation public AES callers — v0.27.3 development

This extends the [cached-caller review](aes-apple-linked-cached.md) to the
three retained fixture wrappers that inline public encryption with
`Aes128/192/256Key`. These paths expand a temporary schedule for each operation.
It is not a review of every call site or the ephemeral secret-output callers.

## Inputs and replay

The same sixteen executables from the
[native Apple capture](../../assurance/aes-native-observations/v0.27.3/apple-linked-capture-20261111.json)
are used: Apple M2 Pro, Rust 1.90.0/1.99.1, direct/facade consumers,
static/hosted admission and abort/unwind. No executable is rebuilt or run,
and no timing measurements are collected.

```sh
python3 scripts/aes/check-aes-apple-linked.py RETAINED_EXECUTABLE \
  --sha256 CAPTURED_BINARY_SHA256 --review-ephemeral-public \
  --compiler 1.90.0 --panic unwind --admission hosted
```

The configuration must match the capture. Hash checking precedes parsing;
failed identity, missing/conflicting configuration or failed dependency
checks prevent success JSON. The
[review record](../../assurance/aes-native-observations/v0.27.3/apple-ephemeral-public-20261111.json)
binds reviewer hashes, captured source/binary identities, function extents
and results. This is an unauthenticated observation of the captured working
tree, not certification evidence. Earlier records retain their original
reviewer identities; updating the CLI does not rewrite those records.

## Reviewed paths

The explicit instruction templates in
[`aes_apple_linked_ephemeral_public.py`](../../scripts/aes/aes_apple_linked_ephemeral_public.py)
were derived from whole-body inspection. They cover exact instructions,
local branch destinations, register assignments and stack extents. Expansion,
transform and zeroizer calls bind to independently reviewed functions in the
same executable, including their key width. No instruction or call target is
accepted merely because it appeared in the submitted executable.

The caller checks authority health, generation and admission, initializes
the complete 176/208/240-byte temporary schedule, and requires a present raw
key pointer with exactly 16/24/32 bytes. After expansion it rechecks health,
generation and admission before transforming any block. The safe Rust
ownership contract supplies valid storage; these checks are not validation
of arbitrary pointers or corrupted process memory.

Only after revalidation does the caller stage the input in 16-byte scratch
storage. The transform receives an explicit encryption selector. Public
output is written only after the transform returns; block scratch and the
entire temporary schedule are then cleared through the reviewed zeroizer.
Rejection paths do not write the public destination. Where a schedule has
been initialized, failure clears it and leaves the authority quarantined.

The Rust 1.90.0 unwind layout includes distinct retained landing-pad entries
for expansion and block transformation. The block path clears scratch and
schedule; the expansion path clears the schedule. Quarantine, preservation
of the exception argument and the bound static unwind import are checked.
This reviews pad instructions, not exception-table dispatch, Apple's loader
or system unwinder. Smaller current-compiler bodies are checked separately;
they do not establish cleanup for arbitrary replacement callees that unwind,
asynchronous faults or process aborts.

## Results and controls

All **48 public caller bodies across 16 binaries** match. Dependency replay
also checks 96 cached callers, 96 constructors, 16 copy helpers, 96 session
bodies, 48 cleanup bodies, 96 AES bodies and applicable static unwind imports.
Flipping one bit at every byte position in the actual caller bodies produced
**24,320 rejected mutations**. Altered executables were never run, and the
original executable hashes were rechecked after mutation testing.

Eight new regression tests cover all compiler/profile/admission/width
combinations and **12,160 synthetic byte mutations**, exact raw-key lengths,
post-expansion revalidation, encryption-only selection, publication order,
both clearing lengths, retargeted calls, corrupted dependencies, symbol
population, unwind handling and CLI identity/configuration failures.
All **885 integrated tooling tests** pass.

## Still separate

Ephemeral secret-output callers, other call sites and Apple startup/platform
lifetime admission remain unfinished. Prior timing alarms remain recorded.
This does not establish physical fault/power/EM protection or register/spill
erasure, and adds no production code, dependencies or publication gate.

The later [ephemeral secret-output review](aes-apple-linked-ephemeral-secret.md)
covers the retained shared encrypt/decrypt callers separately.
