# Apple retained cached-key AES callers — v0.27.3 development

This extends the [constructor review](aes-apple-linked-constructors.md) to
the complete retained `Aes128/192/256ExpandedKey` public-encryption and secret
encrypt/decrypt implementation bodies. It is not whole-program approval or
coverage of ephemeral-key callers.

## Inputs and replay

The same sixteen executables from the
[native Apple capture](../../assurance/aes-native-observations/v0.27.3/apple-linked-capture-20261111.json)
are used: Apple M2 Pro, Rust 1.90.0/1.99.1, direct/facade consumers,
static/hosted admission and abort/unwind. Neither the capture nor its binaries
are modified. This review does not rebuild, execute or collect measurements.

```sh
python3 scripts/aes/check-aes-apple-linked.py RETAINED_EXECUTABLE \
  --sha256 CAPTURED_BINARY_SHA256 --review-cached \
  --compiler 1.90.0 --panic unwind --admission hosted
```

The configuration must match the capture. Hash checking precedes parsing;
missing/conflicting configuration and any failed dependency prevent success
JSON. The [cached-caller record](../../assurance/aes-native-observations/v0.27.3/apple-cached-callers-20261111.json)
binds reviewer hashes, capture/source identities, function extents and results.
It remains an unauthenticated observation of the captured working tree. Earlier
records remain historical observations under their own reviewer hashes.

## Reviewed paths

The explicit instruction templates in
[`aes_apple_linked_cached.py`](../../scripts/aes/aes_apple_linked_cached.py)
match complete function bodies. Local branches, register use and constants
are exact. Calls bind to the matching reviewed transform, copy and zeroizer
functions in the same executable; an unchecked symbol name is insufficient.

Both output paths check authority health, generation and admission fields,
then require a present schedule pointer with the exact 176/208/240-byte length.
Malformed schedule state quarantines the authority and returns an error.
The safe Rust ownership contract supplies valid storage; these pointer/length
checks do not validate arbitrary pointers or corrupted process memory.

Public encryption stages the input in a 16-byte scratch block, explicitly
selects encryption, calls the width-matched AES transform, then writes the
result to the caller's public destination and clears scratch. Rejection paths
do not write that public destination. No public decryption path is introduced.

The shared secret encrypt/decrypt implementation first clears the admitted
16-byte destination, before checking authority. It stages the input and selects
the requested direction. Most retained layouts forward the Boolean selector;
Rust 1.90.0 unwind layouts branch to separate calls with explicit 0/1 selectors.
On success, the reviewed copy helper copies exactly 16 result bytes, scratch
is cleared, and the secret owner's pointer/length/discriminant are returned.
Rejection clears the destination through the reviewed zeroizer.

The older compiler's full unwind pads include quarantine and scratch cleanup;
the secret path also clears its admitted destination. The exception argument
and calls to the previously checked static unwind import are bound. This
checks the retained pad instructions, not exception-table dispatch, Apple's
dynamic loader or its system unwinder. Smaller current-compiler bodies are
matched separately and do not prove that arbitrary replacement callees cannot
unwind. No assertion is made about asynchronous faults or process aborts.

## Results and controls

All **96 cached caller bodies across 16 binaries** match. Dependency replay
also checks 96 constructors, 16 copy helpers, 96 session bodies, 48 cleanup
bodies, 96 AES bodies and applicable static unwind imports.
Flipping one bit at each byte position of the actual caller bodies yields
**27,888 rejected mutations**, without executing altered binaries.

Nine new regression tests cover the complete configuration/width matrix,
**13,944 synthetic byte mutations**, public publication after the AES call,
encryption-only public selection, secret clear-before-admission ordering,
direction forwarding, retargeted calls, corrupt dependencies, invalid
profiles/roles, unwind pads/imports and CLI identity/failure handling.
All **877 integrated tooling tests** pass.

## Still separate

Ephemeral-key secret/public callers, all call sites, Apple startup and platform
lifetime admission still need their own review. Prior timing alarms, physical
fault/power/EM protection and register/spill erasure are not closed here.
No production Rust, dependencies, native measurements or publication gates
change in this step.

The later [ephemeral public-caller review](aes-apple-linked-ephemeral-public.md)
covers the retained fixture-inlined per-operation public paths separately.
