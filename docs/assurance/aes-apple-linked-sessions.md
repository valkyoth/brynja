# Apple retained AES session functions — v0.27.3 development

This extends the [kernel-body](aes-apple-linked-kernels.md) and
[cleanup-body](aes-apple-linked-cleanup.md) reviews to six complete retained
session functions per executable. It is a bounded offline instruction review,
not whole-program or Apple runtime qualification.

## Inputs and replay

The inputs are the same sixteen native Apple M2 Pro executables in the
[capture record](../../assurance/aes-native-observations/v0.27.3/apple-linked-capture-20261111.json):
Rust 1.90.0/1.99.1, direct/facade consumers, static/hosted admission and
abort/unwind. Original captures and their capture-only status are unchanged.
No rebuilding, native execution or timing collection is performed by this step.

```sh
python3 scripts/aes/check-aes-apple-linked.py RETAINED_EXECUTABLE \
  --sha256 CAPTURED_BINARY_SHA256 --review-sessions \
  --compiler 1.90.0 --panic unwind --admission hosted
```

Supply the configuration from that executable's capture, not a guessed profile.
The runner checks its SHA-256 before parsing, rejects missing/conflicting
configuration, and emits no success JSON on failure. The
[session record](../../assurance/aes-native-observations/v0.27.3/apple-session-bodies-20261111.json)
binds capture/source identities, reviewer hashes, function extents and results.
It remains an unauthenticated observation of the captured working tree.

## Reviewed behavior

The explicit instruction templates in
[`aes_apple_linked_sessions.py`](../../scripts/aes/aes_apple_linked_sessions.py)
cover `Session::encrypt128/192/256` and `decrypt128/192/256`:

- Health checks reject not-ready or quarantined owners before the AES call.
- The permit generation must match the owner's generation.
- Retained execution-authority/admission fields are checked, with the extra
  field present in hosted layouts. This is not a fresh CPU-feature probe or
  proof of the platform lifetime contract.
- Arguments and the encryption/decryption selector match the requested
  direction. The call target is the actual reviewed transform function for
  that key width, not merely a matching symbol name.
- Success and rejection return paths, saved registers and complete extents
  match the selected compiler/profile. No instructions are wildcarded.

Rust 1.90.0 unwind bodies additionally retain a landing pad after the normal
return. Its instructions quarantine the owner, set its terminal generation
and call the bound unwind stub. This checks the pad's bytes, not whether
exception metadata dispatches to it. Rust 1.99.1 has different retained
extents; absence of this pad is not a general proof that arbitrary callees
cannot unwind.

The separate
[`aes_apple_unwind_import.py`](../../scripts/aes/aes_apple_unwind_import.py)
checks the four older-compiler unwind binaries. The strong undefined
`__Unwind_Resume` symbol, two-level library ordinal, indirect stub/pointer
entries, actual ARM64 stub, lazy-binding record and per-symbol helper agree
on `/usr/lib/libSystem.B.dylib`. Unsupported import representations fail.
This establishes a static declaration and stub chain only. Other dyld fixups,
the common lazy-binding dispatcher, runtime memory, exception tables and the
system unwinder remain trusted or outside this review; no loader correctness
or runtime-resolution guarantee is inferred.

## Controls and results

All **96 session bodies across 16 executables** matched. Their **48 cleanup
bodies and 96 AES bodies** were rechecked with the current dependencies.
Flipping one bit at every byte position of the actual session bodies produced
**12,000 rejected mutations**, without executing the altered binaries.

Nine session tests include all eight compiler/panic/admission layouts,
**6,000 synthetic byte mutations**, exact direction/call controls, missing and
duplicate roles, dependency corruption, runtime-binding rejection, landing-pad
quarantine and CLI identity/configuration failure behavior. Seven import tests
exercise a complete synthetic Mach-O binding, mutated stub/helper/pointer and
lazy-record bytes, library/symbol/ordinal mismatches and malformed tables.
Together with the previous controls, the integrated tooling suite passes
**859 tests**.

## Still separate

Constructors, higher-level cached/ephemeral operation callers, all cleanup
call sites, hosted/static startup and lifetime admission still need their
Apple-specific closure. This step does not qualify arbitrary downstream
builds, erase register/spill copies, establish physical fault/power/EM
resistance, resolve earlier timing alarms or introduce a publication gate.

The subsequent [constructor review](aes-apple-linked-constructors.md) now
covers the six retained raw/cached constructors and their copy helper, with
session/cleanup/AES dependencies rechecked. Higher-level operation callers,
exception dispatch and platform startup/lifetime admission remain separate.
