# Apple retained AES constructors — v0.27.3 development

The raw-key and cached-key constructors for all three AES widths now have
explicit Apple instruction policies. This extends the
[session review](aes-apple-linked-sessions.md); it does not qualify the entire
program or higher-level encryption/decryption callers.

## Retained inputs and replay

This uses the same sixteen binaries in the
[native Apple capture](../../assurance/aes-native-observations/v0.27.3/apple-linked-capture-20261111.json):
Apple M2 Pro, Rust 1.90.0/1.99.1, direct/facade consumers, static/hosted admission
and abort/unwind profiles. The original capture, binaries and native results
are unchanged. No rebuild, native execution or timing measurement is needed.

```sh
python3 scripts/aes/check-aes-apple-linked.py RETAINED_EXECUTABLE \
  --sha256 CAPTURED_BINARY_SHA256 --review-constructors \
  --compiler 1.90.0 --panic unwind --admission hosted
```

Use the recorded configuration for that binary. The runner requires an exact
hash before parsing, rejects conflicting/missing configuration, and emits no
success JSON on failure. The
[constructor record](../../assurance/aes-native-observations/v0.27.3/apple-constructor-bodies-20261111.json)
binds the capture/source identities, reviewer hashes, complete body extents,
dependency reviews and negative controls. Like the preceding observations,
it is unauthenticated and describes the captured working tree, not a clean
tag or arbitrary downstream executable.

## Inspected instruction paths

[`aes_apple_linked_constructors.py`](../../scripts/aes/aes_apple_linked_constructors.py)
contains instruction templates constructed from the inspected sequences,
not automatically refreshed hashes. Local branches have exact computed
destinations. External calls and tail branches must target independently
reviewed functions in the same executable.

Both constructor forms clear the complete admitted destination before checking
authority health and execution/admission fields. A raw owner copies exactly
16, 24 or 32 key bytes, captures the authority/generation, and returns the
corresponding pointer/length fields. Rejection records an error and clears the
destination through the reviewed zeroizer.

A cached owner instead initializes a 176-, 208- or 240-byte temporary schedule,
calls the matching reviewed hardware expansion function, and checks health,
generation and admission again before copying that schedule into caller storage.
Success clears the temporary schedule before returning the owner. Rejection
after expansion records the error, quarantines as appropriate and clears both
scratch and destination. The two compilers' different hosted-field checks and
control-flow layouts are explicit; no branch condition, register, length or
cleanup instruction is ignored.

Rust 1.90.0 unwind cached constructors additionally retain landing-pad code.
Its complete extent includes quarantine, scratch and destination clearing,
preservation of the exception argument, and calls to the previously checked
static unwind import. This does not establish exception-table dispatch or
qualify Apple's loader/unwinder. Current-compiler unwind bodies use a shared
ordinary epilogue without that retained pad; their smaller extent is checked
separately, not treated as general proof that arbitrary callees cannot unwind.

The shared `copy_bytes` helper is also matched in full: an eight-byte loop,
a byte remainder loop, then explicit clearing of its x4/x5/x6 working registers
and NZCV. Loop decisions depend on the public length, not copied bytes. This
local observation does not imply erasure of other registers, spills or copies.
The constructor signatures and safe borrowing supply valid, nonoverlapping
storage; this is not a general-purpose runtime pointer validator.

## Results and regression controls

All **96 constructor bodies and 16 copy-helper bodies** match across the
sixteen retained executables. Dependency replay also checks 96 session bodies,
48 cleanup bodies, 96 AES bodies and the applicable static unwind imports.
One-bit changes at every byte position of the actual constructor/copy extents
produce **30,576 rejected mutations**. Altered binaries are never executed.

Nine new tests cover all configurations and widths, **15,288 synthetic byte
mutations**, exact key lengths and clear-before-admission ordering, modified
call targets/opcodes, missing/duplicate/aliased symbols, corrupt dependencies,
unwind-pad truncation, invalid profiles and CLI identity/failure behavior.
All **868 integrated tooling tests** pass.

## Remaining scope

Higher-level cached/ephemeral operation callers, complete cleanup call-site
coverage, platform startup and lifetime admission still need their own Apple
review. This does not resolve prior timing alarms or provide physical
fault/power/EM protection or register/spill erasure. No production Rust,
dependency, native measurement protocol or publication gate changes here.

The subsequent [cached-caller review](aes-apple-linked-cached.md) covers the
six retained cached public/secret operation bodies and rechecks these
constructor dependencies. Ephemeral callers and platform startup/lifetime
admission remain separate work.
