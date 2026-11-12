# Apple retained per-operation secret AES callers — v0.27.3 development

This extends the [ephemeral public review](aes-apple-linked-ephemeral-public.md)
to the retained `Aes128/192/256Key::secret` bodies. Each shared body serves
encryption and decryption into a clearing owner, with a temporary schedule
expanded for each operation. This is not approval of every possible call site.

## Inputs and replay

The same sixteen executables from the
[native Apple capture](../../assurance/aes-native-observations/v0.27.3/apple-linked-capture-20261111.json)
are used: Apple M2 Pro, Rust 1.90.0/1.99.1, direct/facade consumers,
static/hosted admission and abort/unwind. No executable is rebuilt or run;
no timing measurement is collected.

```sh
python3 scripts/aes/check-aes-apple-linked.py RETAINED_EXECUTABLE \
  --sha256 CAPTURED_BINARY_SHA256 --review-ephemeral-secret \
  --compiler 1.90.0 --panic unwind --admission hosted
```

The configuration must match the capture. Identity checking precedes parsing;
failed identity, missing/conflicting configuration or failed dependencies
prevent success JSON. The
[review record](../../assurance/aes-native-observations/v0.27.3/apple-ephemeral-secret-20261111.json)
binds reviewer hashes, source/binary identities, extents and results. It is an
unauthenticated observation of the captured working tree, not certification
evidence. Earlier records retain their original reviewer identities.

## Reviewed paths

The explicit whole-body templates in
[`aes_apple_linked_ephemeral_secret.py`](../../scripts/aes/aes_apple_linked_ephemeral_secret.py)
pin instructions, local branches, stack extents, register assignments and
constants. Calls bind to the reviewed width-matched expansion and encrypt/
decrypt session functions, copy helper and zeroizer in the same executable.
The public/cached/constructor/session/cleanup/AES dependency chain is replayed.

The caller clears all 16 destination bytes before checking authority health,
generation and admission. It initializes the entire 176/208/240-byte schedule
and requires a present raw-key pointer with exactly 16/24/32 bytes before
expansion. Health, generation and admission are rechecked after expansion.
Valid storage and Boolean/enum representations come from the safe Rust
ownership contract, not from a claim to tolerate arbitrary memory corruption.

Only after revalidation does it stage the input in 16-byte scratch storage.
The saved direction selects the matching encryption or decryption session
call. Each callee is independently reviewed, including its own admission and
error handling. The caller checks the returned success representation before
copying the result: the retained MSRV layout compares the low byte with 6;
the current layout tests that all eight low bits are set. These are the
respective reviewed Rust enum layouts, not a general external-provider ABI.

Success copies exactly 16 bytes into the admitted destination, clears block
scratch and the complete temporary schedule, then returns the clearing
owner's pointer, length and success discriminant. Admission/key failures
clear the destination; failures after schedule initialization clear the
schedule and leave authority quarantined. Session failure also clears block
scratch and destination, and does not construct a successful owner.

Unwind configurations share cleanup using a destination-clearing flag. The
Rust 1.90.0 body additionally retains distinct session and expansion landing
pads: the session pad clears block/destination before common schedule cleanup;
the expansion pad has no initialized block and arranges destination cleanup
afterward. Both preserve the exception argument, clear the schedule and
quarantine before calling the checked static unwind import. This checks pad
instructions, not exception-table dispatch, Apple's loader or system unwinder.
The current compiler's smaller bodies do not establish cleanup for arbitrary
replacement callees that unwind. Asynchronous faults and aborts remain out
of scope.

## Results and controls

All **48 shared secret-output caller bodies across 16 binaries** match.
Dependency replay includes 48 ephemeral public callers, 96 cached callers,
96 constructors, 16 copy helpers, 96 session bodies, 48 cleanup bodies,
96 AES bodies and applicable static unwind imports.

Flipping bit zero at every byte position in those retained secret caller bodies
produces **29,520 rejected mutations**, each with the full dependency review
replayed. The original executable hashes remain unchanged. These are static
checker rejection controls; no altered executable is run.

Nine new tests cover every compiler/profile/admission/width combination,
**14,760 synthetic byte mutations**, destination clear-before-admission,
exact raw-key lengths, direction selection, session result checks, copy and
cleanup before successful owner return, retargeted calls, corrupt dependencies,
invalid profiles/symbols, unwind pads/imports and CLI failure handling.
All **894 integrated tooling tests** pass.

## Still separate

Apple startup/platform lifetime admission and other call sites remain
unfinished. Exception dispatch and the system runtime remain outside this
bounded review. Prior timing alarms remain recorded; physical fault/power/EM
protection and register/spill erasure are not established here. No production
code, dependency, native measurement or publication gate changes in this step.
