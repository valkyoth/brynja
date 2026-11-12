# Apple retained clearing and destruction bodies — v0.27.3 development

This extends the [Apple kernel-body review](aes-apple-linked-kernels.md) with
three complete functions per retained executable: the volatile zeroizer,
the retained `destroy_block` fixture boundary and the retained AES-128
`destroy_key` fixture boundary. It is not approval of every cleanup call site,
constructor, operation, or exception path.

## Identity and scope

All sixteen original native captures are reused without rebuilding, executing
or collecting timing data: Rust 1.90.0/1.99.1, direct/facade, static/hosted and
abort/unwind, on the Apple M2 Pro. The same Mach-O mapping and complete
`LC_FUNCTION_STARTS` boundaries are required. Cleanup definitions must reside
in the uniquely mapped instruction section and have exact known symbol
spellings, distinct starts and following function boundaries.

The hash supplied to the offline checker must be the one from the native
capture. Compiler, panic and admission values must likewise come from that
capture; they are not inferred or authenticated by an instruction sequence.

```sh
python3 scripts/aes/check-aes-apple-linked.py PATH_TO_RETAINED_BINARY \
  --sha256 CAPTURED_BINARY_SHA256 --review-cleanup \
  --compiler 1.99.1 --panic abort --admission static
```

Cleanup review first rechecks the six AES round/expansion bodies. It then
checks the zeroizer before either destruction body. External branch words are
computed using the actual source instruction and independently checked
zeroizer address. A name match, a branch somewhere inside the zeroizer, or a
call instruction in place of a tail branch is not accepted. All remaining
words and function extents are exact, including paths after an early return.

## Inspected Apple instruction sequences

The Apple clear loop differs from Linux's scheduling, so it has explicit
templates rather than relaxing the existing Linux policy:

- Rust 1.90.0: `cbz x1` skips an empty region; `strb wzr, [x0], #1`
  writes a zero byte and advances the pointer; `subs x1, x1, #1` decrements
  the length; `b.ne` repeats until zero; `ret` completes the 20-byte body.
- Rust 1.99.1: the same empty-length check precedes `strb wzr, [x0]`,
  an explicit pointer increment, decrement, loop branch and return. This body
  is 24 bytes. Both bodies use the supplied region length, not secret data,
  as the loop bound. Neither contains a call or a stack access.
- Both compiler endpoints' abort destruction bodies, and the MSRV unwind
  bodies, contain a null-owner check, a tail branch to the zeroizer and a
  return. The pointer and length arguments are preserved for the clear call.
  Each complete body is 12 bytes.
- Current-compiler unwind destruction bodies retain the public explicit-clear
  selector. Both selector paths check the owner pointer and tail-branch to the
  same zeroizer for a live owner, otherwise returning. Each body is 24 bytes.
  Checking this function's unwind build does not validate the exception tables
  or prove that another function's landing pad reaches it.

The compiler retains only the named destruction boundaries in these fixtures;
this review does not infer approval of missing, merged or inlined destruction
call sites for other key sizes or cached schedules. Their runtime fixture
checks remain useful but are not substituted for emitted-code coverage.

## Results and regression controls

The [cleanup record](../../assurance/aes-native-observations/v0.27.3/apple-cleanup-bodies-20261111.json)
binds the original capture/source hashes, new reviewer hashes, binary identities,
exact cleanup extents and their kernel-review dependency. All **48 cleanup
bodies in 16 binaries** matched. A one-bit change at every byte position of
each actual cleanup body was rejected: **832 actual-binary controls**. All
96 AES round/expansion bodies were rechecked without changing their policy.

Nine new tests cover all configurations, explicit zeroizer encodings, all
208 cleanup byte positions across four synthetic compiler/panic layouts,
wrong/missing/out-of-range branch targets, symbol aliases, unknown roles,
wrong profiles, modified AES dependencies and runner hash/configuration binding.
The existing sixteen Mach-O tests still pass, and the integrated repository
tooling suite passes all **843 tests**. No production crypto changed.

## Remaining caller and unwind work

The subsequent [session review](aes-apple-linked-sessions.md) now checks the
six complete session functions, their width-bound calls and the Rust 1.90.0
quarantine landing-pad instructions. It also checks the static declaration,
stub and lazy-pointer/helper chain for the unwind import. Exception-table
dispatch and the dynamic loader/system unwinder are not qualified by that
step. Original cleanup and capture records remain unchanged.

Constructor and operation callers, full admission/startup coverage, exception
dispatch and every cleanup call site remain separate work. No platform
unwinder, arbitrary downstream binary, register/spill erasure, physical fault
resistance or power/EM qualification is claimed. Earlier timing alarms remain
unchanged. The native capture mode remains capture-only; this offline review
adds no release gate or automatic native rerun.
