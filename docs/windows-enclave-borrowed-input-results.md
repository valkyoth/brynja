# Direct-copy input worker observations

Status: **public-data experiment only; not Windows strict qualification or a
shipping secret-input API.** No production implementation, availability flag or
release gate changed.

The separately built worker at commit
`33816b76ee1fe2d59d0274ad5b2c991b8feb7566` ran on the existing disposable Azure
Windows Server 2025 x86-64 development host on 2026-09-29. The host remains in
test-signing mode with Secure Boot disabled; these observations do not establish
a production signed deployment.

## Native outcomes

All 78 normal calls passed:

- Twenty independent SHA-256 vectors with explicit public output.
- The same twenty vectors after the host changed the original payload and header
  at the post-copy callback. Results matched the original snapshot, not the
  changed source.
- Twenty cancellations with no public destination modification.
- Three repetitions each of malformed header, inaccessible header, inaccessible
  input, an input crossing from a committed page into an inaccessible page,
  inaccessible output, and denied post-copy acknowledgment.

Empty inputs made no payload copy. Nonempty successful inputs made one exact-width
copy. The page-boundary case returned the input-copy failure status without
issuing a result; it does not establish whether the OS partially wrote the
destination before returning failure. Both full-capacity cleanup and untouched
public output were checked regardless.

For every normal call, the capture validated the guard geometry, all 16 worker
pages locked through cleanup, disjoint and bounded header/payload/command,
workspace and output regions, inner-owner clearing before the outer window wipe,
and successful enclave teardown. Successful result handling remained one-use:
replayed output or cancellation attempts returned the spent status.

Four separately signed negative images were rejected:

| Deliberate regression | Native rejection |
| --- | --- |
| Skip snapshot clearing | Exact inner cleanup/outcome check |
| Ignore failed input copy | Unexpected result offer after page-boundary failure |
| Read source twice | Duplicate nonempty input-copy callback |
| Hash the full unused capacity | Wrong absorbed-length/outcome |

These supplement seven Rust worker tests at both O0 and O2, including all
1025 lengths and independent digests; four compiled mutants rejected at each
level; the earlier borrowed-input lifetime/cleanup tests; and four capture
validator tests also run natively on Windows. Mock tests are not included in the
78 native calls.

## Binding and development-signing warning

The [reviewed observation record](../assurance/windows-protection-observations/borrowed-worker-33816b76.json)
binds the captured outputs, five image identities, Rust archives, compiler,
source closure, negative diagnostics and cleanup observations. Source hashes
were checked against both the capture commit and local bytes. The MSVC build used
`/W4 /WX` and completed successfully.

SignTool signed each development image but returned exit **2** with Microsoft's
warning about changing VBS enclave compatibility on older OS versions. The
signing wrapper returned **1**; neither exit is recorded as a clean signing pass.
The temporary signing certificate/key was removed. All five images subsequently
loaded for their native experiment; that is a separate observation, not a waiver
of the signing warning.

The original scoped-wire image was not modified. No capture child or temporary
signing certificate remained. Public raw artifacts, including assembly and
complete transcripts, were downloaded outside Cargo's cleanable `target/` tree:
`release-reports/windows-azure-replacement-2026-09-29/borrowed-worker-33816b76.tar`.
Its SHA-256 is
`2bd4b8ad43a2382f413ea67fae15482b16cb24ba0977b3b9a0ebc742cbced5eb`.
The archive contains no crash dumps or private signing key.

## Still not established

The Python driver intentionally owns ordinary **public** test buffers. This
campaign proves the new worker copy path, not a Rust host borrowing contract.
The later [Rust-owned host experiment](windows-enclave-borrowed-host-results.md)
retains that input borrow and removes the older payload-serializing request.
The follow-up at `671795bb6577e9703de12a49c2059a8840908eef` exercised
enclave-internal source rejection three times using the unchanged signed worker.
After window admission, the public descriptor selected a real address 4096 bytes
inside that window. All three calls returned input-copy failure (11), with zero
payload-copy acknowledgments, no result offers and untouched public output.
Inner clearing, all 16 pages locked through clearing, outer clearing and enclave
deletion passed. The [focused record](../assurance/windows-protection-observations/internal-input-671795bb.json)
binds the new driver source closure separately from the unchanged image source
at `33816b76`. No older campaign was relabeled or repeated.

Persistent protected result ownership and the enclave-compatible API remain
separate work. This experiment retains results only within one guarded worker
call. No caller-frame, signal-frame, snapshot, fatal-abort or full-runtime
protection claim is added. See the [input design and remaining boundaries](windows-enclave-borrowed-input-design.md).
