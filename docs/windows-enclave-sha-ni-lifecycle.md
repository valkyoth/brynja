# Saved SHA-NI lifecycle and receiver review

This is offline implementation-author review of an existing development image,
not new enclave execution, independent retest or whole-image qualification.
No implementation, image or release-gate policy changed.

The `sha2/mod.rs::open_sha_ni` image SHA-256 is
`ca5806be2e78ae43f4942b0733bb94bef1e5c75dfa2250d98408dfda74c77d0a`;
its selected COFF member is
`dd53ebce1a62cf2392ec6b96dc0ef1acf7ce5f435080d527fb28c8ba111310a4`.
The [body inventory](../assurance/windows-protection-observations/sha-ni-lifecycle-20261005.json)
binds eight complete bodies and relocation populations. The reviewer also
reproduces existing C entry, transport, memory-runtime and worker bindings;
an old PASS string is not substituted for those checks.

## Admission and clearing

Emitted operation code checks the requested phase, excludes quarantined owners,
rejects sequence zero and requires the exact next sequence. The wrapping machine
increment cannot admit zero after `u64::MAX`. Only a healthy exact SHA-NI
authority permits sequence commit. Failures clear the owner and latch authority
and owner quarantine. The incomplete guard reaches that cleanup; cancellation
returns to Empty only after successful admission and cleanup.

Common teardown copies 2,000 state bytes to `RSP+32`, replaces the original
discriminant with the exact linked None sentinel, and conditionally destroys
the moved active fields:

| Region | Offset within moved state | Bytes |
| --- | ---: | ---: |
| Hash workspace | 816 | 1,170 |
| Compression scratch, when present | 96 | 704 |

The workspace uses eight reviewed volatile-clear ranges; scratch uses 640-byte
and 64-byte ranges. Output is cleared separately: 32 bytes at owner offset
2,000. Algorithm metadata is invalidated. This is **not an individual wipe of
the entire enum or original inactive storage**. The remaining 126 bytes when
both owners are active include metadata/padding and are not claimed erased by
those typed wipes.

Resident construction places the owner 16 bytes into the aligned page. Both
startup-KAT rejection and resident destruction contain an eight-store,
eight-byte-stride loop covering all 4,096 page bytes. Destruction takes/drops
the owner before the full page wipe. Construction also makes two 2,015-byte
copies containing inactive state/padding; these bytes are not claimed all
separately initialized or individually cleared.

Inactive storage, padding and compiler-generated copies depend on page teardown
and enclosing protected stack-window clearing. Selected frames and copied spans
are reconciled with unwind data: nested cancel/admission reaches `H-5600`;
constructor steady RSP is `H-5424`, with `H` the window high address. These are
selected paths, **not maximum transitive depth**. Startup KAT and inner
state/engine callees are outside that depth calculation.

## Receiver and explicit public output

The receiver copies the 64-byte header, bounds payload length to 1,024 before
copying, decodes again, and rejects a changed decoded length before dispatch.
Its six operation entries and seven identity entries are rebound to exact
machine-code destinations. Private update/finalize compiler declarations carry
`range(i64 0, 1025)` on length; local source length checks were optimized away.
The receiver bound is load-bearing. Review pins that IR precondition and checks
the emitted bound and dispatch instructions.

Public export requires Retained admission and matching identity/width. After
the fixed OS output adapter succeeds, authority is rechecked, the owner is
cleared and phase returns to Empty. Copy or authority failure invokes the guard.
This does **not** promise rollback of bytes already written to the explicitly
public host destination. Actual receiver-to-C and named SDK connections are
rebound through the existing transport review.

## Reproduction and remaining scope

```sh
python3 scripts/cryptography/test-windows-enclave-sha-ni-lifecycle.py
python3 scripts/cryptography/test-windows-enclave-sha-ni-receiver.py
python3 scripts/cryptography/windows_enclave_sha_ni_lifecycle.py \
  release-reports/windows-local-20261004 --mutate
```

Eleven focused tests pass on Linux and Windows; parsed reports are identical.
All 1,976 actual body-byte mutations in the eight bodies and 52 actual
dispatch-table byte mutations are rejected per host. Semantic-template tests
cover admission, take/wipe, export, branches and page loops independently of
body hashes. Unchanged SHA-NI component/oracle and compiled-mutant results from
the preceding worker reconciliation remain applicable; these script-only
changes did not require a new native campaign.

Results are stored outside Cargo target directories in
`release-reports/windows-worker-review-20261005/offline/`; the committed
[observation](../assurance/windows-protection-observations/sha-ni-review-20261005.json)
records their identities and limitations.

The subsequent [state review](windows-enclave-sha-ni-state.md) binds construction
and consuming finalization, their owner call edges, IVs and copy helpers.
Still open: complete begin/update/finalize/rehash operation and engine call chains,
startup KAT depth, decoder semantics, exception-handler behavior, remaining
family workers and indirect SIMD dispatch, full transitive stack depth, and
live runtime-selector/application-image SDK reconciliation. Guard body review
does not qualify arbitrary exception invocation. Windows ARM64, production
signing and independent cryptographic qualification are not established here.
See the [remaining-work checklist](windows-v02450-remaining.md).
