# Concrete retained-output facade candidate

Status: **integration candidate, not an exported production backend**. Existing
Windows strict constructors remain Unsupported. This step connects a concrete,
non-generic safe interface to the previously tested native host and unchanged
enclave worker. It changes no production crate, image or release-gate policy.

The existing strict digest's `expose() -> &[u8]` contract cannot represent
enclave-private output. The candidate therefore deliberately has a distinct
retained-result API rather than pretending to provide a protected host slice.
Its implementation is in
[`retained_facade.rs`](../assurance/windows-enclave-probe/retained_facade.rs).
There is no public constructor yet: `from_retained` is private to the integration
fixture, and accepting an image path is not image verification.

## API and lifecycle

| Operation | Result and boundary |
| --- | --- |
| `Session::hash` | Synchronously copies at most 1024 caller-owned bytes; returns a retained SHA-256 result borrowing the session, not the input |
| `Digest::rehash` | Consumes/replaces the retained result inside the enclave; exports no result bytes |
| `Digest::declassify` | Requires an explicit `PublicDeclassification` decision and exact 32-byte public destination; commits only after validated cleanup |
| `Digest::cancel` | Consumes/clears without exposure; successful cancellation permits reuse |
| Drop or forget digest | Quarantined or Busy respectively; owner still owns cleanup, and another hash cannot begin |
| `Session::close` | Closed only after confirmed native release; failed cleanup stays quarantined and retains uncertain resources |

The public surface exposes no generic driver, raw authority, host pointer, token,
image-path constructor, arbitrary callback, secret byte slice, Deref or AsRef.
Session and digest do not implement Send, Sync, Copy, Clone or Debug. A live digest
prevents closing/destroying or reusing its owner. The declassification marker is a
caller decision, not provenance enforcement or permission from a security service.
Caller-owned input storage and deliberate public output remain outside enclave
protection. Failed public output preserves the destination; it is not a secret
destination-clearing API.

The wrapper delegates to the reviewed receipt/cleanup state machine and concrete
native resource adapter. It neither adds a portable fallback nor performs hashing
on the host. Native protocol/cleanup validation remains load-bearing; a wrapper
alone cannot establish protected residency or trustworthy image identity.

## Checks completed

Host source: `1762987f23cbb87e53718d9a7dbc3f2f082c453c`.
The [observation record](../assurance/windows-protection-observations/retained-facade-1762987f.json)
binds the committed source closure, generated inputs, libraries, executables,
unchanged image, raw captures and exact expected outcomes. Build inputs were
transferred as source-bound archives, not taken from the server's old checkout.

Local tests pass at O0 and O2: nineteen Rust tests including four facade-specific
tests, three compiled lifecycle/receipt mutants, one successful downstream usage
compilation, and twenty-five rejected ownership/exposure/construction probes.
Tests cover input lifetime ending after the synchronous copy, reuse after
cancellation/declassification, failure without output commit, oversized input,
rehash failure, forgotten/abandoned results and recoverable component unwinding.
Capture-schema tests reject changed counters, boolean substitutions and exits.
The preceding lifetime suite also passes. An initial test-harness metadata file
name was corrected before the candidate commit and native capture; its failed
compilation was not counted as a passing negative test.

Two native campaigns on Azure x86-64 Windows each pass **281 calls**, including
the earlier 265-call lifecycle campaign and 16 calls through the new concrete
facade. Each creates/deletes 14 enclave instances with zero normal retained
resources or cleanup errors. The facade hashes a temporary `abc` input, overwrites
the caller buffer, performs two retained rehashes and explicitly declassifies the
result, matching the independently generated hashlib chain. Further cases exercise
cancellation, abandonment, forgotten results and terminal close.

Four previously defined broken-host variants are rejected at their exact expected
points in the preceding lifecycle campaign. They are not four newly injected
facade implementations. Native startup and deletion-failure controls also match;
the intentional deletion failure retains one resource with three errors until
child exit, not a cleanup success. Local mutants additionally fail facade tests.

Artifacts are stored outside Cargo's target directory:

```text
release-reports/windows-azure-replacement-2026-09-29/retained-facade-complete.tar
SHA256 4fae7e1fb2abe1994d4b245122ba9015dfac886353ce1a5855ca77b1d8caa48e
```

Artifact review matches source/current commit hashes, generated inputs and
libraries, EXE/image hashes, repeated raw outcomes, warning-free MSVC build logs
and cleanup. No probe children or temporary certificates remain; earlier images
are unchanged. No signing or host configuration changes occurred. Native builds
use Rust 1.98.1 panic=abort and MSVC 17.14.41 O2 with warnings-as-errors and control
flow protection. Native unwind is not claimed.

## Before production integration

Keep the fixture constructor private. A deployable constructor must verify the
intended image/identity/import contract before confidential input admission;
successful loading of a development-signed DLL is insufficient. Microsoft's
[development guide](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide)
distinguishes local test signing from production enclave signing through Trusted
Signing. Existing image and Secure-Boot-disabled development-host limitations
remain unchanged. This step does not implement signing, attestation or deployment.

The final public enclave namespace and constructor/deployment API still need
review before export. Wider algorithms, streaming/bit inputs, opt-in hardware and
SIMD, bounded workers and exact-image residency/dump/runtime qualification remain
on the [remaining-work list](windows-v02450-remaining.md). Windows AArch64 is not
qualified. These observations are not a general claim that Windows strict now
works, or a replacement for the pending pentest.
