# Scoped result wire experiment

Status: v0.24.50 research only. **Not Windows strict support, a shipping API,
an authenticated channel, or native qualification.** Production crypto and
release gates are unchanged. This connects the earlier
[scoped result model](windows-enclave-result-design.md) to a new version of the
[public snapshot transport](windows-enclave-request-design.md). Those earlier
experiments and their source-bound observations remain unchanged.

## Namespace and lifetime

The enclave generates a public 128-bit instance identifier once, using
`BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`. Microsoft lists
[this API as available inside VBS enclaves](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/enclaves-available-in-bcrypt);
its [documented return value and flag](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom)
are checked. This is namespace generation, not outsourced cryptographic hashing:
the digest still uses Brynja's first-party Rust SHA-256 implementation.

Entropy failure or an all-zero identifier permanently rejects admission for that
instance. A checked 64-bit epoch is consumed before every admitted worker call;
rejected requests do not roll it back. Exhaustion rejects rather than wrapping.
The public wire token is four words: instance low/high, epoch, slot 1. A new
enclave instance obtains a fresh namespace. Random identity collision remains
probabilistic; neither identity nor epoch authenticates an application, proves
attestation, prevents a hostile host observing tokens, or establishes authorization.

Exactly one synchronous worker owns one result in one call. There is no retained
result table or cross-call live object. The previous Rust model is reused unchanged
inside that call; the wire adapter checks the full external namespace before
invoking its private handle. The first export or cancellation attempt consumes
the handle even if metadata is invalid or copy-out fails. A second request reports
spent, without exposing the digest again. This is a diagnostic two-exchange
protocol, not a persistent asynchronous resource API.

## Fixed copies and explicit public output

The enclave restricts direct containing-process access and uses only the documented
enclave copy APIs. The 1,072-byte input snapshot contains a version-2 six-word
header and at most 1,024 public message bytes. No Rust reference points into host
memory. A 64-byte command area receives an offer with the public token and prior
status; a fixed host callback then prepares a 64-byte command for copy-in. The
enclave validates that private copy, including the exact token, operation, explicit
public flag, destination range and width. Mutation of the original message after
the offer cannot change the digest. Concurrent host writes during a platform copy
are **not** claimed to form an atomic/authenticated transaction.

Offers and reports contain public metadata only. Export requires the existing
public-output assertion, which does not prove provenance or declassify secrets.
Copy failures may partially modify the host destination; owned-memory cleanup is
promised, not host-output rollback. Input, command, digest and hardened workspace
live within the bounded guarded/locked window. Their cleanup is checked before
the existing outer window-clear handshake. Abort/fatal faults are not unwinding
success and cannot establish cleanup.

## Tests and remaining boundaries

Local compiled Rust tests cover all message lengths 0..1024, stale/future/foreign
tokens, invalid commands, cancellation, replay, partial-copy and callback failures,
input mutation and local storage clearing. Five compiled mutations separately
ignore identity, ignore epoch, retain a consumed result, forget its owner, or skip
buffer clearing. An extracted copy of the actual C admission function is compiled
against a mock entropy provider to check failure latching, zero rejection and
epoch exhaustion; four mutations must fail. This is not an entropy-quality test.

The native runner exercises public hashing and transport with three calls per
mode, including a donor enclave destroyed before a second instance rejects its
token. Native execution, guard/callback ordering, copy errors, source/image/compiler
binding and mutant rejection must be recorded separately; mocks and cross-builds
cannot substitute for those observations. All machine records remain explicitly
nonqualifying. Diagnostic exports and callbacks remain exposed by the research
image. Production signing, attested confidential ingress, host-side lifetime API,
concurrency, full resource cleanup, register/TLS/runtime boundaries and application
integration remain separate work. No wider secret-handling guarantee is inferred.
