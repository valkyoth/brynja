# Brynja 0.5.0 Release Notes

Status: implementation stop reached; pentest required

Brynja 0.5.0 implements the first shared protocol value domains. It does not
implement TLS, DTLS, QUIC-TLS, cryptography, PKI, or platform providers and
must not be used to secure network traffic.

## Typed Alert Registry

`brynja-core 0.2.0` classifies every possible TLS AlertDescription byte as an
assigned, reserved, or unassigned value. The thirty currently assigned alerts
use a closed enum with exact IANA codes. Reserved and unassigned bytes retain
their distinct registry status and cannot be silently coerced into an assigned
alert.

Assigned alerts carry one concrete protocol identity: TLS 1.2, TLS 1.3,
DTLS 1.2, or DTLS 1.3. Version-specific alerts fail closed when constructed in
an inadmissible context. Alert class and hardened local severity are derived;
callers cannot choose a contradictory class or downgrade a failure severity.

## Outcome And Failure Separation

Orderly `close_notify` and explicit `user_canceled` outcomes have dedicated
types and cannot enter `TlsFailure`. Alert failures accept only error-class
alerts. Local failures, provider failures, and resource exhaustion use separate
closed domains so callers can preserve cause without collapsing unrelated
conditions.

Failure envelopes carry no arbitrary strings, byte slices, provider-native
codes, cryptographic values, or numeric limit values. They intentionally have
no `Debug` or `Display` implementation. Numeric budgets, wire emission,
terminal protocol state, provider capabilities, cryptographic cleanup, and
zeroization remain owned by their later milestones.

## Verification

The implementation includes:

- exhaustive classification of all 256 registry bytes;
- exact checks for all thirty assigned and seven reserved values;
- TLS/DTLS version-admission and alert class/severity matrices;
- close, cancellation, and failure non-collapse tests;
- deterministic provider-category and resource-exhaustion tests;
- representation bounds and compile-fail formatting/payload tests;
- `no_std`, no external dependencies, forbidden unsafe code, and the existing
  Rust 1.90.0 through 1.97.1 compatibility and OS-less target gates; and
- an immutable requirement transition for `BRY-REQ-TLS-0005` from planned to
  implemented to tested, with actual code and test anchors.

These tests and the release pentest are not independent cryptographic or
protocol verification. No Brynja package has FIPS 140-3 validation.

## Publication

The release selects `brynja-core 0.2.0`, eight dependency-only modern support
patches at `0.1.1`, and the mandatory `brynja 0.5.0` facade. `brynja-crypto`
remains unchanged at `0.1.0`; legacy and repository-only packages remain
unpublished. The guarded publisher enforces exact pins and dependency order.

Publication remains blocked until the repository owner pentests this exact
implementation stop, the permanent report records `PASS`/`PASS`, GitHub is
green, and the user explicitly authorizes tagging.

## Limitations

There is no record parser, handshake engine, transport state machine, key
schedule, cipher, signature, certificate validator, provider implementation,
socket integration, interoperability evidence, formal proof, independent
review, production-readiness claim, or FIPS validation. Alert wire encoding
and peer state transitions remain later version-specific work.
