# Brynja 0.6.0 Release Notes

Status: pentest remediation complete; awaiting retest

Brynja 0.6.0 implements bounded numeric and resource value foundations. It
does not implement TLS, DTLS, QUIC-TLS, cryptography, PKI, mutable resource
accounting, or platform providers and must not be used to secure network
traffic.

## Checked Numeric Domains

`brynja-core 0.3.0` provides private-field `BoundedU64<MAX>` and
`BoundedUsize<MAX>` types with fallible construction and checked addition,
subtraction, and multiplication. Operations distinguish configured-bound
violations, primitive overflow, underflow, and platform-width conversion
failure without relying on release-profile overflow behavior.

`Count<MAX>` and `Length<MAX>` remain different Rust types so an item count
cannot be passed where a byte length is required. Conversion from wire-sized
`u64` values to platform `usize` values fails before truncation.

## Sequence And Epoch Exhaustion

`SequenceNumber<MAX>` and `Epoch<MAX>` are protocol-neutral monotonic values.
They admit an inclusive maximum and return typed exhaustion when an advance
would cross it. They never wrap, saturate, or reuse zero.

Direction-specific record state, concrete TLS and DTLS wire widths, replay
handling, nonce construction, epoch-key ownership, and mutable state
transitions remain assigned to later version-specific milestones.

## Immutable Budgets

`ResourceBudget` carries explicit limits for input bytes, output bytes,
workspace bytes, retained state items, queue items, certificate bytes, and
provider operations. Every limit uses a named builder method, and construction
fails closed until all seven domains are present. `WorkBudget` carries an
explicit `u64` work-unit limit. Neither budget provides a default or setter.

Budget checks are read-only and return the existing typed
`ResourceExhaustion` domain. The error identifies only the resource class and
operation phase; it does not contain or format configured limit values. These
budgets are policy values, not mutable accounting or allocation machinery.

## Verification

The implementation includes:

- exhaustive construction checks over a complete small bounded domain;
- exhaustive checked-add, checked-subtract, checked-multiply, sequence, and
  epoch matrices compared with primitive checked operations;
- exact zero, maximum, above-maximum, underflow, primitive-overflow,
  pointer-width, and exhaustion checks;
- every resource dimension, zero-budget, exact-limit, over-limit,
  every-missing-builder-field, no-mutation, and limit-value-free error checks;
- storage-size tests proving bounded values carry no hidden allocation or
  bound metadata;
- compile-fail doctests for count/length confusion and accidental formatting;
- `no_std`, no external dependencies, forbidden unsafe code, and the existing
  Rust 1.90.0 through 1.97.1 and OS-less target gates; and
- source and test files below the 500-line review limit.

The repository-owner assessment found a Medium positional-argument
transposition risk in the original seven-argument resource-budget constructor
and a Low diagnostic gap in the fixed, valueless `NumericError` enum. The
constructor has been replaced by named fail-closed construction, future
overlong positional APIs are denied by workspace Clippy policy, and
`NumericError` now safely implements `Debug`. Local remediation is complete;
external retest remains required.

The requirements and surface registers intentionally do not mark TLS or DTLS
sequence, epoch, record, or resource behavior implemented. Version 0.6.0 is a
source-free shared foundation boundary. Project tests, CI, Kani policy checks,
and the required release pentest do not constitute independent protocol or
cryptographic verification. No Brynja package has FIPS 140-3 validation.

The release evidence also incorporates the reviewed 2026-07-31 IANA DNS
Parameters snapshot. Three new registries and seventeen new entries remain
caller-owned by the future v0.140.0 DNS boundary. Registry references to the
provisional Structured DNS Error draft do not admit that draft as
implementation authority or add protocol code.

## Publication

The release selects `brynja-core 0.3.0`, eight dependency-only modern support
patches at `0.1.2`, and the mandatory `brynja 0.6.0` facade. `brynja-crypto`
remains unchanged at `0.1.0`; legacy and repository-only packages remain
unpublished. The guarded publisher enforces exact pins and dependency order.

Publication remains blocked until the repository-owner pentest is complete,
its permanent report is committed, GitHub is green, and the user explicitly
authorizes tagging.

## Limitations

There is no parser, buffer cursor, arena, mutable resource counter, record
layer, handshake engine, transport state machine, key schedule, cipher,
signature, certificate validator, provider implementation, socket integration,
interoperability evidence, formal proof, independent review,
production-readiness claim, or FIPS validation.
