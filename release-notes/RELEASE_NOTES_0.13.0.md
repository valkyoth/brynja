# Brynja v0.13.0 Development Milestone

Status: remediation implemented; awaiting repository-owner retest

Brynja v0.13.0 freezes the first protocol-neutral provider capability and
opaque-handle contracts in `brynja-core`, advances the `brynja` facade to
0.13.0, and selects no crate for crates.io publication. It implements no
provider effect, cryptographic algorithm, entropy source, clock, storage,
certificate-path engine, or pending-operation lifecycle.

## Implemented

- nineteen independent operations covering hash, separate MAC
  generation/verification, key derivation, key agreement, sign/verify, KEM
  encapsulate/decapsulate, AEAD seal/open, entropy, wall and monotonic clocks,
  certificate chains, storage read/write, and pending poll/cancel;
- immutable capability snapshots with named single assignment, duplicate
  rejection, explicit empty-set rejection, and no implied opposite direction;
- named transactional installation of capabilities, caller resource and work
  limits, and mandatory nonempty secret-destruction duties;
- non-cloneable, non-copyable, non-formattable opaque provider handles and
  exact-operation authorization tokens with no raw or provider-native identity;
- immutable, version-neutral request frames that retain their exact installed
  provider, pre-effect enforcement of aggregate input, output-capacity, and
  provider-operation limits, and a monotonic provider-owned work meter; and
- closed unsupported-operation and request failures without strings, secret
  bytes, native codes, configured limits, fallback order, or algorithm policy.

## Security Boundaries

Protocol code chooses one installed provider explicitly. Authorization checks
only that provider's frozen snapshot. An unsupported operation fails and never
searches a registry, changes provider, broadens direction, or falls back.
AEAD seal/open, sign/verify, KEM encapsulate/decapsulate, storage read/write,
and pending poll/cancel remain distinct.

Provider requests expose immutable primary and contextual bytes plus public
output-capacity metadata. They provide no mutable output or effect buffer, so
request preparation cannot partially mutate caller output. They retain the
exact installed provider, cannot create success or failure receipts, and never
accept a caller-supplied work estimate. Any later trusted provider
implementation remains responsible for deriving and charging actual work,
returning an authoritative result directly, performing an operation-specific
failure-atomic commit, and satisfying mandatory destruction behavior.

MAC generation and verification are distinct capabilities. MAC and signature
verification requests reject nonzero output capacity, preventing a future
verification operation from returning computed authentication bytes through
the generic frame.

Every installed contract names at least one destruction target. The contract
can retain local-memory, external-store, accelerator, cache, and DMA duties,
but it does not claim those effects completed. Completion remains governed by
the existing single-consumption destruction contract.

## Verification Evidence

- nine behavioral test groups cover all nineteen capabilities, duplicates,
  empty and incomplete installation, exact direction, unsupported operations,
  no fallback, exact limits, immutable and overlapping input, all destruction
  targets, cancellation direction, exact provider identity, monotonic work
  exhaustion, verification-output prohibition, and deterministic request
  metadata;
- six compile-fail examples reject handle, authorization, and request
  duplication or formatting plus request-side success and failure forgery;
- a SHA-256-locked source policy confines four provider files below 500 lines,
  forbids allocation, `std`, unsafe code, protocol-version and target coupling,
  mutable request buffers, registry/fallback paths, token trait drift, and
  missing work/resource/destruction checks;
- thirteen broken fixtures exercise operation omission, authorization bypass,
  fallback injection, mutable effects, destruction-duty removal, result
  forgery, provider detachment, caller-supplied work, verification byte output,
  version coupling, dependency inversion, cloneable handles, and unreviewed
  source drift;
- the Miri and AddressSanitizer evidence lanes use current
  `nightly-2026-08-10` at the exact official Rust revision
  `969b803cbe1d4499f841ae0a49c637d8c70a0458`; and
- workspace tests, Clippy, rustdoc, `no_std`, supported Rust and target
  matrices, dependency policy, package policy, advisory checks, SBOM, and
  modern/legacy isolation remain mandatory.

## Current Limits

The v0.13.0 boundary freezes request metadata and authority only. It does not
define algorithm identifiers, keys, nonces, signatures, ciphertext semantics,
entropy health, clock units, certificate-path semantics, persistent storage,
asynchronous resumption, cancellation completion, CPU dispatch, FIPS service
approval, platform I/O, or provider implementations. Those remain owned by
later explicit milestones.

The voluntary assessment found three High authorization/provider-binding
findings and one Medium work-accounting finding. All four are remediated in
source and local tests, but v0.13.0 remains blocked pending repository-owner
retest of the signed remediation candidate.

Brynja remains incomplete, must not secure application traffic, has no
independent cryptographic or protocol verification, and is not FIPS 140-3
validated.

## Release Process

v0.13.0 is an internal development milestone in the cumulative range after
v0.10.0 through v0.15.0 and selects zero crates for crates.io publication. It
did not require a scheduled pentest, but the completed voluntary assessment
and its High findings now activate an exceptional retest gate. Only a PASS
retest, complete local gate, green GitHub and CodeQL, and explicit
repository-owner authorization permit the signed `v0.13.0` tag.
