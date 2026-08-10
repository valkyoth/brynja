# Brynja v0.13.0 Development Milestone

Status: local verification complete; awaiting green GitHub, CodeQL, and signed tag

Brynja v0.13.0 freezes the first protocol-neutral provider capability and
opaque-handle contracts in `brynja-core`, advances the `brynja` facade to
0.13.0, and selects no crate for crates.io publication. It implements no
provider effect, cryptographic algorithm, entropy source, clock, storage,
certificate-path engine, or pending-operation lifecycle.

## Implemented

- eighteen independent operations covering hash, MAC, key derivation, key
  agreement, sign/verify, KEM encapsulate/decapsulate, AEAD seal/open, entropy,
  wall and monotonic clocks, certificate paths, storage read/write, and pending
  poll/cancel;
- immutable capability snapshots with named single assignment, duplicate
  rejection, explicit empty-set rejection, and no implied opposite direction;
- named transactional installation of capabilities, caller resource and work
  limits, and mandatory nonempty secret-destruction duties;
- non-cloneable, non-copyable, non-formattable opaque provider handles and
  exact-operation authorization tokens with no raw or provider-native identity;
- immutable, version-neutral request frames and pre-effect enforcement of
  aggregate input, output-capacity, provider-operation, and work limits; and
- closed unsupported-operation and request failures without strings, secret
  bytes, native codes, configured limits, fallback order, or algorithm policy.

## Security Boundaries

Protocol code chooses one installed provider explicitly. Authorization checks
only that provider's frozen snapshot. An unsupported operation fails and never
searches a registry, changes provider, broadens direction, or falls back.
AEAD seal/open, sign/verify, KEM encapsulate/decapsulate, storage read/write,
and pending poll/cancel remain distinct.

Provider requests expose immutable primary and contextual bytes plus public
output-capacity and work metadata. They provide no mutable output or effect
buffer, so request preparation cannot partially mutate caller output. Any
later provider implementation remains responsible for its operation-specific
failure-atomic commit and mandatory destruction behavior.

Every installed contract names at least one destruction target. The contract
can retain local-memory, external-store, accelerator, cache, and DMA duties,
but it does not claim those effects completed. Completion remains governed by
the existing single-consumption destruction contract.

## Verification Evidence

- nine behavioral test groups cover all eighteen capabilities, duplicates,
  empty and incomplete installation, exact direction, unsupported operations,
  no fallback, exact limits, immutable and overlapping input, all destruction
  targets, cancellation direction, exact terminal results, and deterministic
  request metadata;
- four compile-fail examples reject handle, authorization, and request
  duplication or formatting;
- a SHA-256-locked source policy confines four provider files below 500 lines,
  forbids allocation, `std`, unsafe code, protocol-version and target coupling,
  mutable request buffers, registry/fallback paths, token trait drift, and
  missing work/resource/destruction checks;
- nine broken fixtures exercise operation omission, authorization bypass,
  fallback injection, mutable effects, destruction-duty removal, version
  coupling, dependency inversion, cloneable handles, and unreviewed source
  drift; and
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

Brynja remains incomplete, must not secure application traffic, has no
independent cryptographic or protocol verification, and is not FIPS 140-3
validated.

## Release Process

v0.13.0 is an internal development milestone in the cumulative range after
v0.10.0 through v0.15.0 and selects zero crates for crates.io publication. It
does not activate a scheduled or exceptional pentest by itself. After the
complete local gate and GitHub and CodeQL are green, explicit repository-owner
authorization may create the signed `v0.13.0` tag.
