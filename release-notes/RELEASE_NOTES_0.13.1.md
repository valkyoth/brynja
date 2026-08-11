# Brynja v0.13.1 Development Milestone

Status: implementation complete; awaiting green GitHub and CodeQL

Brynja v0.13.1 freezes the protocol-neutral CPU-backend capability, health,
and dispatch contract in `brynja-core`, advances the `brynja` facade to
0.13.1, and selects no crate for crates.io publication. It adds no CPU probe,
intrinsic, assembly, accelerated kernel, cryptographic algorithm, provider
effect, global registry, or FIPS-validated module.

## Implemented

- four explicit policies: scalar-only, opportunistic acceleration,
  required acceleration, and validated-module-only;
- sealed scalar, x86 SHA/AES-GCM/AVX2/AVX-512, AArch64 SHA-2/AES-GCM,
  RISC-V vector/scalar-cryptography, and validated-module identities;
- exact feature bundles and exact provider-operation capability sets for each
  inert backend profile;
- opaque feature evidence, KAT pass/failure evidence, active-backend authority,
  and exact-operation dispatch tokens with no public evidence constructor;
- caller-owned `Cell` health state with `NeverTested`, `Testing`, `Healthy`,
  and permanent `Quarantined` states, monotonic health generations, explicit
  runtime generations, and no atomics or global first-use state; and
- explicit scalar-fallback reasons only in opportunistic mode, with required
  acceleration and validated-module policy failing closed.

## Security Boundaries

Candidate profiles and selection reports are observational and cannot become
execution authority. Only an opaque complete-feature evidence value can create
an accelerated candidate, and only an exact trusted-provider KAT result can
complete initialization. A copied profile, public feature set, approval enum,
or report cannot construct either token.

KATs must call future direct backend entry points rather than dispatch. A
recursive initialization attempt permanently quarantines the backend. Panic,
cancellation, early return, or any other dropped initialization guard also
quarantines it. KAT result evidence is bound to the complete profile, health
generation, runtime generation, and service-approval state.

Active and dispatch tokens are non-copyable, non-cloneable, non-formattable,
and thread-bound through stable Rust auto-trait behavior. Every dispatch
revalidates backend identity, health, runtime generation, health generation,
and exact operation. Runtime replacement invalidates healthy authority and
requires a new KAT; permanent quarantine cannot be reset by that transition.

Validated-module identity and `Approved` observation are contract values only.
They do not claim FIPS 140-3 validation. Validated-module policy requires exact
opaque approved-module KAT evidence and never substitutes an accelerated or
scalar backend.

## Verification Evidence

- nine behavioral test groups cover feature bundles, success, direct failure,
  interruption, recursive first use, evidence mismatch, approval substitution,
  all four policies, explicit fallback, quarantine, runtime replacement,
  exact operations, and non-authorizing reports;
- seven compile-fail examples reject observational-profile injection, feature
  and KAT evidence forgery, and active-token cloning, formatting,
  cross-thread movement, and dispatch-token cloning;
- a SHA-256-locked four-file source policy confines each backend file below
  500 lines and rejects `std`, allocation, unsafe code, atomics, target/ISA
  coupling, intrinsics, assembly, FFI, registries, recursive fallback, token
  trait drift, public evidence constructors, and missing generation,
  operation, approval, or quarantine checks; and
- thirteen broken fixtures exercise execution, evidence, thread, generation,
  quarantine, operation, approval, registry, and source-hash regressions.
- the network freshness gate updates Miri and Rust sanitizer execution to
  `nightly-2026-08-11` at exact official Rust revision
  `12c36e2539c54397c51d6ea4401defd8768a4f5b`.

## Standards Authority Refresh

The clean candidate gate detected an official TLS Parameters registry update.
The reviewed delta replaces provisional draft references for three final
ECDHE-ML-KEM groups with Standards Track RFC 10024 and updates the references
on two obsoleted Kyber draft entries; it adds no new registry value. RFC 10024
is now checksum-locked as the exact authority for X25519MLKEM768,
SecP256r1MLKEM768, and SecP384r1MLKEM1024, has no reported errata, and changes
no existing errata record.

The former hybrid-source blocker is retained as a machine-readable resolved
record, and `BRY-REQ-HYB-0001` moves from blocked to planned. Protocol code,
group negotiation, ML-KEM, and hybrid key agreement remain absent and owned
only by v0.117.0 through v0.122.0. Draft and private group identifiers remain
forbidden. Requirements whose evidence embeds the refreshed IANA snapshot
receive explicit immutable revision increments even where their registry
records and dispositions did not change.

## Current Limits

No accelerated backend can be constructed through the public safe API in this
milestone. The safe scalar candidate is inert until a trusted provider returns
an exact KAT result. v0.13.2 owns the optional no_std ISA-kernel package, std
runtime-detection adapter, and separately reviewed unsafe boundary. v0.13.3
owns native-host, differential, emitted-code, side-channel, and performance
admission evidence. Later per-primitive milestones decide whether any backend
is useful and safe enough to activate.

The caller-owned no-atomics session serializes one thread by construction; it
does not implement a concurrent global cache. A later platform boundary must
issue a new runtime generation after fork or equivalent cloning. Startup KATs
can detect persistent implementation or toolchain faults but cannot prove the
absence of input-specific, transient, microarchitectural, or hardware faults.

Brynja remains incomplete, must not secure application traffic, has no
independent cryptographic or protocol verification, and is not FIPS 140-3
validated.

## Release Process

v0.13.1 is an internal development milestone in the cumulative range after
v0.10.0 through v0.15.0 and selects zero crates for crates.io publication. No
scheduled pentest applies unless an exceptional trigger is identified. The
complete local gate, green GitHub and CodeQL, and explicit repository-owner
authorization remain mandatory before the signed `v0.13.1` tag.
