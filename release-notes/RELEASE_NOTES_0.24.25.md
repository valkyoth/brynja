# Brynja 0.24.25 Release Notes

Status: owner pentest/retest and local release checks PASS; awaiting green GitHub/CodeQL and explicit tag permission

## Scope

The default-off `general-sha512-t` feature in `brynja-hash-sha2` adds:

- `Sha512TBits::new`/`TryFrom<u16>`: all 510 positive t below 512 except 384,
  exact bit identity and rounded output width.
- `write_iv_label`: shortest ASCII decimal label, bounded 9..=11-byte writes,
  atomic short-buffer rejection and unchanged trailing bytes.
- `initial_words`: the FIPS 180-4 XOR-modified SHA-512 IV generation, exactly
  one portable compression block over public t, not message hashing.
- `Sha512TDigest::from_bytes`: exact-width public digest import with canonical
  unused low bits, zero unused private storage and parameter-aware equality.
  General /224 and /256 types do not implicitly convert to named digests.

The contract now explicitly names the public diagnostic/import operations so
these value types are usable independently of next milestone's hash states.
No caller-provided IV import, secret input, secret owner or message-hashing
stub is introduced. Public values are copyable and not zeroized. They must not
be used as confidential state; ordinary equality is not authentication.

## Verification

The candidate includes exhaustive u16 admission, all label destination widths,
every t and last-byte canonicalization pattern, exact digest lengths and typed
identity tests; a separate Python oracle derives its constants from prime
roots and checks all 510 IVs, including normative named /224 and /256 values.
The oracle is repository tooling, not a runtime dependency.

An external no_std fixture exercises public value import and IV diagnostics;
compile-fail tests enforce default-off access, private parameter construction
and named/general identity separation. Source-hash and adversarial policy
checks bind feature isolation, model/oracle inputs and dynamic-analysis gates.
Eight compiled mutants must execute and fail assertions, including equality
that ignores the parameter. Verification-only Miri/sanitizer pins advance to
nightly-2026-09-08; production Rust stays 1.98.1 with MSRV 1.90.0.
See the [pentest report](../security/pentest/v0.24.25.md) for actual completed
local checks and the owner-supplied green retest; tests are not independent review.

Post-pentest release checks passed: the complete repository gate, twelve Rust
compiler lanes, bare-metal and QEMU campaigns, all ten local full Miri groups,
AddressSanitizer, all 29 registered Kani harnesses, current dependency/tooling
and authority checks, documentation/package checks, SBOM and publication policy.
LeakSanitizer was excluded because of the environment's ptrace restriction.
Miri groups ran concurrently on this workstation using the existing group
entry points; no remote evidence aggregation or native backend admission is
claimed. Post-review changes only update documentation and current hash-bound
metadata; no Rust implementation or dependency selection changed.

## Limits and release flow

General SHA-512/t stays **In progress**. Message hashing, hardened processing,
and their independent digest/lifecycle oracles remain v0.24.26 onward; final
family acceptance remains v0.24.29. Existing six named SHA-2 APIs are unchanged.
Short t has weak generic security bounds; no arbitrary t gains protocol, MAC,
signature or FIPS approval. All CPU candidates remain unadmitted. Brynja has
no independent cryptographic review or FIPS validation.

The facade advances to 0.24.25 without reexporting the new leaf types. Support
crate versions and exact-pinned sanitization 2.1.0 are unchanged. Zero crates
are selected for publication; next scheduled checkpoint remains v0.25.2.
After owner pentest/retest, complete release checks, commit the report, wait
for green GitHub/CodeQL and explicit tag permission.
