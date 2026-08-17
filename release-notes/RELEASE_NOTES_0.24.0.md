# Brynja 0.24.0 Release Notes

Status: remediation candidate; exceptional pentest retest, hosted
verification, and internal tag pending; no crates.io publication

Brynja 0.24.0 introduces first-party portable FIPS 202 SHA-3 ownership and
completes the named SHA3-224 and SHA3-256 algorithms. The complete SHA-3/SHAKE
family remains in progress through later v0.24.x milestones.

## Added

- A new allocation-free `no_std` `brynja-hash-sha3` leaf crate with distinct
  SHA3-224 and SHA3-256 streaming states, one-shot functions, closed errors,
  exact digest types, public traits, and checked `u128` byte counters.
- One private, safe-Rust Keccak-f[1600] permutation shared by both algorithms,
  with the exact 24 round constants, theta, rho, pi, chi, and iota steps.
- Exact FIPS 202 SHA-3 domain separation (`0x06`) and multi-rate final bit,
  while raw Keccak, SHA3-384, SHA3-512, SHAKE, and acceleration remain absent.
- Exact reexports through `brynja-crypto` and the modern `brynja` facade.
- Exact official SP 800-185 authority and a complete pre-1.0 roadmap for all
  fourteen cSHAKE, KMAC/KMACXOF, TupleHash/TupleHashXOF, and
  ParallelHash/ParallelHashXOF instances, with separate encoding, keyed,
  tuple, parallel, portable-usability, and cross-backend review units.
- A planned v0.24.5 cross-authority lifecycle monitor that will detect official
  document and publication-status drift without automatically admitting,
  disabling, or moving an implementation between modern and legacy policy.

## Verification

- Official NIST zero-bit and 1600-bit SHA3-224/SHA3-256 examples.
- Standard `abc` and million-`a` results, exact rate-minus-one, rate, and
  rate-plus-one padding vectors, and every tested irregular streaming split.
- A deterministic 328-message corpus checked for both algorithms against
  Python's independent OpenSSL-backed `hashlib` implementation.
- Two Kani harnesses for exact byte-counter overflow and all 200 Keccak state
  byte-to-lane mappings, separately paired with the pinned verifier toolchain.
- Miri over the focused library invariants and AddressSanitizer over all unit
  and integration cases, including the million-byte vectors.
- Hash-bound source and test inventories plus adversarial fixtures covering
  unsafe/native code, permutation visibility, round constants, theta, chi,
  suffixes, final padding, rates, claims, adjacent algorithms, package class,
  file size, and reviewed-source drift.

## Security Boundaries

The production implementation contains no unsafe Rust, foreign ABI, C or C++
code, assembly, third-party dependency, allocation, I/O, runtime detection, or
mutable global state. The raw Keccak permutation and sponge owner are private.

SHA3-224 and SHA3-256 are ordinary unkeyed hash APIs. They are not raw Keccak,
authentication, MACs, password hashing, or secret-bearing constructions.
Their ordinary states do not promise erasure of buffered input, permutation
state, registers, caches, crash snapshots, or compiler-created copies.

No SHA-3 code is independently reviewed or FIPS 140-3 validated. FIPS 202
remains the current NIST standard, but NIST's announced future update must be
reviewed when a draft or replacement final appears.

SP 800-185 remains the current final recommendation and its exact PDF is now
checksum-pinned as local-only authority. NIST's announced revision is recorded
as mutable status, not treated as unpublished normative text. The added roadmap
does not claim that any SP 800-185 function is implemented in v0.24.0.

## Pentest Remediation

The exceptional assessment found one High supply-chain trust-bypass issue:
241 generated files under the SHA-3 differential fixture's Cargo `target/`
directory had been committed, including two executable binaries. Cargo could
consider those fingerprints fresh and execute a tracked artifact instead of
rebuilding the reviewed fixture source.

All generated files have been removed. Cargo `target/` directories are now
ignored at every repository depth, the complete repository gate rejects any
tracked path containing a `target/` component, and the differential runner
uses a fresh temporary target with locked dependency resolution and
incremental compilation disabled. Three negative fixtures cover root, nested,
and crate-local target paths. No production Rust or cryptographic algorithm
code changed during remediation. The finding is closed locally with zero open
findings, but the tag remains blocked pending independent retest.

## Release Process

Version 0.24.0 is an internal milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates.io packages. The new
first-party permutation and algorithms trigger an exceptional pentest. The
remediated candidate, independent retest, complete local gate, hosted GitHub,
and CodeQL must be green before explicit tag authorization.
