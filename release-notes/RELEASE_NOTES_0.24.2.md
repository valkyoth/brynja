# Brynja 0.24.2 Release Notes

Status: implementation complete; exceptional pentest pending; no crates.io
publication

Brynja 0.24.2 completes portable SHAKE128 and SHAKE256 over the private
Keccak-f[1600] sponge introduced in v0.24.0. All six FIPS 202 functions now
have complete leaf and facade APIs, while portable package acceptance and
accelerated final acceptance remain v0.24.3 and v0.24.4 work.

## Added

- Distinct allocation-free `no_std` `Shake128` and `Shake256` absorbing states
  with checked `u128` input domains and transactional streaming updates.
- Separate non-cloneable `Shake128Reader` and `Shake256Reader` output states,
  making absorption after squeezing structurally impossible.
- One-shot caller-buffer APIs plus incremental repeated squeezing, valid zero-
  length output, checked `u128` output accounting, and failure-before-mutation
  preflight.
- Exact 168-byte SHAKE128 and 136-byte SHAKE256 rates with the FIPS 202 `0x1f`
  domain suffix and final `0x80` padding bit.
- Algorithm-neutral `ExtendableOutput` and `XofReader` interfaces in the
  unpublished `brynja-hash-core` boundary.
- Exact reexports and implementation flags through `brynja-hash-sha3`,
  `brynja-crypto`, and the `brynja 0.24.2` facade.

## Verification

- Official FIPS 202 zero-bit and 1,600-bit SHAKE128/SHAKE256 examples.
- Exact rate-minus-one, rate, and rate-plus-one input values; bounded irregular
  input partitions; 343-byte output partition campaigns crossing multiple
  squeeze permutations; zero-length output; trait use; counter behavior; and
  fixed-output SHA-3 domain-separation negatives.
- A deterministic 328-message corpus checks all four SHA-3 digests and both
  SHAKE XOFs against Python's independently maintained `hashlib` path with
  caller-selected outputs from zero through 343 bytes.
- Forty-three source-policy mutation fixtures cover unsafe/native code,
  allocation, visibility, permutation operations, SHA-3/SHAKE suffixes,
  padding, all six rates and identities, XOF transitions, input/output counter
  ownership, authoritative-vector gates, dynamic-analysis commands, package
  boundaries, file size, and reviewed-source drift.
- The Kani inventory now contains nine bounds: six SHA-2 bounds and three
  shared FIPS 202 bounds covering checked input length, checked output length,
  and all 200 Keccak byte-to-lane mappings. Hosted CI remains policy-only;
  complete proofs are required locally before the tag.
- The CI-invoked Miri script runs both SHAKE boundary suites, while the
  AddressSanitizer script runs every SHA-3/SHAKE test target.

## Security Boundaries

The production implementation contains no unsafe Rust, foreign ABI, C or C++
code, assembly, third-party dependency, allocation, I/O, runtime detection, or
mutable global state. Raw Keccak and Keccak-f[1600] remain private.

Absorption consumes into a separate output reader. Callers cannot squeeze
before finalization or absorb after squeezing through the public type system.
Output work is linear in the public caller-selected output length; protocols
must apply their own semantic output bounds.

These are ordinary unkeyed XOF APIs, not authentication, MACs, password
hashing, or secret-bearing constructions. Their ordinary states do not promise
erasure of buffered input, permutation lanes, stack copies, registers, caches,
or crash snapshots. Later keyed constructions must own and verify hardened
secret-state cleanup.

No SHA-3 or SHAKE code is independently reviewed or FIPS 140-3 validated. FIPS
202 is the pinned current algorithm authority; its announced future revision
remains subject to the explicit standards-lifecycle gate.

## Release Process

Version 0.24.2 is an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates.io packages. The two newly
admitted XOF algorithms and their absorbing-to-squeezing state machine trigger
an exceptional cryptographic pentest. After the report and any remediation are
committed, the complete local gate and hosted GitHub/CodeQL must pass before
explicit signed-tag authorization.
