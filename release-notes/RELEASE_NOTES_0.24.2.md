# Brynja 0.24.2 Release Notes

Status: Medium assurance-tooling finding remediated; independent retest
pending; internal development tag; no crates.io publication

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
- Fifty-one source-policy mutation fixtures cover unsafe/native code,
  allocation, visibility, permutation operations, SHA-3/SHAKE suffixes,
  padding, all six rates and identities, XOF transitions, input/output counter
  ownership, authoritative-vector gates, dynamic-analysis commands, package
  campaign input/case/output allocation and child timeout boundaries, file
  size, and reviewed-source drift.
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
an exceptional cryptographic pentest. The repository-owner assessment of exact
implementation candidate `208c0b07d152d3a5c8316093e98b29c89f332c07`
was initially reported green, after which one overlooked Medium denial-of-
service finding was supplied for the repository-only differential adapter.
The adapter now enforces its 343-byte XOF campaign ceiling before allocation,
uses fallible output and hex reservations, and rejects 344, `usize::MAX`, and
numeric overflow without panic. The first retest confirmed that remediation
and identified a second Medium aggregate-input/case and missing-timeout gap.
The adapter now also caps stdin at 8 MiB and campaigns at 1,968 cases, uses
fallible decode/render allocations, rejects both aggregate attacks, and gives
every child run a 240-second timeout. Production SHAKE code is unchanged.
Local second-remediation verification passes; independent second retest is
pending. After retest, the exact report commit must pass the complete local
gate plus hosted GitHub and CodeQL checks before explicit signed-tag
authorization.

The mandatory freshness pass moves the default and complete release gate to
official stable Rust 1.98.0 while preserving Rust 1.90.0 as the MSRV and every
intervening stable in CI. The compiler-sensitive Kani 0.67.0 pairing remains
separate on Rust 1.90.0. Miri and AddressSanitizer advance to the latest
available Miri-capable `nightly-2026-08-28` at exact Rust revision
`e457a7b0d326d67b4322ef0d11bd715cfaeda48f`.

The same pass confirms `sanitization 2.0.3`, cargo-deny 0.20.2, cargo-audit
0.22.2, cargo-sbom 0.10.0, Kani 0.67.0, AFL++ 5.02c, honggfuzz 2.6, and the
full-SHA actions/checkout v7.0.1 pin are current. No crate or CI tool version
change beyond the Rust stable/nightly pins is required.

Rust 1.98's style-only `chunks_exact_to_as_chunks` Clippy lint is explicitly
allowed by the full gate to avoid semantically neutral rewrites of reviewed
fixed-width cryptographic loops; every other warning remains denied and all
existing source-policy, correctness, and code-generation checks remain bound.

The release-time live standards gate also detected official IANA SMI Numbers
and DNS Parameters updates dated 2026-08-18 and 2026-08-24, plus RFC 3986
erratum 9147 reported on 2026-08-27. Independent review confirmed the exact
registry and metadata deltas, including two draft-to-RFC 10031 SMI reference
changes and provisional C509, DNS type, and DELEG allocations. The refreshed
evidence retains the existing future milestone owners and admits no new
authority, SHAKE change, or runtime behavior.
