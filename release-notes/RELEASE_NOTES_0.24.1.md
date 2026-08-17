# Brynja 0.24.1 Release Notes

Status: pentest remediation complete; independent retest, hosted verification,
and signed tag pending; no crates.io publication

Brynja 0.24.1 completes the portable fixed-output FIPS 202 SHA-3 algorithms by
adding SHA3-384 and SHA3-512 over the private Keccak-f[1600] sponge introduced
in v0.24.0. SHAKE and final SHA-3/SHAKE family acceptance remain later work.

## Added

- Distinct allocation-free `no_std` `Sha3_384` and `Sha3_512` streaming states,
  one-shot functions, closed errors, exact 48-byte and 64-byte digest types,
  checked `u128` message domains, transactional updates, and consuming
  finalization.
- Exact 104-byte SHA3-384 and 72-byte SHA3-512 sponge rates with the FIPS 202
  SHA-3 domain suffix and padding over the unchanged private permutation.
- Exact public reexports and implementation-status flags through
  `brynja-hash-sha3`, `brynja-crypto`, and the `brynja 0.24.1` facade.

## Verification

- Official FIPS 202 zero-bit and 1,600-bit SHA3-384/SHA3-512 examples.
- Standard `abc` and million-`a` results, exact rate-minus-one, rate, and
  rate-plus-one padding values, irregular streaming partitions, common-trait
  use, exact output identity, and raw-Keccak domain-separation negatives.
- A deterministic 328-message corpus checked for all four fixed-output SHA-3
  algorithms against Python's independently maintained `hashlib` path,
  producing 1,312 matching results.
- Twenty-nine source-policy mutation fixtures covering unsafe/native code,
  allocation, visibility, permutation constants and transformations, suffixes,
  padding, all four rates and output widths, claims, authoritative vector
  gates, package boundaries, Miri and AddressSanitizer command removal, file
  size, and reviewed-source drift.
- The existing shared Kani harnesses continue to prove exact checked `u128`
  byte admission and all 200 Keccak byte-to-lane mappings for every fixed-
  output state. The CI-invoked Miri script now executes the SHA3-384 and
  SHA3-512 boundary tests, and the CI-invoked AddressSanitizer script executes
  every SHA-3 test target; the SHA-3 policy rejects removal or narrowing of
  either path.

## Security Boundaries

The production implementation contains no unsafe Rust, foreign ABI, C or C++
code, assembly, third-party dependency, allocation, I/O, runtime detection, or
mutable global state. Raw Keccak and the underlying permutation remain private.

These are ordinary unkeyed hash APIs. They are not authentication, MACs,
password hashing, or secret-bearing constructions. Their ordinary state does
not promise erasure of buffered input, permutation state, registers, caches,
crash snapshots, or compiler-created copies. Later keyed constructions must
own and verify their separate secret-state cleanup boundary.

No SHA-3 code is independently reviewed or FIPS 140-3 validated. FIPS 202 is
the pinned current algorithm authority; the announced future NIST revision
remains subject to explicit lifecycle review when normative text is available.

## Pentest

After an initial green result, subsequent review identified one Medium
verification-control finding: the release notes claimed Miri and
AddressSanitizer coverage for SHA3-384/SHA3-512 that the committed CI scripts
did not enforce. Direct analysis had passed, so no memory defect was shown.
The scripts and SHA-3 policy now enforce the claimed coverage, four broken
fixtures reject its removal, and both remediated analysis scripts pass
locally. The permanent report records zero open findings and remains
`RETEST REQUIRED`/`PENDING` until independent retest.

## Release Process

Version 0.24.1 is an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates.io packages. It adds two
fixed-output parameterizations over the already assessed private sponge, with
no new primitive owner, unsafe boundary, backend, or dependency. The final
committed candidate must pass independent retest, the complete local gate, and
hosted GitHub and CodeQL before explicit signed-tag authorization.
