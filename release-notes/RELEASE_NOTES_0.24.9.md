# Brynja 0.24.9 Release Notes

Status: implementation and exceptional pentest complete with `PASS`/`PASS`
and zero open findings; hosted GitHub and CodeQL plus signed tag pending; no
crates.io publication is selected

Brynja 0.24.9 completes the ordinary arbitrary-bit FIPS 202 domain for
SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256. SHAKE now also
supports every output bit length. The family remains **In progress** until the
hardened state milestone at v0.24.10 and final combined acceptance at
v0.24.11.

## Added

- A distinct borrowed `Fips202BitString` that represents partial final bytes
  least-significant-bit first as required by FIPS 202 and rejects noncanonical
  nonzero unused high bits. It intentionally cannot be confused with SHA-2's
  high-bit-first `BitString`.
- One-shot arbitrary-bit functions for all four SHA-3 digests and both SHAKE
  XOFs, plus consuming final-tail methods for every streaming state.
- `Fips202Output` and consuming final-bit reader operations for exact SHAKE
  output lengths that do not end on a byte boundary. Unused high bits are
  cleared and output exhaustion is checked before caller memory changes.
- Reexports through `brynja-crypto` and `brynja`, and package-external
  `no_std` acceptance through both the leaf and facade.

## Verification

- Reproducibly import 76 records from the checksum-pinned official NIST
  `sha-3bittestvectors.zip` and `shakebittestvectors.zip` archives. The
  selection covers every input tail residue, exact-rate boundaries and every
  SHAKE output residue.
- Match all six official NIST five-bit examples and preserve byte-aligned
  equality with the frozen v0.24.3 APIs.
- Pass 440 independently implemented bounded Python Keccak cases across all
  six identities, rate boundaries, all message-tail widths and SHAKE output
  tails. The Rust adapter rejects oversized, malformed and noncanonical input
  without panic or unbounded allocation.
- Exercise exact suffix collisions, rate-minus/at/plus boundaries,
  multirate messages, partitioned SHAKE output and consuming partial-output
  transitions.
- Add three Kani bounds for canonical shape, checked quotient/remainder and
  tail masks, bringing the cumulative SHA-2/SHA-3 inventory to sixteen.
- Include the new bit-vector suite in Miri and the complete SHA-3 suite in
  AddressSanitizer, while retaining the workspace, Clippy, documentation,
  package, bare-metal, Rust 1.90.0-through-1.98.0 and source-policy gates.

## Security Boundaries

The APIs are allocation-free safe Rust and expose neither raw Keccak nor a
permutation state. A partial bit tail is accepted only through a consuming
finalization operation. SHAKE output after a partial byte is also consuming,
so a caller cannot resume at an ambiguous bit position.

These ordinary states are for unkeyed/public data and make no cleanup claim.
They must not own keys, passwords, or other secret-derived material. The
hardened v0.24.10 owner is responsible for clearing private sponge lanes,
buffers, suffix staging, squeeze cursors and Brynja-owned temporaries. Callers
remain responsible for the source and output copies they own.

This milestone does not establish independent cryptographic verification,
FIPS 140-3 validation, accelerated-backend admission, collision resistance by
testing, or suitability for classified deployment. NIST states that use of
CAVP vectors does not replace algorithm validation.

## Release Process

The new standards-visible bit representation, padding and XOF output boundary
triggered an exceptional pentest. The assessment of exact implementation
candidate `3f6669f670472cea4f2a162e545db456ee368530` reported no Critical,
High, or Medium finding. The permanent report records `PASS`/`PASS`, zero open
findings, and no remediation. Version 0.24.9 remains an internal development
milestone in the cumulative v0.20.0-to-v0.25.0 range and selects zero crates.io
packages. The report-bearing candidate must pass the complete local gate,
hosted GitHub and CodeQL and receive explicit tag authorization before the
signed tag is created.

Run the focused acceptance from a clean checkout with:

```bash
python3 scripts/sha3/check-sha3.py
python3 scripts/sha3/check-sha3-bit-differential.py
python3 scripts/sha3/check-sha3-public-api.py
```

The full local release gate additionally runs the separately pinned Kani,
Miri and Rust sanitizer evidence.
