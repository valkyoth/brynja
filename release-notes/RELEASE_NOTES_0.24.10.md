# Brynja 0.24.10 Release Notes

Status: implementation and exceptional pentest/retest complete; hosted GitHub
and CodeQL plus signed tag pending; no crates.io publication is selected

Brynja 0.24.10 adds the distinct hardened secret-bearing state family for all
four SHA-3 digests and both SHAKE XOFs. Ordinary public-data states remain
unchanged. The SHA-3/SHAKE family remains **In progress** until the final
combined package-external acceptance at v0.24.11.

## Added

- Sealed `HardenedSha3_224`, `HardenedSha3_256`, `HardenedSha3_384`, and
  `HardenedSha3_512` streaming states with complete byte and canonical FIPS 202
  arbitrary-bit input.
- Sealed `HardenedShake128` and `HardenedShake256` absorbing states plus
  distinct incremental reader typestates. Readers support zero-length,
  repeated, multi-permutation, and final arbitrary-bit output.
- Explicit `Sha3PublicDeclassification` for public output and affine
  `HardenedSha3SecretOutput` ownership for secret-derived output. Wrong-length
  public destinations remain unchanged; failed or dropped secret destinations
  are cleared completely.
- One private byte-backed hardened owner with eleven registered regions:
  sponge lanes, partial input, input/output counters, phase/cursors, suffix,
  padding and squeeze staging, and three permutation-scratch regions.
- Reexports through `brynja-crypto` and `brynja`, plus a standalone `no_std`
  downstream consumer for every fixed and extendable-output identity.

## Verification

- Compare hardened and ordinary output for all six identities across empty,
  text, every relevant rate boundary, multiblock input, irregular absorption,
  multi-permutation squeezing, all seven partial input widths, and partial
  SHAKE output.
- Exercise typed secret transfer and clearing, independent multi-squeeze
  destinations, zero output, wrong-length failure, cancellation, early Drop,
  recoverable panic unwinding, and every partial secret SHAKE output width.
- Register the exact secret owner and resolve its `Drop` call to its reviewed
  cleanup symbol in optimized MIR under Rust 1.90.0 and 1.98.0.
- Inspect development and release MIR, LLVM IR, and x86_64 assembly for the
  eleven cleanup calls and absence of source-created one-byte/eight-byte
  secret temporaries; source policy forbids byte-array lane/counter
  conversions, out-of-owner array expressions, unsafe Rust, FFI, allocation,
  accelerated dispatch, raw state export, unsealed capabilities, and missing
  output or lifecycle coverage.
- Add two bounded hardened final-output Kani properties, for eighteen
  cumulative SHA-2/SHA-3 harnesses, and include the full hardened suite in
  Miri and AddressSanitizer.
- Run the workspace, strict Clippy, documentation, bare-metal, package,
  Rust 1.90.0-through-1.98.0, and adversarial mutation gates.

## Security Boundaries

Hardened states are separate from ordinary states and cannot be copied,
cloned, formatted, serialized, reset, exported as raw sponge state, or marked
hardened by downstream code. They use only the portable safe-Rust permutation;
unadmitted accelerated candidates cannot process hardened state.

Cleanup covers all Brynja-owned source-declared byte regions and runs on
normal completion, failure, cancellation, Drop, and recoverable unwinding.
Lane and counter conversion uses scalar fixed-count operations, while partial
secret SHAKE output is staged and cleared inside the registered owner rather
than a local byte array.
Callers remain responsible for source buffers and copies they own. The crate
cannot guarantee removal of compiler-created copies, CPU registers, stack
spills, caches, swap, crash or suspend images, DMA copies, forgotten owners,
process abort, forced termination, power loss, or physical memory remnants.

This milestone does not establish independent cryptographic verification,
FIPS 140-3 validation, accelerated-backend admission, collision or security
strength by testing, final v0.24.11 family acceptance, publication, or
suitability for classified deployment.

The initial exceptional assessment reported one High secret-derived
byte-array remanence finding in the hardened permutation and partial secret
SHAKE output paths. Remediation replaced those arrays with bounded scalar
conversion and registered owner staging, added direct all-width cleanup
coverage, and strengthened development/release compiler-artifact gates. The
repository-owner retest of exact candidate
`b3232116a66f908524d859aa40d1b1ab8e31f913` passed with zero open findings.
The permanent report is
[`security/pentest/v0.24.10.md`](../security/pentest/v0.24.10.md).

## Release Process

The new secret-state and destruction boundary triggered an exceptional pentest.
Version 0.24.10 remains an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates.io packages. After the exact
candidate passed assessment and retest, its permanent report was committed
with the remediation. The complete local and hosted gates must be green, and
explicit tag authorization is required before creating the signed tag.

Run the focused acceptance from a clean checkout with:

```bash
python3 scripts/sha3/check-sha3-hardened.py
python3 scripts/sha3/test-sha3-hardened.py
scripts/sha3/check-sha3-hardened-codegen.sh
```

The full local release gate additionally runs the separately pinned Kani,
Miri, and Rust sanitizer evidence.

The report-bearing assurance-only follow-up moves full Miri and sanitizer
execution from the bounded 20-minute GitHub job into that local pre-tag gate.
GitHub continues to validate exact tool pins, script presence, coverage
bindings, mutation fixtures, and compiler-artifact evidence. No Rust source,
Cargo manifest, public API, digest result, dependency, or cryptographic claim
changes in that follow-up.
