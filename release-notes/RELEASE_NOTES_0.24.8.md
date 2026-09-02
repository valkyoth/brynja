# Brynja 0.24.8 Release Notes

Status: implementation complete; exceptional pentest, final repository gate,
hosted GitHub and CodeQL, and signed tag pending; no crates.io publication is
selected

Brynja 0.24.8 completes distinct hardened state APIs for SHA-224, SHA-256,
SHA-384, SHA-512, SHA-512/224, and SHA-512/256. These states accept the same
FIPS 180-4 byte and canonical arbitrary-bit messages as the ordinary APIs while
owning and destroying Brynja's source-declared secret-bearing memory. SHA-2
remains **In progress** until the combined family acceptance at v0.24.11.

## Added

- Six distinct, allocation-free, portable hardened streaming states sharing
  the already reviewed SHA-2 compression math.
- A sealed `HardenedSha2State` capability that downstream crates cannot
  implement or forge. Hardened states are not copyable, cloneable,
  formattable, serializable, snapshot-capable, resettable, or convertible to
  ordinary states.
- Byte and consuming canonical-bit finalization for every identity.
- Explicit `PublicDeclassification` authority for public digest output and
  typed `OwnedSecretRegion` ownership for digests that remain secret.
- One registered byte-backed owner for partial input, chaining state, message
  length, lifecycle phase, schedule, block copy, padding block, and staged
  output. Every region is cleared through Brynja's first-party compiler-
  resistant destruction boundary.
- Reexports through `brynja-crypto` and `brynja`, plus standalone downstream
  `no_std` consumers through workspace and assembled-package paths.

## Verification

- All six hardened identities match the ordinary algorithms across empty,
  short, padding-boundary, exact-block, multiblock, irregular streaming, and
  every partial-byte-width case.
- Public output length failure leaves the complete destination unchanged;
  secret output failure clears the complete destination. Typed secret output
  clears on `Drop` and recoverable unwinding.
- Compile-fail documentation rejects forged hardened capabilities, cloning,
  formatting, reset, and conversion into an ordinary state.
- Exact Rust-source contracts bind the owner fields, sealed capability, output
  rules, portable-only execution, downstream fixture, dynamic-analysis
  commands, and complete repository gate.
- Optimized MIR, LLVM IR, and x86_64 assembly confirm that `Drop` reaches the
  non-unwinding owner sanitizer and that all eight declared regions reach the
  first-party clearing boundary. The adjacent strict MIR verifier also checks
  exact caller, callee, receiver provenance, dominance, normal/unwind exits,
  alias escape, post-cleanup mutation, and return escape under Rust 1.90.0 and
  1.98.0.
- Two new Kani harnesses cover public failure atomicity and complete
  secret-output failure clearing, bringing the local SHA-2/SHA-3 inventory to
  thirteen. Miri and AddressSanitizer include the complete hardened behavior
  suite.
- The normal workspace, all-feature, no-default-feature, documentation,
  Clippy, bare-metal, package, dependency, SBOM, source-policy, and supported
  Rust/target gates remain mandatory.

## Security Boundaries

Ordinary SHA-2 states remain the efficient API for public and unkeyed data and
make no remanence-erasure claim. Secret-bearing consumers must select a
hardened state. Cleanup is mandatory in the leaf crate and does not depend on
the optional `brynja-sanitization` adapter or a downstream implementation.

The exact claim covers every Brynja-owned, source-declared byte region on
success, error, `Drop`, and recoverable panic unwinding. It does not guarantee
erasure of compiler-created copies, CPU registers, stack spills outside those
regions, caches, DMA-visible copies, core dumps, suspend images, physical
memory, `mem::forget`, process abort, forced termination, or power loss.
Caller-owned source buffers remain the caller's clearing duty. Hardened CPU
acceleration remains prohibited until an accelerated implementation has
equivalent state, spill, backend-lifecycle, and emitted-code evidence.

This milestone does not establish collision resistance by testing,
independent cryptographic verification, FIPS 140-3 validation, an approved
operational environment, or suitability for classified deployment.

## Release Process

New secret-state ownership and destruction behavior is an exceptional pentest
trigger. Version 0.24.8 is otherwise an internal development milestone in the
cumulative v0.20.0-to-v0.25.0 range and selects zero crates.io packages. The
exact implementation candidate must receive a committed `PASS`/`PASS` report
with zero open findings, pass the complete local gate plus hosted GitHub and
CodeQL, and receive explicit tag authorization before the signed tag is
created.

Run the focused acceptance from a clean checkout with:

```bash
python3 scripts/sha2/check-sha2-hardened.py
scripts/sha2/check-sha2-hardened-codegen.sh
```

The full local release gate additionally runs the separately pinned Kani,
Miri, and Rust sanitizer evidence.
