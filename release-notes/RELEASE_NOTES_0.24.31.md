# Brynja v0.24.31

Status: implementation candidate; exceptional owner pentest required.

## Static CPU execution authority

- Add the default-off `static-execution` feature in `brynja-crypto-cpu` with
  sealed caller-owned authority and borrowed, generation-bound sessions.
- Support exact x86 SHA-256, x86 AVX2 Keccak, Arm SHA-256, Arm SHA-512 and Arm
  SHA3 Keccak static bundles. Construction requires compiler target features
  and executes the actual kernel KAT. The deployment must satisfy the complete
  ISA and OS-state contract for every eligible CPU throughout execution.
- Keep testing and failed-KAT owners non-executable; quarantine invalidates
  every sibling session. Wrong operation, stale generation and unhealthy
  authority errors occur before caller-state mutation.
- Provide ordinary raw block/permutation APIs only. No hardened, hosted,
  legacy or RISC-V activation; existing high-level hash routes stay unchanged.
- Add normal extracted-package downstream vectors and lifecycle tests,
  compiled negative controls, compiler endpoint and Arm QEMU execution checks.
- Refocus the GitHub README on capabilities, architecture, usability and
  security boundaries. Individual release history stays in docs and reports.
- Refresh the Miri/AddressSanitizer verifier to `nightly-2026-09-09` and add a
  scoped `static_cpu` memory-test group. Stable Rust remains `1.98.1`, with
  compatibility from `1.90.0`; no runtime dependency is upgraded.

See [static CPU execution](../docs/static-cpu-execution.md) for API and exact
platform prerequisites. The crate facade advances to 0.24.31; support package
versions remain unchanged internally. All publication entries remain false;
the next crates.io checkpoint remains v0.25.2.

## Limits

No cryptographic kernel algorithm or external dependency is changed. Existing
legacy admission registers remain non-authorizing for their old dispatch paths;
the new static API has a separate explicit executable contract. Caller-owned
quarantine is not a process-global or FIPS module latch. Runtime fault detection,
register/spill erasure and CPU migration protection are not claimed.

These kernels must not own key-derived state, passwords or other confidential
input. Hardened accelerated ownership remains subsequent work. Native AMD
execution and AArch64 QEMU are not independent cryptographic review, native
Arm qualification, comprehensive side-channel proof or FIPS validation.

Complete the exceptional pentest and affected checks, commit the report, wait
for green GitHub/CodeQL and request explicit tag approval. No tag or publication
is authorized by implementation tests alone.
