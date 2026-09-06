# Brynja 0.24.21 Release Notes

Status: implementation candidate; exceptional pentest and reviewed native evidence pending

## Scope and deliverables

- Opt-in `cpu` feature in `brynja-legacy-sha1`: private first-party x86/x86_64
  SHA/SSE2 and little-endian AArch64 NEON/SHA1 schedule and round intrinsics.
- Distinct legacy identities, exact feature bundles, direct startup KAT,
  per-operation revalidation, permanent session quarantine, and neither-Send-
  nor-Sync session ownership. Production builds reject candidates before KAT.
- `AcceleratedSha1`: consuming public-data byte/bit one-shot and streaming APIs,
  checked capacity, terminal backend failure, private-owner clearing and
  compile-fail separation from hardened capabilities. Hardened SHA-1 is portable.
- Separate `brynja-legacy-sha1-std` host observation/fallback adapter with no
  third-party dependencies. Required acceleration fails closed: detecting a
  feature cannot mint a migration-safe execution authority.
- Frozen v0.24.20 vectors and actual file bytes plus all 529 pinned NIST vectors
  replayed through candidates; 4,096 arbitrary state/block differentials,
  canonical bit, streaming, quarantine, failure, compiler and mutation gates.
- Endpoint code-generation checks, supplemental AArch64 QEMU execution, and
  hostname-free exact-commit native capture instructions/tools.

All normal APIs and portable hardened algorithms remain available; the existing
portable consumer, corpus and dependency closure are unchanged. The facade
advances to 0.24.21 without publishing. The new adapter stays at unpublished
0.1.0. No existing support version or external dependency version changes.

## Security and evidence limits

All SHA-1 CPU candidates remain **unadmitted**. Raw instruction tests are not
operational approval. Before admission, native correctness, migration-safe
execution authority, performance/timing review and applicable cleanup evidence
are required. Checking features immediately before instructions cannot eliminate
OS migration between the check and use. Neither a callback nor thread-bound
marker is sufficient; admission is a reviewed architectural change.

Only public/unkeyed data may use accelerated candidate types. Kernel-local
vector schedules, registers and spills are not cleanup-qualified. No accelerated
hardened API exists. Existing portable owners continue their documented clearing;
abort, forget, termination, caller copies, caches, dumps and physical remnants
remain residual risks. SHA-1 is collision-broken and remains absent from modern,
TLS, PKIX and FIPS graphs. No independent cryptographic review or FIPS validation.

SHA-1 stays **In progress** until the v0.24.23 final family disposition. RISC-V
and unsupported targets remain scalar-only. Rust 1.90.0–1.98.1 is retained.

## Local verification

The repository gate, twelve-version Rust matrix, three bare-metal targets,
packaged portable/CPU/host consumers, strict Clippy, 34 candidate-policy mutation
cases and native-capture rejection tests pass. Forced local AMD and supplemental
AArch64 QEMU runs pass the frozen/NIST corpus and eight kernel/lifecycle groups.
32-bit x86 QEMU groups also pass on both compiler endpoints. Emitted-instruction
checks cover x86_64/AArch64 on Rust 1.90.0 and 1.98.1.

Focused Miri checks cover the instruction-free quarantine/clearing model and
ordinary-build admission rejection, not ISA execution. Native AMD instruction
tests pass AddressSanitizer with leak detection disabled for this environment.
These are local implementation checks, not independent review or native admission.
Current tooling, RustSec, dependency-policy and committed SBOM checks pass.

## Release workflow

The first pentest identified a Medium shared-build-cfg risk and two lower-
severity API caveats. SHA-1 evidence now requires its dedicated cfg AND the
non-default `cpu-evidence` feature; a shared flag or feature unification cannot
enable it alone. Five optimized negative build combinations, dedicated positive
controls and additional policy mutations cover this remediation. Persistent
evidence flags and secret input to ordinary accelerated APIs remain prohibited.
The owner retest is pending; no backend was admitted.

Complete local checks, request an exceptional pentest, address any findings and
collect/review exact-commit native observations on AMD/Intel/M2/AWS Arm where
available. Record unsupported/unavailable lanes honestly. Commit the report,
wait for green GitHub/CodeQL and explicit owner tag permission. Zero crates are
selected for upload at this internal milestone.

See [the API/evidence contract](../docs/legacy-sha1-acceleration.md) and
[candidate report](../security/pentest/v0.24.21.md).
