# Post-1.0 RISC-V Qualification Plan

Status: planned post-1.0 community evidence campaign; not a v1.0.0 blocker and
not a backend-admission record

Brynja intends to broaden native RISC-V hardware evidence after the first
production release. The project will publish reproducible capture instructions
and ask the Rust and RISC-V communities for access to machines whose exact ISA
extensions are not available on the project's registered host.

This campaign broadens observed hardware coverage. It does not turn a forum
message, product name, QEMU result, or unauthenticated log into cryptographic
proof, independent review, FIPS validation, or permission to dispatch a CPU
backend.

## Evidence Before The Campaign

The registered native host is used wherever its common all-hart ISA actually
supports the operation under test. Its sanitized inventory is recorded in
[`riscv-native-host-inventory.md`](riscv-native-host-inventory.md).

- Portable scalar RV64 behavior may run natively.
- Generic vector, embedded-vector, and bit-manipulation experiments may run
  natively only when they require extensions present on every eligible hart.
- Each experiment must name its exact required bundle; one observed extension
  cannot qualify another operation or family.
- The host cannot execute the current SHA-256 `Zknh` candidate or substitute
  generic `V`, `Zve*`, `Zbc`, `Zkt`, or `Zvkt` for missing SHA instructions.
- Where exact hardware is unavailable, Brynja uses cross-compilation,
  generated-instruction checks, and QEMU differential execution as
  supplemental evidence only. Documentation must label such a path
  **QEMU/codegen-only** and keep it unadmitted.

Native evidence on the registered host remains subject to the normal clean
commit, exact compiler, per-hart capability, migration, KAT, differential,
performance, side-channel, provenance, and review requirements. Hardware
presence alone is never admission.

## Community Campaign

After v1.0.0, maintainers will publish a public request in appropriate Rust
and RISC-V community forums and project discussion channels. The request will
prioritize real RV64 systems exposing exact ratified bundles needed by an
implemented but unadmitted backend, initially:

- scalar SHA-2 `Zknh`;
- vector SHA-2 `Zvknha` and, separately, `Zvknhb`;
- scalar AES `Zkne` and `Zknd`, and vector AES `Zvkned`;
- vector GCM `Zvkg`;
- ShangMi bundles such as `Zksh`, `Zksed`, `Zvksh`, and `Zvksed`; and
- later exact RISC-V bundles named by implemented post-quantum or other
  accelerated operations.

Requests must distinguish homogeneous machines from heterogeneous systems and
must collect the capability intersection of every hart on which a task may
run. A model name, vendor statement, aggregate `/proc/cpuinfo` line, or
compiler-recognized target feature is insufficient.

## Reproducible Contributor Route

Before requesting results, Brynja will publish a small, versioned capture kit
using the repository's detached evidence runner. Instructions must let a
contributor:

1. check out one immutable signed commit or tag and verify its identity;
2. run a read-only capability preflight before compiling or executing an
   instruction-specific candidate;
3. record sanitized CPU, hart, firmware, OS, ABI, compiler, linker, flags,
   frequency-governor, and migration information;
4. force the exact candidate through startup KATs, official vectors, scalar
   differentials, boundary inputs, and unsupported-feature negative tests;
5. capture emitted instructions, raw measurements, transcripts, manifests,
   and checksums without credentials, endpoints, hostnames, or personal data;
6. package the result for offline validation by the repository-owned verifier;
   and
7. retain enough raw material for an independent maintainer to reproduce or
   reject the observation.

Slow or remotely accessed machines receive focused bounded jobs, persistent
state, resumable retrieval, and explicit disk/time estimates. A contributor
must not need to expose remote login access: locally executed capture and an
offline bundle are the preferred route.

## Review And Admission Boundary

A community bundle enters the register as a candidate observation. It can be
useful only after its schema, checksums, source commit, lane identity, exact
feature bundle, transcript, generated instructions, and privacy sanitization
pass local verification.

Backend admission remains a separate reviewed decision. It additionally
requires authenticated provenance, native correctness and migration evidence,
representative performance and code-size results, side-channel assessment,
failure/quarantine behavior, supported-compiler coverage, reproducibility, and
the independent security review required by the applicable milestone. No
single contributor, machine, benchmark, forum post, or QEMU run is sufficient.

If those requirements cannot be met, the backend remains implemented but
unadmitted and the portable scalar path remains authoritative. Negative and
unsupported results are recorded as useful coverage rather than pressured
into a support claim.

## Campaign Deliverables

- A public hardware-needs matrix mapping operations to exact ISA bundles and
  missing native lanes.
- A versioned capture kit with checksums, expected duration/storage, privacy
  guidance, and failure recovery.
- Sanitized capability inventories distinct from admission-grade evidence.
- Locally validated candidate bundles and an explicit accepted/rejected status.
- Reproduction on another qualifying system when practical, especially for
  heterogeneous-hart and migration-sensitive cases.
- Updated backend-admission, verification-status, residual-risk, and support
  documentation after every reviewed decision.

This work improves post-1.0 hardware coverage without retroactively expanding
the guarantees or supported acceleration claims of v1.0.0.
