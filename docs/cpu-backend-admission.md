# Native CPU Backend Evidence And Admission

Status: v0.13.3 contracts implemented; zero backend implementations or admissions

## Purpose

Brynja admits an optimized CPU backend because one exact implementation is
correct, guarded, useful, and evidenced on the hardware where it will run—not
because a build target or processor brand appears compatible. Version 0.13.3
creates that admission route before any cryptographic ISA kernel exists.

The machine-readable policy is
`assurance/cpu-evidence-policy.toml`. The current decision register is
`security/cpu-backend-admissions.toml`; every one of the eight reserved
x86_64, AArch64, and RISC-V backends is `unadmitted`. The generated
`assurance/cpu-evidence-ledger.json` binds those decisions, registered lanes,
harnesses, and future evidence manifests reproducibly.

## Native Lanes

Five native lanes are registered:

- the repository owner's AMD x86_64 Linux host;
- an AWS x86_64 Linux host selected only after observing an Intel CPU and the
  required usable feature and operating-state predicates;
- the repository owner's Apple M2 AArch64 macOS host;
- an AWS AArch64 Linux host selected by observed capabilities; and
- the available RISC-V Linux cloud host, admitted only if its exact ratified
  ISA subset and enabled hart state qualify.

AMD, Intel, Apple, and QEMU lanes bind exact vendor identifiers; the other
native lanes still require a nonempty directly observed vendor identity. The
manifest's logical-CPU identity hash is deterministically derived from all CPU,
firmware, feature, state, and logical-CPU fields so model substitution cannot
retain the earlier identity. The AWS Intel lane is currently marked unavailable. That is an ordinary
unadmitted result, not a reason to block scalar builds or infer Intel support.
The other lanes are registered but unmeasured. Product names never substitute
for direct CPU, microcode or firmware, feature, operating-state, compiler, OS,
clock, frequency, isolation, and logical-CPU evidence.

The recorded runner owner is inventory metadata, not authentication. Version
0.13.3 has no admitted lane trust root and no reviewed signature or attestation
verifier. It therefore rejects every candidate backend and every native
performance, native side-channel, or admission-eligibility claim. A later
schema amendment must authenticate a canonical payload binding the source
commit, measured binary, environment, manifest, and artifact hashes before
candidate admission can exist.

QEMU x86_64, AArch64, and RISC-V lanes are registered separately as
supplemental instruction-coverage routes. Emulation cannot satisfy native
performance, cold-start, latency, throughput, or side-channel evidence and can
never make a backend admission-eligible.

## Evidence Contract

One future run binds all of the following in a bounded TOML manifest:

- source commit, backend, primitive, operation, runner owner, lane, timestamp,
  and execution kind;
- architecture, vendor, model, family, stepping, microcode or firmware,
  logical-CPU identity hash, exact observed features, and operating state;
- OS, kernel, virtualization, compiler and commit, target, flags, measured
  binary SHA-256, clock, frequency policy, and isolation;
- exact boundary-and-streaming input sizes, corpus and balanced-order schedule
  hashes, and sample count;
- forced-backend, required-no-fallback, unsupported-feature, KAT fault,
  permanent quarantine, scalar differential, concurrency isolation,
  emitted-code, code-size, cold-start, latency, throughput, and statistical
  side-channel results; and
- one size and SHA-256 for every machine-readable harness artifact plus an
  explicit residual statement that statistical side-channel testing is not
  proof.

Each harness artifact is exact JSON bound to the run, source commit, measured
binary, backend, lane, primitive, operation, full manifest context, declared
status, and harness-specific measurements. A text claim such as `FAIL: harness
was never executed` is rejected even if its submitter also changes the stored
hash. This semantic binding still is not runner authentication and therefore
cannot authorize a backend by itself.

Evidence expires after 90 days. A run needs at least 31 samples, at most ten
percent coefficient of variation, balanced interleaving with order-count
difference no greater than one, at least a five-percent speedup over scalar,
no more than 64 KiB code-size growth, and at most 5 ms cold-start overhead.
These initial budgets are security admission ceilings, not public performance
promises; primitive-specific milestones may tighten them through review.

Each manifest is limited to 1 MiB, a repository snapshot is limited to 256
manifests, and each raw artifact is limited to 16 MiB with the complete set
limited to 64 MiB. These bounds are enforced with
descriptor-bound limit-plus-one reads. Every metric is a bounded integer in a
named unit. NaN, infinity, implicit
units, unbounded files, symlinks, duplicate harnesses, missing raw files,
checksum differences, mixed logical CPUs, future or stale timestamps,
incomplete or overbroad feature sets, any operating-state value that differs
from the exact reviewed backend ABI prerequisites, architecture disagreement,
noisy data, and benchmark-order bias are rejected.

## Test Fixture And Limits

`assurance/cpu-admission-fixture` is a non-cryptographic, dependency-free
`no_std` model. It exercises scalar-only, positive forced mock execution,
unsupported-feature refusal, explicit opportunistic fallback, fail-closed
required mode, KAT fault injection, permanent quarantine, scalar differential
mismatch, and independent interleaved sessions. The repository compiles it on
the stable Rust matrix and OS-less targets and rejects atomic, allocation,
standard-library, and low-level code in the fixture.

The fixture does not implement or benchmark cryptography and is not backend
evidence. Cross-compilation and QEMU are supplemental preparation only. A real
backend remains unadmitted until its later primitive milestone provides the
exact native artifacts, admits a reviewed trusted-runner trust root and
signature verifier, and passes the v0.13.2 unsafe-boundary amendment,
independent review, and every v0.13.3 gate.

Run the current controls with:

```bash
python3 scripts/check-cpu-evidence.py
python3 scripts/test-cpu-evidence.py
scripts/check-cpu-admission-fixture.sh
```
