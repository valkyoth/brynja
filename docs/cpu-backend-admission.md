# Native CPU Backend Evidence And Admission

Status: v0.23.3 has five implemented SHA-2 candidates; zero backend admissions

## Purpose

Brynja admits an optimized CPU backend because one exact implementation is
correct, guarded, useful, and evidenced on the hardware where it will run—not
because a build target or processor brand appears compatible. Version 0.13.3
created that admission route before any cryptographic ISA kernel existed.

The machine-readable policy is
`assurance/cpu-evidence-policy.toml`. The current decision register is
`security/cpu-backend-admissions.toml`. Versions 0.22.1 through 0.23.3
implement the `x86-sha`, `aarch64-sha2`, `aarch64-sha512`,
`riscv-scalar-crypto`, and `riscv-sha512` SHA-2 candidates; all ten registered
identities remain
`unadmitted`. The generated
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
retain the earlier identity. The AWS Intel lane supplied an observed-feature
SHA-224/SHA-256 execution; that observation is not admission and makes no
SHA-512 acceleration claim.
The RISC-V lane has a sanitized capability preflight recorded in
`docs/riscv-native-host-inventory.md`: all harts lack `Zknh`, `Zvknha`, and
`Zvknhb`, so no candidate was executed and the lane is ineligible for SHA-2
acceleration evidence. The AMD, Intel, Apple M2, and AWS Arm lanes supplied
non-authorizing native candidate observations at the reviewed v0.23.3 source
commit.
Product names never substitute for direct CPU, microcode or firmware, feature,
operating-state, compiler, OS, clock, frequency, isolation, and logical-CPU
evidence.

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

## v0.22.1 Candidate Disposition

The two SHA-256 kernels, direct KAT, static selection, optional host detector,
scalar fallback, required mode, reporting, and quarantine paths are present.
Generated release assembly contains x86 `sha256rnds2` and AArch64 `sha256h`
plus `sha256h2`. The local AMD lane and supplemental forced AArch64 QEMU route
pass scalar differentials over official vectors, padding boundaries, and
arbitrary streaming partitions. GitHub also runs the non-authorizing candidate
configuration on x86_64, macOS Arm, and Linux Arm hosts.

Those observations are tests, not admission. The repository has not recorded
the canonical authenticated manifests, side-channel results, balanced
performance samples, or complete AMD, Intel, Apple M2, and AWS Arm evidence
required by this policy. Ordinary construction therefore rejects each
candidate before instruction use. An unavailable lane never weakens scalar
portability or turns a candidate into a support claim. Before runtime
admission, the safe adapter must also bind each later instruction call to a
reviewed migration-safe feature guarantee; making a session non-`Send` does
not itself prevent the operating system from moving its thread between logical
CPUs.

## v0.22.2 RISC-V Candidate Disposition

The implemented RISC-V identity is exactly RV64 `Zknh`. Its isolated kernel
uses `sha256sig0`, `sha256sig1`, `sha256sum0`, and `sha256sum1`; generic RV64,
`Zkn`, RVV, and processor naming are not substitutes. Rust 1.90.0 and 1.98.0
both emit those four instructions, and the full accelerated SHA-256
differential corpus passes under QEMU's explicit RISC-V model. The reserved
vector identity now names exact `Zvknha`; a future `Zvknhb` route requires its
own policy amendment. The vector identity
has no source implementation or low-level authority because the supported
Rust line lacks the stable vector intrinsic, runtime-detection, and
vector-state boundary needed by this project.

The scalar-crypto candidate is deliberately absent from automatic std runtime
detection. Ordinary construction rejects it as unadmitted, and a build without
compiler-proven `zknh` cannot select it statically. The registered native cloud
lane has not supplied qualifying ISA, correctness, performance, migration,
side-channel, or provenance evidence. QEMU cannot satisfy those duties.
Therefore the admission register retains zero active backends and makes no
RISC-V acceleration claim.

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
named unit. Artifact JSON accepts only signed 64-bit integers and rejects
floating-point values, non-finite constants, duplicate keys, and oversized
integers through controlled evidence errors. NaN, infinity, implicit units,
unbounded files, symlinks, duplicate harnesses, missing raw files,
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

## Detached Native Candidate Runs

The candidate runner applies the operational controls already proven useful in
`base64-ng` without copying its fuzz-specific targets. It creates a persistent
local session bound to one clean commit and tree. Local and SSH workers run in
detached sessions, and remote workers clone and check out that exact commit
before executing. A later status check retrieves a successful remote bundle
and validates it locally. State and SSH key paths stay under ignored `target/`
or the local SQLite database and are not evidence.

Initialize one session after the final pentest remediation commit:

```bash
python3 scripts/cpu/manage-cpu-evidence.py init
```

If pentest remediation or another reviewed change creates a new exact commit,
start a new session with `init --new`. The manager refuses this while any job
is marked running and archives the prior SQLite files instead of deleting or
relabeling them.

Run the local AMD lane and inspect it later:

```bash
python3 scripts/cpu/manage-cpu-evidence.py start-local local-amd-x86_64
python3 scripts/cpu/manage-cpu-evidence.py check local-amd-x86_64
```

An AWS worker uses the matching registered lane, observed host IP, SSH user,
and local private-key path. `--bootstrap-rustup` is optional and is the only
remote bootstrap mutation the manager can request:

```bash
python3 scripts/cpu/manage-cpu-evidence.py start-remote aws-intel-x86_64 \
  --host HOST --user ubuntu --key /absolute/path/to/key --bootstrap-rustup
python3 scripts/cpu/manage-cpu-evidence.py check aws-intel-x86_64
```

The same command accepts `aws-aarch64` and `riscv64-cloud`; the latter exits
before compilation unless `/proc/cpuinfo` identifies exact `zknh`. On the non-remotely accessible Apple
M2, the repository owner checks out the exact session commit and runs:

```bash
scripts/sha2/capture-sha256-cpu-native.sh apple-m2-aarch64 target/apple-m2-aarch64
```

After transferring that directory back without changing it, import it with:

```bash
python3 scripts/cpu/manage-cpu-evidence.py import apple-m2-aarch64 /path/to/apple-m2-aarch64
```

The resulting standard bundles prove clean-source SHA-256-family candidate
execution and native instruction emission. Supplemental exact-commit test and
assembly transcripts cover the SHA-512-family candidates on Apple M2 and AWS
Arm. Their manifest says
`authority=non-authorizing-native-candidate-observation`; they deliberately do
not satisfy the authenticated benchmark, side-channel, or admission schema.

Run the current controls with:

```bash
python3 scripts/cpu/check-cpu-evidence.py
python3 scripts/cpu/test-cpu-evidence.py
python3 scripts/cpu/test-cpu-evidence-runner.py
scripts/cpu/check-cpu-admission-fixture.sh
scripts/sha2/check-sha256-cpu-codegen.sh
scripts/sha2/check-sha256-cpu-qemu.sh
```
