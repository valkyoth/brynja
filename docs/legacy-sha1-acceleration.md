# Legacy SHA-1 instruction candidates (v0.24.21)

SHA-1 remains collision-broken and **In progress** through v0.24.23. This
milestone adds ordinary public-data hardware candidates, not approved execution.
No modern facade, TLS, PKIX, FIPS or hardened owner gains a SHA-1 CPU route.

## API and isolation

`brynja-legacy-sha1` stays zero-allocation `no_std`, with its unchanged two
first-party dependencies. Opt-in `cpu` exposes `Sha1BackendSession` and the
consuming `AcceleratedSha1` byte/bit, streaming, one-shot and capacity APIs.
Kernels stay in private review-sized modules; no C, assembly file or external
cryptographic implementation is used. The frozen v0.24.20 portable consumer,
corpus and package dependency closure are unchanged.

`brynja-legacy-sha1-std` is a separate hosted observation/selection adapter.
Its opportunistic byte/bit and streaming APIs fall back to portable SHA-1;
required acceleration fails closed. It cannot mint an execution capability.
All new packages remain unpublished until an explicitly selected checkpoint.

Cargo feature unification means the hosted adapter's `cpu` dependency can expose
accelerated types to other consumers of the same leaf instance. Visibility is
not execution authority: the adapter never enables `cpu-evidence`, and ordinary
builds still reject candidates. Selecting all features also grants no admission.

Plain byte slices cannot prove that input is public. Direct callers must keep
secrets out of `AcceleratedSha1`; only the sealed hardened capability enforces
composition with secret-bearing constructions. An explicit public-data marker
may be considered before production admission, but a marker would be an assertion
by the caller, not proof of secrecy classification or cleanup.

| Candidate | Compiler features | Current disposition |
| --- | --- | --- |
| x86/x86_64 SHA-1 | `sha,sse2` | Unadmitted |
| Little-endian AArch64 SHA-1 | `neon,sha2` | Unadmitted |
| RISC-V, other architectures or unsupported endianness | None | Scalar only |
| Hardened/secret-bearing SHA-1 | Portable only | No accelerated cleanup qualification |

Rust groups the Arm SHA1 intrinsics under its `sha2` compiler feature. This
is a compiler naming convention, not a claim SHA-1 is SHA-2. The code implements
the FIPS 180-4 SHA-1 IV, 80 rounds, schedule and feed-forward, using both the
schedule and round instructions. See Rust's
[x86 intrinsics](https://doc.rust-lang.org/core/arch/x86_64/index.html) and
[AArch64 intrinsics](https://doc.rust-lang.org/core/arch/aarch64/index.html).

## Authority and cleanup limits

Production builds reject candidates before startup KAT or instruction use.
Unit tests and explicitly non-production builds using BOTH `cpu-evidence` and
`brynja_sha1_cpu_evidence` can force them only with exact static features or an
external execution authority. The shared `brynja_cpu_evidence` flag is ignored
by this leaf even when all features are enabled. The direct
KAT executes the actual kernel. KAT failure and lost-feature revalidation latch
session quarantine. Every buffered update/finalization and block revalidates;
backend failure clears the operation's owned regions and prevents continuation.
Length rejection is checked before mutation. Finalization consumes ownership.

A callback or non-Send/non-Sync marker does **not** prevent OS migration between
checking and executing an instruction. The documented external-constructor
contract requires feature validity on every CPU that may execute the whole
operation. Admission must add a reviewed migration-safe authority; flipping
`is_admitted()` is not sufficient. A new sibling session cannot authorize an
unadmitted production candidate. No global or FIPS module health is claimed.

The portable hardened implementation is unchanged. Accelerated schedules,
registers and compiler spills have no cleanup qualification: only public data
may use these candidate APIs. Existing owned-buffer Drop clearing is not an
accelerated secret-erasure guarantee. No FIPS validation, independent
cryptographic review, or production/military deployment approval is claimed.

## Reproducible checks and native collection

The CPU fixture reuses the exact v0.24.20 real-file/bit corpus and all 529 pinned
NIST SHA-1 vectors. Kernel tests compare 4,096 arbitrary state/block cases with
the portable implementation, plus byte/bit partitions and lifecycle failures.
Compiler-endpoint checks require x86 schedule/round and Arm schedule/round
instructions. AArch64 QEMU is supplemental correctness, never native evidence.
Additional 32-bit x86 QEMU execution was checked at both compiler endpoints.
Miri covers the non-executing quarantine/clearing model and ordinary admission
rejection; it does not execute the hardware kernels. Native AddressSanitizer
checks are separate from Miri and from production backend admission.

```sh
python3 scripts/sha1/check-sha1-cpu.py
python3 scripts/sha1/test-sha1-cpu.py
scripts/sha1/check-sha1-cpu-codegen.sh
scripts/sha1/check-sha1-cpu-qemu.sh
```

After pentest remediation is committed, fetch exact locked dependencies once
on each machine with `cargo fetch --locked` and
`cargo fetch --locked --manifest-path assurance/sha1-cpu-public-api/Cargo.toml`.
On the clean same commit, run one line (ordinary ASCII spaces):

```sh
python3 scripts/sha1/capture-sha1-cpu-native.py apple-m2-aarch64 target/sha1-m2.json
```

Other lanes are `amd-x86_64`, `intel-x86_64`, and `aws-aarch64`. Return the JSON
without editing it. It omits hostnames and records the exact commit/compiler,
source hashes, real-vector output, small exploratory throughput/timing samples
and residual restrictions. Vendor/OS feature checks precede candidate execution;
the capture rejects dirty/changing commits, source drift, wrong backend output,
and attempts to overwrite an existing artifact. These checks are regression-tested.
They do not authenticate cloud ownership or establish migration/side-channel
safety. These captures are operator-self-attested observations, not admission.
Any implementation change requires affected captures to be rerun. AWS/M2
access and reviewed native dispositions remain release preparation work.
