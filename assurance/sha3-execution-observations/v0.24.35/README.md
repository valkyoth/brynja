# v0.24.35 ordinary SHA-3/SHAKE native observations

Native functional collection completed on 2026-09-10 at
`f09aa8538c92fc3ba3537c3ca86844c1cda59c7b`. All 237 archived source/build/fixture
inputs are byte-identical to the reviewed implementation at
`010fb9ba73fa3bcd2fa49165066823080a709423`. No production Rust, dependency,
feature or CPU admission changed during collection. The owner supplied the Mac
log; the coding agent ran both AWS guests. These are project/operator observations,
not independent cryptographic verification or certification.

| Lane | CPU | Prefer / hosted Require | Static Require |
| --- | --- | --- | --- |
| macOS 26.6.2 ARM64 | Apple M2 Pro | `Runtime(ArmKeccak)` / `Runtime(ArmKeccak)` | `Static(ArmKeccak)` |
| Ubuntu 26.04 AWS Arm | Neoverse-V1 | `Runtime(ArmKeccak)` / `Runtime(ArmKeccak)` | `Static(ArmKeccak)` |
| Ubuntu 26.04 AWS Intel | Xeon Platinum 8488C | Portable fallback / typed rejection | `Static(X86Keccak)` |

Every successful mode passed 1,084 cases through the unchanged public consumer:
76 pinned NIST bit vectors plus 1,008 rate/bit/streaming comparisons across all
four SHA-3 hashes and both SHAKE XOFs. Portable mode passed on every host.
The fixture also verifies that quarantine of an accelerated owner prevents a
retained reader from writing output. Each AWS guest additionally passed 15
library and four execution integration tests with static acceleration enabled.

Generic Intel hosted Require returned exactly
`Unavailable(MissingMigrationGuarantee)` with exit code 1. This was explicitly
checked as expected rejection, not counted as accelerated execution. Preferred
hosted execution recorded `PortableFallback(MissingMigrationGuarantee)`.

All captures used Rust 1.98.1, commit
`48a229ceaefd4985c50990b14116b6d856af0985`, LLVM 22.1.8. Static Arm used
`-C target-feature=+neon,+sha2,+sha3`; static Intel used
`-C target-feature=+avx,+avx2`. Portable/hosted builds had inherited Rust flags
unset. Arm hosted execution preceded static entry; AWS feature lists also
confirmed each required ISA bundle. Both AWS guests had two CPUs and about
4 GB RAM, running kernel 7.0.0-1004-aws. No QEMU/emulated execution is counted here.

## Provenance and reproducibility

[observations.json](observations.json) preserves privacy-filtered route results,
original log hashes, compiler/CPU metadata and the exact source map. Both AWS
downloads matched SHA-256 values computed on the respective remote hosts.
All three logs end with `NATIVE_CAPTURE: PASS` after clean-checkout checks.
The AWS script was fail-fast and bounded each test command to 600 seconds;
its detached process exit status was not separately recorded. The Mac command
and log were owner-supplied; no remote access to the Mac occurred. A PASS marker
and authenticated SSH transfer are not hardware attestation.

Original logs and the AWS capture script remain gitignored under
`target/sha3-native-v0.24.35`. Public records omit usernames, local paths and
host addresses; the JSON transcripts are derived observations, not raw logs.
Import checks rejected 18 corrupted copies spanning missing completion,
wrong commit, wrong compiler, changed counts/routes and missing source binding.
The SHA-3 source-policy file digest recorded by all captures is
`348b051764d6886502aa6711fb1ab6c97919a61996885c87bbe085940ac70c3e`.

From the capture checkout, fetch locked dependencies, validate
`python3 scripts/sha3/check-sha3-execution.py --policy-only`, then run:

```sh
cargo +1.98.1 run --locked --offline --release --manifest-path assurance/sha3-execution/Cargo.toml -- portable
```

Repeat with `prefer` and, on supported Arm, `hosted`. Run `static` with the
matching flags above and a compatible deployment. Generic x86 hosted Require
must reject as described. The fixture accepts no evidence-only activation flags.
See the [public API guide](../../../docs/sha3-ordinary-execution.md).

## Limits and release disposition

These observations close the requested native functional collection for the
ordinary execution API. They do not qualify VM migration, heterogeneous cores,
hotplug, side channels, performance, registers, stack spills, caches or OS storage.
Hosted routes retain their OS/hypervisor feature-contract requirements; static
builds require compatible features on every CPU where they may execute.

The APIs remain public-data-only and non-erasing. No hardened acceleration,
independent cryptographic review or FIPS validation is inferred. Required local
release checks passed; green GitHub/CodeQL and explicit tagging permission remain pending.
This internal milestone selects zero crates.io publications.
