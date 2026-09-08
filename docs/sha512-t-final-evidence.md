# General SHA-512/t final evidence

v0.24.29 completes the implementation evidence over the v0.24.28 frozen
[public consumer](sha512-t-public-acceptance.md). Status remains **In progress**
until the exceptional owner pentest/retest and native evidence disposition pass.
The ordinary [CPU API integration](sha512-t-cpu-evidence.md) reuses existing
unadmitted SHA-512 kernels. No facade reexport or third-party dependency is added;
hardened operations and default ordinary APIs remain portable-only.

## Reproduce the closure

```sh
python3 scripts/sha2/check-general-sha512-t.py
python3 scripts/sha2/test-general-sha512-t.py
cargo run --locked --offline --release --manifest-path assurance/general-sha512-t/Cargo.toml --bin general-sha512-t-profile
```

The first command checks the exact reviewed sources; regenerates the independent
510-IV and 4590-digest corpus; runs byte/bit, ordinary/hardened, failure and
ownership checks; inspects endpoint compiler cleanup; observes live destructor
storage; and repeats extracted-package acceptance. It then runs the new work
probe and fixed local performance campaign. Tests are not replaced by a saved
JSON success marker. The second command includes compiled algorithm, destructor,
package and work-probe mutants plus malformed-input and false-claim controls.

The local `target/general-sha512-t-final.json` records complete first-party
dependency Rust source hashes, fixture/tooling inputs, compiler/target identity,
50 timing rows and explicit non-approval flags. Capture rejects source drift
during execution. It is diagnostic, not a portable certificate or an input
that authorizes a release. The checkout and build environment must be trusted;
this is not a hostile-code sandbox. Logs and this generated local artifact are
not committed; the permanent [pentest record](../security/pentest/v0.24.29.md)
records actual runs and remaining review.

## Work, memory and side-channel scope

| Property | Evidence and precise limitation |
| --- | --- |
| IV derivation | One ordinary SHA-512 compression over a public decimal t label before accepting any secret |
| Message work | For n complete bytes: floor(n/128) + one final block when n mod 128 < 112, otherwise two; exactly 80 rounds per block |
| Instrumented coverage | All 510 t, eight lengths (0/1/111/112/127/128/129/1024), three public patterns, ordinary and hardened: 12,240 cases per debug/release profile |
| Instrumentation | Block-entry and round counters added only to an isolated copied crate; four omitted hooks and two shortened compression-loop mutants must each compile and fail a real work assertion in both profiles (12 mutant runs) |
| Object storage | Consumer enforces ordinary state <=256, hardened state <=1200, public digest <=72, secret output owner <=32 bytes; caller-owned output <=64 bytes for valid t |
| Error work | Length admission is checked before mutation. Invalid secret destinations are cleared in O(destination length), including oversized slices; callers bound their own buffers |
| Cancellation | Synchronous updates finish their supplied chunk; callers bound chunks and cancel between calls. No preemptive cancellation or hidden worker |
| Performance | Five representative t, five byte lengths, two public patterns, nine samples of eight operations; median ordinary and hardened nanoseconds. Includes IV derivation, correctness checks and secret output Drop |

Object ceilings are **not total stack bounds**. They exclude compression locals,
compiler temporaries, inlining, spills, ABI frames and caller storage. No stack
high-water, register-erasure, locked-memory or allocation-interception proof is
claimed. The production dependency closure remains safe, allocation-free no_std;
the profiling executable is separate hosted assurance code.

The source review classifies t, message/output lengths, loop indices, phase and
buffer occupancy as public. IV label selection branches on t. Absorption,
padding, canonicalization and output widths branch on those public sizes.
Compression uses fixed round/schedule ranges, public-index accesses and word
rotates/boolean/wrapping operations rather than message-indexed tables.
The block/round probes corroborate the work model for their declared inputs;
they do not observe every address, instruction, compiler-created copy or branch.
Timing measurements are reproducibility/performance observations, not a
statistical constant-time proof or a universal side-channel guarantee. Public
digest comparison/import is not a constant-time authenticator; confidential
inputs and outputs require hardened APIs. All existing physical-erasure limits
in the [lifecycle inventory](sha512-t-lifecycle.md) remain.

## Cross-target and acceptance disposition

The frozen no_std consumer remains in the existing twelve-compiler Rust
1.90.0–1.98.1 matrix and three bare-metal targets. Current local profiling is
native x86_64; other target builds are compilation evidence, not native timing.
The existing SHA-2 affected Miri group, local AddressSanitizer, Kani inventory,
ordinary/hardened exact-source cleanup checks and public acceptance all remain
required where applicable. No new general-algorithm-wide formal proof is claimed.
The local sanitizer wrapper explicitly runs the consumer library (including
its resource checks) and the hosted profile; source-policy tests reject removing
that coverage. Full dynamic analysis stays local, not in bounded GitHub CI.
Fresh AWS Arm/Mac capture is required for the new ordinary CPU integration after
the fresh owner pentest; follow the [capture instructions](sha512-t-cpu-evidence.md).
CPU admission and especially RISC-V native qualification remain separate.

After all these checks, reviewed native evidence disposition and a clean exceptional pentest, update the general
SHA-512/t implementation row to Fully implemented (portable). Keep independent
cryptographic review and FIPS validation negative. Short t has correspondingly
short collision/preimage strength; implementing general t does not approve it
for a protocol or an approved FIPS service.

The [official NIST FIPS 180-4 landing page](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
was checked on 2026-09-08: August 2015 remains final and a revision is planned.
The pinned authority and its redistribution restrictions are unchanged.
