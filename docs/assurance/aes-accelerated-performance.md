# AES setup and block-operation performance diagnostic

This package-external fixture compares the existing portable and accelerated
owners. It is a performance diagnostic, not fixed-versus-random side-channel
acceptance, a minimum-speed promise, or a new publication gate. The production
implementation is unchanged: selected hardware executes rounds while key
expansion still uses the portable fixed-work implementation.

## Policy declared before measurements

The initial experiment consists of exactly two native local Linux x86_64
observations: Rust 1.90.0/direct and Rust 1.99.1/direct, named
`local-x86-msrv-20261109` and `local-x86-current-20261109`. Collect them
sequentially, after fixture regression checks. Do not run other verification
campaigns concurrently with these measurements. There is no speed threshold,
outlier rejection, adaptive sample count, or retry-to-pass. Retain failures,
timeouts, every sample, host information and compiler/archive/binary identities.
These short observations are development diagnostics on a shared machine, not
statistically qualified target-wide performance or side-channel results.

Every binary uses opt-level 3, fat LTO, one codegen unit, overflow checks and
unwind panic behavior. Both compared backends are in the same binary with the
same `+aes,+sse2` flags; a baseline-compiled host probe runs before any specialized
binary. This does not establish CPU migration guarantees for arbitrary users.
The measurement subprocess is pinned to the lowest eligible logical CPU; prior
affinity is restored even on failure. Host load, governor, boost and SMT sibling
information are recorded, not tuned until a desired result appears.

The fixed 48-case population is three key widths × two owner forms × two
backends × four operations: construction/explicit clearing, secret encryption,
secret decryption and explicit public encryption. Each pair has eight warmup
batches, followed by nine samples of 64 operations. Portable/accelerated order
alternates each sample. Both durations are collected before printing. Every
sample is retained; summaries report median, minimum and maximum per-operation
cost, without accepting or rejecting the speed.

Construction/clearing measures the whole public constructor, explicit owner
clear and a full caller-storage residue fold; it is not a pure expansion cycle
count. Raw-key construction does not expand a schedule; cached construction
does. Block operations retain the owner across each timed batch, excluding its
construction/destruction. Raw owners expand and clear temporary schedules per
operation; cached owners do not. Both include public API checks, output
observation/copy and, for secret outputs, explicit clearing. Authority startup
and its known-answer tests are outside all timers. Storage setup, formatting
and final known-answer comparisons are also outside timers. All keys and inputs
are public FIPS 197 fixtures, not production secrets.

The fixture checks all 48 cases without measuring before collecting samples,
then checks each batch's final result. It tests both block directions against
the published AES-128/192/256 example ciphertexts. Four Rust regression tests
also cover malformed routes/counts, wrong outputs, operation failures and fixed
population. Python tests reject altered sample identities, order, populations,
diagnostics and incomplete output, and confirm that slow samples are retained.

## Use and evidence boundaries

```sh
# Routine correctness check: never takes performance measurements.
brynja-verify run aes --needed --category aes-performance-fixture

# Explicit one-off diagnostics, in the declared order, after correctness checks.
env -u LD_LIBRARY_PATH python3 scripts/aes/check-aes-performance.py --toolchain 1.90.0 --route direct --observation local-x86-msrv-20261109
env -u LD_LIBRARY_PATH python3 scripts/aes/check-aes-performance.py --toolchain 1.99.1 --route direct --observation local-x86-current-20261109
```

An observation name cannot overwrite an existing directory, including a failed
attempt. Artifacts remain under `target/aes-performance/NAME/`: raw process
output in `measure.json`, all samples and summaries in `summary.json`, host data
in `host.json`, and compiler, binary, fixture and archive hashes in
`identity.json`. Library sources come from byte-checked Cargo archives, not
checkout path dependencies. These working-tree observations are not clean-tag
certification records. Do not infer physical fault resistance, power/EM
protection, constant time, ARM behavior or minimum performance from them.

Both compiler endpoints and both API routes have registered fixture-correctness
checks, which do not pass `--observation`. A later native ARM performance study
needs a separately declared configuration; emulated timings are not substitutes.

## Integrated-expansion native experiment, declared 2026-11-10

The earlier 2026-11-09 observations used portable key expansion. They remain
historical baseline diagnostics and do not describe the integrated hardware
expansion. The following four new observations are declared before collection,
in this order:

1. `aws-arm-integrated-msrv-20261110`: AWS Neoverse-V2, Rust 1.90.0, direct API.
2. `aws-arm-integrated-current-20261110`: the same host, Rust 1.99.1, direct API.
3. `amd-integrated-msrv-20261110`: local Ryzen 9 9950X3D, Rust 1.90.0, direct API.
4. `amd-integrated-current-20261110`: the same local host, Rust 1.99.1, direct API.

Before collecting any of these observations, run the fixture's correctness-only
mode for both API routes and both compiler endpoints on each named host, and
run the Python regressions. Each measurement invocation also repeats its own
unit checks and exact-binary correctness preflight before measuring. Do not run
other verification campaigns on the measurement host during collection.

Keep the existing 48-case population and all 432 samples unchanged: three key
widths, raw/cached owners, portable/accelerated backends and four operations,
eight warmup batches and nine measured batches of 64 operations. Pair order
alternates by sample. Timer boundaries, public FIPS examples, output observation,
clearing and construction inclusion/exclusion remain exactly as described above.
There is no new statistical threshold, minimum speed, sample filtering or
retry-to-pass policy. These are performance diagnostics, not fixed/random
side-channel observations. A failed or partial observation remains recorded;
do not replace its directory or take another measurement with a new name merely
to obtain a preferred result.

Both targets use opt3/fat-LTO/cgu1/overflow/unwind. The explicit ARM target is
`aarch64-unknown-linux-gnu` with `+aes,+neon`, requiring `ArmAes` markers. The
explicit AMD target is `x86_64-unknown-linux-gnu` with `+aes,+sse2`, requiring
`X86AesNi` markers. Both routes use static admission after a baseline-compiled
native ISA probe; no QEMU runner is admitted. The hosted admission cost is not
measured. Portable and accelerated APIs are compared in the same executable.

The runner retains and executes the exact performance binary, rather than
deleting it with the private build directory. Retain compiler/archive/fixture
identities, full build and process logs, executable hash, raw samples and all
summaries. Pin each measuring process to the lowest eligible logical CPU and
restore affinity afterwards, including failure. Record host load, CPU details,
SMT siblings, governor and boost without adjusting them to improve a result.
The AWS machine is virtualized and the local host is not isolated; neither is
a controlled-frequency benchmark lab. Do not infer platform-wide throughput,
multi-block scaling, side-channel resistance or physical protection.

The source is the uncommitted v0.27.3 working tree based on v0.27.2, not a clean
tagged release. Retain hashes of the transported source bundle for AWS. These
observations add no publication gate and do not replace the separately planned
accelerated fixed-versus-random timing experiment.
