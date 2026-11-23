# GHASH acceleration: v0.28.2 development

The signed v0.28.1 package fixture remains the portable baseline. The first
v0.28.2 candidate is an x86_64 field multiply available in CPU-crate unit
tests and an explicit hosted checkout evidence build. The later
[runtime integration](#x86-production-route-review-v0282) makes PCLMUL available
on explicit request, as do the [Linux RV64 scalar route](#rv64-public-scalar-route)
for Zbc and the [Arm PMULL route](#arm-public-pmull-route). Enabling all
features does not accelerate `Ghash::new`.

The kernel takes the same big-endian numeric block representation as portable
GHASH (the top bit represents one). It reverses the coefficient order, computes
four 64-by-64 carry-less products, reduces the 256-bit result modulo
`x^128 + x^7 + x^2 + x + 1`, then converts back. Neither AES instructions nor
VPCLMUL are required.

On Linux x86_64 with PCLMULQDQ and SSE2, run:

```sh
brynja-verify run ghash pclmul-candidate-msrv
brynja-verify run ghash pclmul-candidate-latest
```

Each check explicitly selects the native tests: all 16,384 pairs of single
coefficient bits, edge values, 512 dense deterministic product and associativity
cases, and a published multiblock GHASH intermediate. Missing CPU features
fail the selected test; a skipped or zero-test run cannot pass the verifier.
Both native suites now exercise these products through a thread-bound,
test-only selector. It checks PCLMULQDQ and SSE2 independently of AES and
executes a fixed known-answer multiplication on that same kernel before first
use. Only an absent instruction bundle can return a portable route in
prefer mode; require mode rejects it. A wrong startup answer or unwind during
startup or use retires that owner. A successful startup test is not a
per-product correctness or physical-fault guarantee.

For the separate negative control run
`brynja-verify run ghash pclmul-unavailable-qemu`. QEMU exposed AES and SSE2
but not PCLMULQDQ; the unmodified detector returned portable in prefer mode,
and both required selection and direct product use failed as unavailable.
This is emulated routing evidence, not a native timing observation. The
portable fallback is a route decision; the forced incremental build below
requires the native path and cannot fall back.

Both registered checks passed on an AMD Ryzen 9 9950X3D (Linux x86_64)
on 2026-11-22, on Rust 1.90.0 and 1.100.0 respectively. The optimized
MSRV test binary's multiply function contained four PCLMUL instructions.
The [verifier records](../VERIFICATION_RESULTS.md#ghash) identify the scoped
inputs; no Intel, Arm or RISC-V native observation is inferred.

## Forced incremental owner

```sh
brynja-verify run ghash pclmul-incremental-msrv
brynja-verify run ghash pclmul-incremental-latest
brynja-verify run ghash pclmul-incremental-qemu
```

The first two commands build the real `Ghash` owner with
`--cfg brynja_ghash_pclmul_evidence` and the existing CPU dependency.
The portable multiplier is not compiled into that owner. The selected native
kernel counts completed data blocks, excluding startup. Tests compare 64
three-block messages with polynomial long division at all 49 two-chunk
splits, check the count before and after rejected updates, and exercise
incomplete tails. The same build runs the existing NIST and caller-storage
lifecycle suites, including canaries and unwind cleanup. The direct arithmetic
oracle tests that explicitly import the scalar field source remain scalar tests.

The QEMU control exposes AES but not PCLMULQDQ. The ordinary constructor
signature cannot return an error, so the forced build retains an unavailable
state: even an empty update or finish must fail, without releasing a result.
The caller's workspace clears and the output remains unchanged. This behavior
and the block counter do not exist in the normal portable build.

These are checkout-level owner tests, not packaged accelerated acceptance,
performance measurements, a new timing campaign or proof of register clearing.

## Pairing scalar AES with x86 GHASH

```sh
brynja-verify run ghash pclmul-scalar-aes-msrv
brynja-verify run ghash pclmul-scalar-aes-latest
brynja-verify run ghash pclmul-scalar-aes-qemu
```

The fixture uses Encrypt-Generate example 3 from the [NIST worked
examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf)
for AES-128, AES-192 and AES-256. Each width is tested twice, with an
operation-local and a caller-cached scalar key schedule. Neither AES CPU
execution feature is enabled. Scalar AES derives both the hash subkey and
the mask. GHASH borrows the actual derived subkey, not the expected bytes.
The fixture passes the five pre-framed blocks in 13-byte chunks, requires
exactly five native products, and checks the subkey, GHASH sum, mask and
masked result separately. It also checks that caller-owned secret storage
is cleared when its owners are released.

The QEMU variant runs the same vectors and independently asserts PCLMULQDQ
is exposed while AES-NI and VAES are hidden. It checks that the two
primitive selections are independent; it is not native performance evidence.
All three registered checks passed on 2026-11-22: the two native runs were
on the AMD Ryzen 9 9950X3D, and the third used QEMU on that host.
This fixed AAD-only example has no ciphertext, caller-selected IV, seal/open
interface or authentication decision. It is not a GCM implementation.

## AArch64 field arithmetic under emulation

On Linux x86_64 with QEMU user mode and the `aarch64-unknown-linux-musl`
target installed for each Rust toolchain, run:

```sh
brynja-verify run ghash pmull-field-qemu-msrv
brynja-verify run ghash pmull-field-qemu-latest
```

The little-endian Arm candidate reflects the wire coefficients and uses three
64-by-64 PMULL products: low, high, and the product of the XORed halves.
It reconstructs the middle coefficients before reducing modulo the same
GHASH polynomial. Both architectures replay the same wire-order serial
oracle, basis pairs, dense inputs and NIST recurrence. An optimized Rust
1.90.0 Arm test binary contained three PMULL instructions in the field kernel.

The Arm tests require positive NEON, Rust AES target-feature bundle, and
PMULL detection before invoking the intrinsic. An AES identity alone is not
authorization. Under QEMU the complete bundle must pass a direct known-answer
multiplication before the first data block. All seven incomplete permission
masks must reject required acceleration without calling the kernel. A wrong
startup answer or an unwind during startup or use retires the owner; prefer
mode cannot override that decision. The x86 and Arm candidates now share this
state machine, but each detects its own features and runs its **own** kernel.

## Incremental PMULL and scalar AES under emulation

```sh
brynja-verify run ghash pmull-incremental-qemu-msrv
brynja-verify run ghash pmull-incremental-qemu-latest
brynja-verify run ghash pmull-incremental-qemu-denied
```

The positive checks compile PMULL into the incremental owner in place of
the portable multiplier and replay the same split, block-count, cleanup,
and scalar AES-128/192/256 fixtures used on x86. The denied check first
confirms the emulator exposes PMULL, then tests a build that masks that
permission: both empty and nonempty updates fail, empty finish leaves the
output unchanged, and the workspace clears. The mask cannot grant PMULL.
This is an injected denial, not an observation on a CPU lacking PMULL.

For a native correctness replay on a little-endian Arm host with PMULL, run
the following from the same checkout with no cross-target runner or emulator.
Repeat with `+1.100.0` and record the host CPU, OS, toolchain and source tree.

```sh
cargo +1.90.0 test --locked --offline --release -p brynja-crypto-cpu --no-default-features --lib ghash_pmull:: -- --include-ignored
RUSTFLAGS='--cfg brynja_ghash_pmull_evidence' cargo +1.90.0 test --locked --offline --release -p brynja-crypto --no-default-features --features hazmat-ghash,cpu,hazmat-aes-block --test ghash_field --test ghash_lifecycle
```

### Native AWS Arm correctness replay, 2026-11-22

Seven release-test executables built on Linux x86_64 for
`aarch64-unknown-linux-musl` ran **directly**, without QEMU, on a two-vCPU
AWS Neoverse-V2 running Ubuntu 26.04.1 LTS, kernel `7.0.0-1018-aws`.
Linux reported ASIMD, AES and PMULL. The source was the development working
tree based on `3d3b6cef92ecbc843eb4b72e67702c66a55104af`, not that clean
commit. The builds used the corresponding PMULL registry commands above
with `--no-run`, no Cargo target runner and `rust-lld` as target linker.
Each SHA-256 was checked on the instance immediately before execution.

| Rust | Executable | Tests passed | Executed binary SHA-256 |
| --- | --- | ---: | --- |
| 1.90.0 | direct | 5 | `25045090691c42b87be1ecd659ca148cce1ebd00bade732b724f3f8aa8587ca6` |
| 1.90.0 | owner-lifecycle | 4 | `ef144f0a487fd48a6a2d9a9554e08670a4941407220c46df21d698bf0c79ca7f` |
| 1.90.0 | owner-field | 15 | `fd4b2f10149a6453c4b4358148498950e76a18625996c40a92f75a4275d0f3e8` |
| 1.100.0 | direct | 5 | `49fa027bf2409fa4e62eb992d3b796b25c6b4d1a16bee476bc647c00fb95ce6b` |
| 1.100.0 | owner-field | 15 | `19dff7d5a9e6c0e4d9e8558f34764b0e5b1bdcefef5f669a3d94cd0e891cf1ad` |
| 1.100.0 | owner-lifecycle | 4 | `27597548c1895d1b8b8fe859a32b4331df7c9cf1b7fe122e84b7cccdcd8cab9b` |
| 1.100.0 | deny | 1 | `e0caa2eff9b78252592c063179c16d19e6989aa9aa799a24af7d1e85fdc86890` |

The direct tests used `ghash_pmull:: --include-ignored`; both owner
executables ran unfiltered. The final control selected only
`pmull::masked_pmull_fails_closed_even_on_empty_finish`. It confirms
denial on a capable host, not the behavior of an actual PMULL-less CPU.
These are correctness observations, not native compiler builds, timing or
performance measurements, or a change to the QEMU verifier records.

### Native Apple M2 Pro correctness replay, 2026-11-22

Both the compiler and the seven resulting arm64 Mach-O test executables ran
on the M2 Pro itself (macOS 27.2.1, build `26B131`, Darwin 27.2.0).
`hw.optional.arm.FEAT_PMULL` reported 1. The scoped source snapshot from
the development working tree based on `3d3b6cef92ecbc843eb4b72e67702c66a55104af`
had tar SHA-256 `e23af7baafee064c4674483a934642f86740ac197fddbfdfb3332a030e76bf0a`;
the archive digest was verified before extraction. Neither the unmodified
base commit nor a Linux test executable was substituted for this build.

The native replay commands above used the explicit `aarch64-apple-darwin`
target and `--no-run` to identify and hash the executable before launching
it directly. The suite filters were the same as for AWS. The additional
latest-compiler negative control used only `hazmat-ghash,cpu`, with both
`--cfg brynja_ghash_pmull_evidence` and `--cfg brynja_ghash_deny_pmull`.

| Rust | Executable | Tests passed | Executed binary SHA-256 |
| --- | --- | ---: | --- |
| 1.90.0 | direct | 5 | `491a81a7b6fcffaa3b589ff868081dd2d4c49f94d7568a651f52dfcd82e4bd7b` |
| 1.90.0 | owner-lifecycle | 4 | `c7323d88b498155522ef2be688aa55b38e1245e86f7ff5ed90c9cb271d67193f` |
| 1.90.0 | owner-field | 15 | `c5a9a6cb04dd3744e3a4ff0a7af1d6b64e402b6a31429f6c6f5e86cce03cee14` |
| 1.100.0 | direct | 5 | `fedd1c4dd7b801bda1e4ad7685a92f015bacd7412365d17692937609f8e8e8be` |
| 1.100.0 | owner-lifecycle | 4 | `eb7a404cb26ba149c723a2ac36737375bca28c3bc9e90f0900f4a86fa9989f49` |
| 1.100.0 | owner-field | 15 | `a02a920a0d92be354a014ab4e7a2bc0dd03612dfad1f3bb3d97f8f844546bf59` |
| 1.100.0 | deny | 1 | `78a04db50708ba39de317b6adb7e3c1642f6bc0c54936cee05ea7892281e1b29` |

Disassembly of each direct-test executable showed three polynomial multiply
instructions in the candidate's startup selection function. This is a narrow
instruction-presence observation, not a timing, cache or performance finding.

## Linux RV64 scalar field candidate

The RV64 test kernel uses only `clmul` and `clmulh` beyond the baseline ISA.
Either Zbc or Zbkc supplies both instructions ([RISC-V scalar cryptography
specification](https://docs.riscv.org/reference/isa/unpriv/scalar-crypto.html)).
It reflects the two 64-bit wire halves, forms three full carry-less products
and reduces the assembled polynomial. Rust's runtime extension detector must
report Zbc or Zbkc, and the kernel must pass its own startup known-answer test.
AES instructions and vector extensions are not prerequisites or proof of either.
This is a direct scalar candidate, not a Zvkg or Zvbc implementation.

```sh
brynja-verify run ghash rv64-field-qemu-msrv
brynja-verify run ghash rv64-field-qemu-latest
```

Each check runs a baseline release test binary under three QEMU models and
asserts the actual detector reports before accepting the results. Both
extensions together and Zbkc alone run the basis, dense, NIST and admission
suites with scalar AES disabled. With both multiply extensions absent but
scalar AES present, prefer selects portable and required selection and direct
product fail as unavailable. No scalar fallback can pass a required test.
These are functional checks, not performance or timing measurements.

### Native Cloud-V scalar correctness replay, 2026-11-22

Cloud-V's SpacemiT X60 (RV64 Linux 6.6.63) advertised Zbc. Both native
executions used the unmodified runtime detector, not a compile-time grant.
The binaries were cross-built on Linux x86_64 from the working tree based
on `3d3b6cef92ecbc843eb4b72e67702c66a55104af`, for
`riscv64gc-unknown-linux-gnu` with the release profile, no default features
and `RUSTFLAGS='-C target-feature=+crt-static'` for a static C runtime.
Neither binary was compiled with global Zbc/Zbkc or an emulator override.
The instance verified each binary's SHA-256, then ran it directly with
`ghash_rv64:: --include-ignored`.

| Rust | Direct tests passed | Executed binary SHA-256 |
| --- | ---: | --- |
| 1.90.0 | 5 | `3c8f6a09f0c356e770bd5674facc4fb7821bba13b6000b71bf985d8fbcefd4a6` |
| 1.100.0 | 5 | `0d8def92d931d512b19eff50f76c8c0558c61d9e8bfae824b7053c0833a7541f` |

These runs cover the scalar field and startup state only. They do not
establish a native Zbkc-only configuration, vector GHASH, or timing safety.

### Incremental RV64 scalar GHASH

```sh
brynja-verify run ghash rv64-incremental-qemu-msrv
brynja-verify run ghash rv64-incremental-qemu-latest
```

The checkout-only flag `--cfg brynja_ghash_rv64_evidence` with the `cpu`
dependency forces the real incremental owner to use the admitted scalar
instruction bundle or report unavailability. It cannot substitute a portable
product. On each positive model the fixture checks completed block counts at
all 49 splits of 64 three-block messages, atomic budget rejection, incomplete
tails, storage cleanup, and all three scalar AES pairings. Both models lack
scalar AES instructions; one exposes Zbc and Zbkc, the other only Zbkc.
On the third model, scalar AES is present but neither CLMUL extension is:
empty and nonempty updates and empty finish fail, output remains unchanged,
and workspace storage clears. The model label is checked against runtime
detection by the test; it cannot grant the owner permission to run.

The available X60 advertised Zbc on all eight Linux `isa` lines; none
advertised Zvbc or Zvkg. This host can exercise the **scalar** candidate.
Its vector capability is not evidence for either vector-crypto extension.

For native correctness replay on a Linux RV64 host that reports Zbc or
Zbkc, run this from the workspace without an emulation runner:

```sh
RUSTFLAGS='--cfg brynja_ghash_rv64_evidence' cargo +1.90.0 test --locked --offline --release \
  -p brynja-crypto --no-default-features --features hazmat-ghash,cpu,hazmat-aes-block \
  --test ghash_field --test ghash_lifecycle
```

Repeat with `+1.100.0`. Each native endpoint expects 15 field/pairing tests
and four lifecycle tests. The QEMU-only model assertion is not compiled in.

On 2026-11-22 all 38 executions passed directly on the Cloud-V SpacemiT
X60. The binaries were cross-built on Linux x86_64 from the working tree
based on `3d3b6cef92ecbc843eb4b72e67702c66a55104af`, with the same target
and static C runtime as the direct replay above, plus the forced owner cfg.
The host verified each SHA-256 before execution. In both field executables,
disassembly showed six carry-less multiply instructions in the startup path
and six in `Ghash::update`; this does not establish a timing property.

| Rust | Executable | Tests passed | Executed binary SHA-256 |
| --- | --- | ---: | --- |
| 1.90.0 | lifecycle | 4 | `86bdf0fa774904f8cb2a008243de12f4a4214f4048c778a223f4ea28672cee13` |
| 1.90.0 | field | 15 | `7257cd1905974ba2aa968cc27eea38c1fcdf2ab4259e5512946440a39c61cd92` |
| 1.100.0 | lifecycle | 4 | `e9329559ec9d33abe9cf7b4955746abea9747f58ec32b1935497bc5ade6e4276` |
| 1.100.0 | field | 15 | `83a6d6f6798e8305e796db291fb14f3adadcc99d85fab8817ace0c6aad5152c2` |

### First accelerated throughput protocol: native Linux x86-64

Compare two release builds of the same standalone fixture on Rust 1.90.0
and 1.100.0, with fat LTO, one codegen unit, and the same dependencies.
Only the candidate build forces PCLMUL. Each launch checks its result against
an independent wire-order oracle; candidate preflight also requires the
expected number of hardware products. There is no AES or tag computation.

On the lowest allowed logical CPU, collect **12 pairs of process launches**
per compiler, alternating portable-first and candidate-first. Within each
launch, use the workload order below and one full untimed warm-up batch per
workload. Keep every measured batch; no trimming, reruns to pass, speedup
threshold or automatic backend admission. Report median ns/message per
route and the ratio of those medians.

| Message | Update chunk | Messages per batch |
| ---: | ---: | ---: |
| 16 B | 16 B | 4096 |
| 1024 B | 1024 B | 128 |
| 16384 B | 16384 B | 8 |
| 16384 B | 13 B | 8 |

The clock includes construction (including each candidate owner's startup
KAT), all updates, finish, and clearing. It excludes process startup,
oracle/preflight and input generation. The fixed public subkey and input are
reused and warm; results are not cold-cache latency, AES-GCM throughput,
or a fixed-vs-random leakage screen. CPU frequency is not locked.

Collect with `python3 scripts/ghash/check-throughput.py collect NEW_DIRECTORY`;
replay with `python3 scripts/ghash/check-throughput.py replay DIRECTORY`.
Only collection needs native PCLMUL hardware; an existing output directory
is never overwritten.

#### AMD Ryzen 9 9950X3D, 2026-11-22

Linux x86-64, logical CPU 0, development working tree based on
`3d3b6cef92ecbc843eb4b72e67702c66a55104af`. Entries are **portable →
PCLMUL median ns/message**; the ratio is computed before rounding.

| Message / chunk | Rust 1.90.0 | Rust 1.100.0 |
| --- | ---: | ---: |
| 16 B / 16 B | 108.6 → 31.9 (3.41×) | 128.1 → 30.3 (4.22×) |
| 1 KiB / 1 KiB | 6,276 → 1,022 (6.14×) | 7,725 → 977 (7.91×) |
| 16 KiB / 16 KiB | 100,209 → 15,989 (6.27×) | 122,941 → 15,306 (8.03×) |
| 16 KiB / 13 B | 101,598 → 18,408 (5.52×) | 129,128 → 16,214 (7.96×) |

Both compilers showed a benefit even for one block with startup included.
The larger ratios on 1.100.0 do not mean its accelerated kernel got that
much faster: its measured portable baseline was also slower. These values
describe this host and these warm-input workloads, not a release threshold.
The [raw batches and artifact metadata](../../assurance/ghash-observations/throughput-amd-9950x3d/)
are retained. `brynja-verify run ghash amd-throughput-observation-replay`
checks the recorded observations without remeasuring.

#### AWS Neoverse-V2: native PMULL throughput protocol

Use the same workloads, warm-up, 12 alternating pairs, lowest available
logical CPU, and median calculation as the AMD protocol. Cross-build
portable and forced-PMULL Linux musl binaries for both compiler endpoints;
execute them on the ARM machine, not under emulation. The timer is inside
the executable and does not include transfer or SSH. Retain every sample.
Do not compare absolute latency across hosts as if the OS, target and
compiler configuration were identical.

Run `python3 scripts/ghash/check-arm-throughput.py prepare NEW_BUNDLE`
on the build host with the Rust musl targets installed. Copy that directory
and both `check-arm-throughput.py` and `check-throughput.py` to the ARM host.
Run `python3 check-arm-throughput.py measure NEW_BUNDLE NEW_RESULTS` there.
Only this step needs native PMULL hardware. Use the same script's
`replay NEW_RESULTS` command on any host to verify the saved batches.

On 2026-11-22, the native AWS run used logical CPU 0 on Neoverse-V2.
Both cross-builds used the development working tree based on
`3d3b6cef92ecbc843eb4b72e67702c66a55104af`. Median ns/message
(portable → PMULL, ratio calculated before rounding):

| Message / chunk | Rust 1.90.0 | Rust 1.100.0 |
| --- | ---: | ---: |
| 16 B / 16 B | 195.7 → 51.2 (3.82×) | 197.2 → 48.7 (4.05×) |
| 1 KiB / 1 KiB | 11,110 → 1,418 (7.83×) | 11,138 → 1,393 (7.99×) |
| 16 KiB / 16 KiB | 174,900 → 21,571 (8.11×) | 175,001 → 21,791 (8.03×) |
| 16 KiB / 13 B | 183,302 → 26,158 (7.01×) | 182,496 → 22,884 (7.97×) |

The candidate was faster than portable in all four workloads on both
compiler endpoints, even with owner startup included. All 192 measured
batches and the build manifest are in the [ARM observation directory](../../assurance/ghash-observations/throughput-aws-neoverse-v2/).
`brynja-verify run ghash aws-throughput-observation-replay` checks that
record without contacting the builder or rerunning a benchmark.

#### Apple M2 Pro: native PMULL throughput protocol

Build and execute both routes natively on macOS arm64 for Rust 1.90.0 and
1.100.0. Use the same fixture, workloads, warm-up, 12 alternating process
pairs and median calculation as on Linux. Check that the host reports PMULL
and the candidate preflight counts the expected hardware blocks. Leave CPU
placement to macOS: no core affinity, performance-core selection or
frequency lock. Keep all batches; compare the two routes on this host,
not absolute times between differently scheduled machines.

With Python 3.11+ on the Mac, run `check-arm-throughput.py --apple prepare NEW_BUNDLE`
and then `check-arm-throughput.py --apple measure NEW_BUNDLE NEW_RESULTS`
from `scripts/ghash/`. For a source export without Git metadata, pass
`--source-base BASE_COMMIT` to prepare. Use `--apple replay NEW_RESULTS`
on any host to verify the retained results without remeasurement.

On 2026-11-22, on the development working tree based on
`3d3b6cef92ecbc843eb4b72e67702c66a55104af`, the M2 Pro returned these
median ns/message (portable → PMULL, with ratios calculated before rounding):

| Message / chunk | Rust 1.90.0 | Rust 1.100.0 |
| --- | ---: | ---: |
| 16 B / 16 B | 171.4 → 41.6 (4.12×) | 170.3 → 41.8 (4.07×) |
| 1 KiB / 1 KiB | 9,253 → 1,208 (7.66×) | 9,017 → 1,198 (7.53×) |
| 16 KiB / 16 KiB | 138,656 → 18,779 (7.38×) | 142,607 → 18,935 (7.53×) |
| 16 KiB / 13 B | 149,917 → 19,570 (7.66×) | 147,383 → 20,693 (7.12×) |

All 192 measured batches, the native compiler identities and executable
hashes are in the [M2 Pro observation directory](../../assurance/ghash-observations/throughput-apple-m2-pro/).
`brynja-verify run ghash apple-throughput-observation-replay` checks these
records offline. The first source export omitted a manifest-declared test
target, which stopped Cargo before compilation; no timed samples were
collected or discarded in that attempt.

#### Cloud-V SpacemiT X60: native scalar throughput protocol

Cross-build both routes with the same static C runtime for
`riscv64gc-unknown-linux-gnu`, with no global Zbc/Zbkc flags. Only the
candidate uses `--cfg brynja_ghash_rv64_evidence`. Pin native execution to
the lowest allowed logical CPU, check its reported scalar Zbc/Zbkc support
and let the candidate preflight check its executed hardware-block count.
Use the same four workloads, warm-up, 12 alternating pairs, and median
calculation as AMD and AWS; retain all samples, regardless of the ratio.
No emulator, AES, or vector path is included in the comparison.

On the build host run `python3 scripts/ghash/check-arm-throughput.py --rv64 prepare NEW_BUNDLE`
with a RISC-V GNU linker and both Rust targets installed. Transfer the
bundle and the two throughput scripts to the native Linux host. Run
`python3 check-arm-throughput.py --rv64 measure NEW_BUNDLE NEW_RESULTS`
there; use `--rv64 replay NEW_RESULTS` to check the record on any host.

On 2026-11-22 the native X60 scalar path was faster for all four workloads
at both compiler endpoints. Median ns/message (portable → scalar CLMUL,
ratios calculated before rounding):

| Message / chunk | Rust 1.90.0 | Rust 1.100.0 |
| --- | ---: | ---: |
| 16 B / 16 B | 1,177.6 → 494.1 (2.38×) | 1,171.6 → 496.6 (2.36×) |
| 1 KiB / 1 KiB | 61,485 → 11,841 (5.19×) | 60,685 → 11,292 (5.37×) |
| 16 KiB / 16 KiB | 977,573 → 184,760 (5.29×) | 963,564 → 175,783 (5.48×) |
| 16 KiB / 13 B | 1,003,265 → 237,995 (4.22×) | 991,262 → 224,411 (4.42×) |

Fragmenting the same 16 KiB into 13-byte updates reduced the speedup on
both compilers. The comparison includes per-message startup, updates,
finish and cleanup, not just isolated multiply instructions. The [X60
records](../../assurance/ghash-observations/throughput-spacemit-x60/) retain
all 192 measured batches, build metadata and pinned CPU ISA. Run
`brynja-verify run ghash rv64-throughput-observation-replay` for an offline replay.

#### AWS Intel Xeon: native PCLMUL throughput protocol

Use the AMD workloads, repetitions, warm-up, and 12 alternating process
pairs per compiler. Keep every sample; there is no speedup threshold.
Build both routes for baseline `x86_64-unknown-linux-gnu`; only the
candidate has `--cfg brynja_ghash_pclmul_evidence`. On the Intel instance
require GenuineIntel and PCLMULQDQ on the lowest allowed logical CPU, pin
both routes there, and check the candidate's hardware-block count before
each timed workload. Frequency is not locked. No AES or VPCLMUL benchmark.

Run `python3 scripts/ghash/check-arm-throughput.py --intel prepare NEW_BUNDLE`
on the build host. Copy the bundle and the two throughput scripts to the
Intel host; run `python3 check-arm-throughput.py --intel measure NEW_BUNDLE NEW_RESULTS`
there. Use `--intel replay NEW_RESULTS` on any host to check the saved run.

On 2026-11-22 the AWS Xeon 6975P-C ran all four binaries directly on
logical CPU 0. Median ns/message (portable → PCLMUL; ratios calculated
before rounding):

| Message / chunk | Rust 1.90.0 | Rust 1.100.0 |
| --- | ---: | ---: |
| 16 B / 16 B | 162.4 → 46.4 (3.50×) | 169.3 → 42.8 (3.95×) |
| 1 KiB / 1 KiB | 9,545 → 1,820 (5.25×) | 10,126 → 1,776 (5.70×) |
| 16 KiB / 16 KiB | 150,342 → 28,558 (5.26×) | 160,137 → 28,386 (5.64×) |
| 16 KiB / 13 B | 152,729 → 31,606 (4.83×) | 164,867 → 28,071 (5.87×) |

The [Intel records](../../assurance/ghash-observations/throughput-intel-6975p-c/)
contain all 192 batches, source and executable digests, compiler identities
and host metadata. `brynja-verify run ghash intel-throughput-observation-replay`
recomputes both summaries offline. The measurements concern end-to-end GHASH
on warm public inputs; they do not establish data-independent timing.

A separate unprivileged availability probe (`perf stat` on `true`, not a
GHASH run) could not open the requested branch and cache counters on this
instance with `perf_event_paranoid=4`. See the later
[attached-counter measurements](#aws-attached-counter-protocol) for the
separately authorized observation without changing that setting.

#### Accelerated x86 timing screen: protocol declared before collection

On the AMD Ryzen 9 9950X3D and the AWS Intel Xeon 6975P-C, run the same
two Linux x86-64 release executables, one per compiler endpoint, exactly
once per host. Pin to the lowest allowed logical CPU. Only the evidence
build selects PCLMUL; its untimed preflight checks a known product and a
completed native block. Follow the [portable timing protocol](ghash-portable-screen.md):
identical labels first, then varied synthetic subkey, then varied synthetic
block. Each campaign discards 64 warm-up pairs and keeps all 2,048 measured
pairs, alternating class order. Each timed sample covers 16 one-block
updates followed by finish and explicit clearing. It excludes construction,
startup, and input generation. This is not the end-to-end throughput fixture.

Keep every raw duration. Use the paired statistic on fixed minus comparison
duration: flag absolute t ≥ 4.5 or constant nonzero differences. An alarm
in the identical-input control makes the experiment harder to interpret;
do not subtract it, trim samples or rerun to pass. Replay verifies the record
even if it contains alarms. A screen using synthetic public inputs is not a
constant-time proof or a cache/branch test.

On 2026-11-22 all four launches completed. Signed paired t statistics:

| Execution host | Rust | Identical control | Vary subkey | Vary block |
| --- | --- | ---: | ---: | ---: |
| Ryzen 9 9950X3D | 1.90.0 | +1.29 | −1.28 | −1.22 |
| Ryzen 9 9950X3D | 1.100.0 | −0.84 | −0.51 | +1.24 |
| Xeon 6975P-C | 1.90.0 | −0.56 | +0.55 | +0.29 |
| Xeon 6975P-C | 1.100.0 | +0.42 | +0.18 | −1.44 |

No comparison reached the threshold. This is a negative observation for
these builds and this workload, not evidence for every input or compiler.
The [AMD records](../../assurance/ghash-observations/timing-pclmul-amd/) and
[Intel records](../../assurance/ghash-observations/timing-pclmul-intel/)
retain all 24,576 measured pairs and identical build manifests.

Use `brynja-verify run ghash pclmul-timing-observation-replay` for the
offline record check. To reproduce as a **new** observation, use
`python3 scripts/ghash/check-pclmul-screen.py prepare NEW_BUNDLE`, copy the
bundle and both `check-pclmul-screen.py` and `check-portable-host.py` under
`scripts/ghash/` on the runner, then invoke the former with
`measure NEW_BUNDLE amd|intel NEW_RESULTS` (choose the matching host).
No timing collection is required by the offline replay.

#### Accelerated Arm timing screen: protocol declared before collection

Run the x86 screen's three campaigns unchanged on AWS Neoverse-V2 and
Apple M2 Pro. Use both compiler endpoints, checking PMULL capability and
a known result with one completed native block before timing. Keep one
launch per compiler and host, with 64 warm-up pairs and all 2,048 measured
pairs per campaign. Use the same paired statistic and absolute threshold
of 4.5 (including the constant nonzero difference alarm); no trimming or
retry-to-pass. Pin to the lowest available logical CPU on AWS. Leave
placement and frequency to macOS on Apple. Build Linux musl binaries on
the x86 build host and Darwin binaries natively on the Mac; results from
these different artifacts are separate observations.

On 2026-11-22 all four launches finished. Signed paired t statistics:

| Execution host | Rust | Identical control | Vary subkey | Vary block |
| --- | --- | ---: | ---: | ---: |
| AWS Neoverse-V2 | 1.90.0 | −0.93 | −0.07 | +1.06 |
| AWS Neoverse-V2 | 1.100.0 | **−4.537 (alarm)** | +0.36 | +0.53 |
| Apple M2 Pro | 1.90.0 | −0.84 | −1.29 | +1.14 |
| Apple M2 Pro | 1.100.0 | +0.20 | −1.56 | +1.21 |

The latest-compiler AWS control used equal inputs, yet the two labels
differed by an average of −25.95 ns per timed batch. **That launch is
inconclusive.** Neither varied-input campaign alarmed; this does not explain
away the control or establish a key-dependent effect. Its cause is unknown.
The collector returned a nonzero alarm status after saving the records.
No retry, exclusions, baseline subtraction, or threshold changes were made.
Neither the MSRV run nor the Mac results qualify the AWS latest build.

**What the saved AWS control tells us about order.** The fixture alternates
which label runs first and prints each pair in label order. Splitting the
original 2,048 identical-input pairs by execution order gives the following
differences (label 0 minus label 1, nanoseconds per 16-update batch):

| First label executed | Pairs | Mean difference | Minimum | Maximum |
| --- | ---: | ---: | ---: | ---: |
| 0 | 1,024 | −51.915 | −7,643 | +5,999 |
| 1 | 1,024 | +0.010 | −31 | +25 |

Almost the entire signed difference came from pairs where label 0 ran first.
This is a retrospective description of one launch: order and even/odd pair
index were tied together, so the split cannot isolate an order effect from
other effects that followed the same pattern. No pairs were removed, no
new timing was collected, and the original alarm and disposition stand.

All 24,576 pairs are retained in the [AWS](../../assurance/ghash-observations/timing-pmull-aws/)
and [Apple](../../assurance/ghash-observations/timing-pmull-apple/) records.
`brynja-verify run ghash pmull-timing-observation-replay` checks the stored
results offline and specifically requires the AWS control alarm.
To reproduce as a new observation, prepare with
`python3 scripts/ghash/check-pclmul-screen.py prepare NEW_BUNDLE --host aws`
on the Linux x86-64 builder, or `--host apple` on the Mac. For a source
export without Git metadata, pass `--source-base BASE_COMMIT`. On the
corresponding native host, invoke the script with
`measure NEW_BUNDLE HOST NEW_RESULTS` (HOST is `aws` or `apple`).

**Separate order-control follow-up (2026-11-22).** The new
[protocol](ghash-pmull-order-control.md) balanced first label within both even
and odd pairs. Both first runs completed natively on Neoverse-V2 CPU 0.
Paired t statistics (identical / varied subkey / varied block):

| Compiler | Identical | Subkey | Block |
| --- | ---: | ---: | ---: |
| Rust 1.90.0 | −0.526 | +0.200 | +0.749 |
| Rust 1.100.0 | −0.630 | +0.568 | +1.703 |

No new comparison crossed 4.5. For identical inputs, mean first-minus-second
times per batch (even / odd pair) were −15.17 / +33.50 ns on 1.90.0 and
+7.01 / +2.64 ns on 1.100.0. All [12,288 new pairs and their build
identities](../../assurance/ghash-observations/order-pmull-aws/) are retained.
This does not isolate the old cause: the schedule **and executable** changed.
The original alarm stands, timing is not qualified, and no further collection
is planned for this investigation now. [GitHub Discussion #4](https://github.com/valkyoth/brynja/discussions/4)
includes a standalone replay of the original alarm and invites independent observations.

#### SpacemiT X60 scalar timing screen: protocol declared before collection

Run the same three synthetic-input campaigns as the x86 and Arm screens:
identical control, varied subkey, varied block. Cross-build for RV64 GNU
with a static C runtime on Rust 1.90.0 and 1.100.0. Do not enable Zbc
globally; require it on the lowest permitted X60 logical CPU, pin execution
there, and verify one known product and its native-block count before timing.
One launch per compiler, no emulator or vector path. Each campaign has
64 warm-up pairs and 2,048 retained pairs; the timer covers 16 updates
and finish/clear. Flag absolute paired t ≥ 4.5 or a constant nonzero
difference. Keep all durations, including control alarms, without trimming
or retrying to pass. The AWS alarm remains a separate observation.

On 2026-11-22, both launches completed on logical CPU 0. Signed paired
t statistics (fixed minus comparison duration):

| Rust | Identical control | Vary subkey | Vary block |
| --- | ---: | ---: | ---: |
| 1.90.0 | −0.14 | −0.34 | +0.55 |
| 1.100.0 | −1.15 | +1.68 | +1.20 |

None crossed the threshold. This describes two builds of the scalar
candidate for these synthetic inputs, not vector execution, a constant-time
guarantee or resolution of the AWS control alarm. The [X60 records](../../assurance/ghash-observations/timing-rv64-x60/)
retain all 12,288 measured pairs, build inputs and executable hashes.
Use `brynja-verify run ghash rv64-timing-observation-replay` for offline
replay. To reproduce as a new observation, run
`python3 scripts/ghash/check-pclmul-screen.py prepare NEW_BUNDLE --host x60`
on the x86 Linux cross-build host. Transfer the bundle and the two screen
scripts (`check-pclmul-screen.py` and `check-portable-host.py`) to the
native runner, then run `python3 check-pclmul-screen.py measure NEW_BUNDLE x60 NEW_RESULTS`.

**Counter availability, not GHASH evidence:** a separate user-mode
`perf stat` probe on the X60, pinned to CPU 0 for a public arithmetic
workload, returned counts for `branches:u` and `branch-misses:u`.
The generic `cache-references:u` and `cache-misses:u` events returned
`<not counted>` even when requested individually. Those are missing
measurements, not zero cache misses. No host settings were changed.

#### X60 branch counters: protocol declared before collection

Use Rust 1.90.0 and 1.100.0, native X60 scalar Zbc and the lowest permitted
logical CPU. Count grouped user-mode `branches:u` and `branch-misses:u`
with `perf stat`, initially disabled. The fixture checks a known product
and the native path, prepares its public inputs and warms up 4,096 updates.
It enables counting with an acknowledged perf control command, calls the
same non-inlined loop of 4,096 one-block updates, then disables counting.
The loop and user-side command/ack overhead are included. Construction,
corpus generation, finish, cleanup and process startup are outside the
enabled interval. Verify the executed native-block count after disabling.

Use one empty update window before and after the measured campaigns per
compiler. Require active branch counts above both empty counts; do not
subtract the controls. In order: identical inputs; fixed vs varied synthetic
subkey; fixed vs varied synthetic block. Use 16 pairs per campaign, same
pair seed in both labels, alternating order; one process per label and
constant key/block within a given batch. Keep every report. Reject missing
events, missing counts or less than 100.00% reported running time.
For each event and campaign use the paired t statistic (fixed minus
comparison), flagging |t| ≥ 4.5 or a constant nonzero difference. Report
alarms, including identical-control alarms, without rerunning to pass.
These are aggregate counts, not a trace of individual branch outcomes or
a test of cache behavior.

On 2026-11-22, all 196 windows (192 active, four empty) produced both
events on logical CPU 0 with 100.00% reported running time. Signed paired
t values (fixed minus comparison):

| Rust | Event | Identical | Vary subkey | Vary block |
| --- | --- | ---: | ---: | ---: |
| 1.90.0 | branches | +1.69 | −1.85 | −0.32 |
| 1.90.0 | branch misses | +0.78 | +0.13 | +0.47 |
| 1.100.0 | branches | 0.00 | −0.96 | −1.07 |
| 1.100.0 | branch misses | −0.77 | −1.11 | +0.21 |

No comparison reached the alarm threshold. Active medians were
167,948–167,954 branches per batch; empty windows recorded 12–18.
Branch misses were much smaller: active medians ranged from 14 to 20.5
and the empty controls counted 4–10. The control overhead is material
for misses, so these are not per-kernel misprediction counts. Matching
aggregate counts need not imply the same branch directions or addresses.
The [retained perf reports and build metadata](../../assurance/ghash-observations/branches-rv64-x60/)
can be verified offline with `brynja-verify run ghash rv64-branch-observation-replay`.

To reproduce as a new observation, run `python3 scripts/ghash/check-rv64-branches.py
prepare NEW_BUNDLE` on the Linux x86-64 cross-build host. Transfer the bundle
and the three scripts (`check-rv64-branches.py`, `check-pclmul-screen.py`,
`check-portable-host.py`) to the native X60 and run
`python3 check-rv64-branches.py measure NEW_BUNDLE NEW_RESULTS`.
No performance counters are opened by `replay NEW_RESULTS`.

#### X60 L1 data-cache protocol

Before collecting a GHASH window, select the Linux hardware-cache pair
`{L1-dcache-loads:u,L1-dcache-load-misses:u}`. Unlike generic cache
references/misses, both named events counted a public memory workload.
Require a positive memory control, with verbose perf attributes confirming
hardware-cache type 3, read access/miss configs 0/0x10000 and kernel and
hypervisor exclusion. This perf version omits the requested `:u` from the
result labels. Disable inheritance and require equal positive group running
times and 100.00% reported scheduling. Use the same binaries, CPU, two empty
windows, 16 alternating pairs, three populations and first-run alarm rule
as the X60 branch screen. All active load counts must exceed both empty
controls; report overlap for misses without subtracting overhead. Keep all
observations, including alarms. Do not infer cache addresses or timing from
aggregate L1 counts.

**First observation:** On the native X60, 196 windows completed on CPU 0
across Rust 1.90.0 and 1.100.0. None of the 12 paired comparisons reached
the declared threshold of 4.5 (largest absolute paired t: 2.355).
Active median loads per 4,096 updates were 385,057–385,060 on 1.90.0 and
352,287.5–352,289 on 1.100.0; empty windows recorded 25–30 loads.
Active median load misses were 5–6.5, versus 3–4 misses in empty windows.
Individual active miss counts overlapped the empty controls in every population.
The load signal was measurable, but these misses cannot be attributed to
GHASH alone. Neither result establishes value-independent memory access.

The [raw reports, positive control and compiler records](../../assurance/ghash-observations/cache-rv64-x60/)
replay offline with `brynja-verify run ghash rv64-cache-observation-replay`.
To collect a separate observation, use the X60 branch bundle preparation above,
then run `python3 check-rv64-branches.py measure NEW_BUNDLE NEW_RESULTS --l1`
on the native host. Use `replay NEW_RESULTS --l1` to recompute the statistics
without collecting again.

### AMD aggregate branch and cache-event protocol

On the Ryzen 9 9950X3D, screen the forced PCLMUL update on Rust 1.90.0 and
1.100.0 using the same 16 alternating-order pairs per population (identical
inputs, varied subkey, varied block), warmup, 4,096-update windows and two
empty controls as the X60 fixture. Use the lowest allowed logical CPU.
Collect Linux generic user-mode branches, branch misses, cache references and
cache misses simultaneously for the fixture child. Include its control-pipe
overhead; exclude startup, input preparation, warmup and finalization. Require
one separate 16 MiB synthetic memory-access probe to exercise all four events,
matching event IDs, and equal nonzero enabled/running time; never scale or
replace missing counts with zero. Active branches must exceed both empty
windows. Report whether each population's counts also clear that envelope for
each other event, without subtracting controls or assigning a cache level.
These are aggregate event counts, not addresses, and the two generic cache
events are not assumed to form a hit-rate denominator. Retain the first run
and every paired |t| >= 4.5 (also a constant nonzero difference); no retry to
pass. This is not a constant-time qualification.

**First observation:** all 196 process windows completed. None of the 24
paired comparisons alarmed. Median active branches were 127,008 per batch on
Rust 1.90.0 and 127,009 on 1.100.0, versus 32 and 33 for the respective empty
windows. Cache references exceeded the empty envelope in every population;
cache misses overlapped it in every population. In particular, no cache-miss
alarm is not evidence of identical memory accesses. The host mapped generic
cache references and misses to `event=0x60,umask=0xff` and
`event=0x64,umask=0x09`, respectively.

The [records and build manifests](../../assurance/ghash-observations/counters-amd-9950x3d/)
can be checked with `brynja-verify run ghash amd-counter-observation-replay`
without opening counters. For a distinct new observation on the named host:

```sh
python3 scripts/ghash/check-amd-counters.py prepare NEW_BUNDLE
python3 scripts/ghash/check-amd-counters.py measure NEW_BUNDLE NEW_RESULTS
python3 scripts/ghash/check-amd-counters.py replay NEW_RESULTS
```

The two AWS instances (Xeon and Neoverse-V2) denied unprivileged hardware
events with `perf_event_paranoid=4`. A read-only follow-up found a hardware
event source in sysfs on both guests (`cpu` on Intel, `armv8_pmuv3_0` on Arm).
The separately authorized attached measurements below did not change that
setting. On the M2 Pro the system-wide selection remains Command Line Tools.
A follow-up found full Xcode at `/Applications/Xcode-27.2.0.app`. A per-command
`DEVELOPER_DIR` allowed unprivileged profiling without changing the host settings.
The default CPU Counters template returned bottleneck metrics, not the requested
event counts, and reported an incomplete logging stream; it is not used as evidence.

#### Apple M2 Pro: first process-attributed event-sampling protocol

Use the standalone CPU Counters instrument in manual event mode, EL0, one
overflow interrupt per 65,536 events. A synthetic branch/memory workload
gave positive target-process samples for both M2 events: `INST_BRANCH`
(retired branches) and `L1D_CACHE_MISS_LD` (loads missing the L1 data cache).
For each event, launch each previously recorded PMULL throughput binary
(Rust 1.90.0, then 1.100.0) once, checking its digest against the original
Apple throughput record. Require clean recorder status, normal target exit,
a matching single-target event schema, and filter by the launched process
identity. Keep zero target samples as below sampling resolution; do not lower
the threshold or repeat a launch based on its result.

This observes the **whole benchmark process**, including startup, reference
calculation, warmup, and the four public workloads. The two events are sampled
in separate processes; no branch/cache correlation, per-kernel count, class
comparison or constant-time conclusion follows. Never infer zero events from
zero samples or compare these sample counts to Linux perf totals.

All four first recordings completed normally with Instruments 27.2 (27B52).
The launched PMULL benchmark process accounted for the following overflow
samples after filtering by its recorded PID:

| Rust | Retired-branch samples | L1 data-cache load-miss samples |
| --- | ---: | ---: |
| 1.90.0 | 129 | 69 |
| 1.100.0 | 162 | 83 |

The [sanitized records](../../assurance/ghash-observations/samples-apple-m2-pro/)
retain the binary digest, requested options, tool version, start time and
relative timestamps of target samples only. They omit stacks, unrelated
processes and machine identifiers. Use `brynja-verify run ghash apple-counter-sample-replay`
for offline verification. For a separate new observation, use the original
hash-matched Apple throughput bundle and an unused result directory:

```sh
DEVELOPER_DIR=/Applications/Xcode-27.2.0.app/Contents/Developer \
  python3 scripts/ghash/check-apple-samples.py measure ORIGINAL_BUNDLE NEW_RESULTS
```

### AWS attached-counter protocol

After synthetic preflight and before measuring GHASH, select one Intel
group (branches, branch misses, L1 data-cache loads and load misses) and two
independent Neoverse-V2 groups (branches/branch misses; L1D accesses/refills).
The Arm pairs run in separate launches and cannot be correlated per batch.
On Intel the generic cache events read zero on a 16 MiB synthetic memory
workload. On Arm the four-event groups could not count together, but each
selected pair returned positive counts independently. These are event-source
limitations, not GHASH results. Do not compare cache rates across hosts.

Use the AMD counter protocol's first-run schedule, positive and empty
controls, compiler endpoints and paired alarm rule without retries. Require
all selected events to count on the positive control with 100.00% reported
running time. The first event in each group (branches or Arm L1D accesses)
must exceed the empty-window envelope in every active launch. No empty
subtraction. Record overlaps on the other events, including valid zero counts.
Only the system `perf stat` attaches with elevated access to the single
unprivileged child PID, using user-mode events with inheritance disabled.
The child waits for acknowledgements around the 4,096-update window. No
system-wide collection, sysctl change, root workload or cache-address tracing.

**First observations (2026-11-22):** all 588 windows completed on CPU 0 with
Rust 1.90.0 and 1.100.0. No alarm in 48 paired comparisons (three populations,
two compiler endpoints, four events per host). The Xeon had median branch
counts of 127,004 and 127,005 per active batch, respectively; the Arm had
196,636 and 196,637. Intel L1 loads cleared the empty envelope in every
population, but L1 load misses overlapped it in every population. On Arm,
both L1 access and refill counts cleared their respective empty controls.
These are user-mode event totals, not access traces or a constant-time
qualification. They do not resolve the independent AWS Arm timing alarm.

Run `brynja-verify run ghash aws-counter-observation-replay` to check the
[saved records and build manifests](../../assurance/ghash-observations/aws-attached/)
without SSH, perf or elevated access. To collect a **new** authorized
observation, prepare a fresh bundle on the x86 build machine with
`python3 scripts/ghash/check-aws-counters.py prepare HOST NEW_BUNDLE`
(`HOST` is `intel` or `aws`). Transfer the bundle and the colocated scripts
`check-{aws-counters,rv64-branches,pclmul-screen,portable-host}.py` to the
corresponding host. As the normal build user, run
`python3 check-aws-counters.py measure HOST PROFILE NEW_BUNDLE NEW_RESULTS`.
Use `intel-l1` on Intel, and `branches` then `arm-l1-only` in **separate**
result directories on Arm. Never run the coordinator as root or rerun the
original campaign to replace an unfavorable result.

### Linked timing-binary review

The original timing executables were recovered for all five named hosts on
Rust 1.90.0 and 1.100.0. Their SHA-256 digests matched both the build
manifests and the timing records **before** decoding. The AMD and Intel runs
used the same executable at each endpoint: ten host/compiler observations,
eight distinct binaries. No rebuild or new timing run was substituted.

LLVM 23.1.6 disassembly of each linked `timed` function showed two clock
reads. Between them were 16 update or field-product call sites, then a call
to finish and an explicit clear before the second clock read. Counts below
are static instructions in **one** field product, not event counts. The
startup known-answer test is outside the measured batch and does not count.

| Timing binaries | Rust 1.90.0 call path | Rust 1.100.0 call path | Field instructions |
| --- | --- | --- | --- |
| AMD & Intel, Linux x86_64 | update → multiply | inlined update → multiply | 4 PCLMULQDQ |
| AWS Neoverse-V2, Linux AArch64 | update → multiply | inlined update → multiply | 3 PMULL (64-bit polynomial lanes) |
| Apple M2 Pro, macOS AArch64 | update with inline product | same | 3 PMULL (64-bit polynomial lanes) |
| SpacemiT X60, Linux RV64 | update with inline product | same | 3 CLMUL + 3 CLMULH |

For the separate multiply functions the listing showed no branch or call
within the whole function body (return excluded). For the inline products
the check covers **only the span from the first to the last multiply
instruction**. The listings are not execution traces. They establish neither
secret-independent memory addresses nor branch behavior of the entire owner,
nor performance on a different machine. In particular the AWS 1.100.0
identical-input alarm is still inconclusive; a matching PMULL instruction
sequence does not explain it.

The [retained function listings and identities](../../assurance/ghash-observations/linked-timing/)
can be checked offline with `brynja-verify run ghash linked-timing-code-replay`.
To regenerate them from the **original** binaries, put the executables named
`1.90.0` and `1.100.0` in the bundle directory and run:

```sh
python3 scripts/ghash/check-linked-screen.py x86 NEW_REVIEW_DIR --bundle ORIGINAL_BUNDLE
```

Use `arm-linux`, `arm-mac` or `rv64` for the other targets. The decoder
does not execute the binaries. The offline check replays the captured
listings; only regeneration disassembles executable bytes.

### Downstream replay from local Cargo archives

`brynja-verify run ghash packaged-candidates` builds the direct
`brynja-crypto` consumer and the `brynja` facade consumer from checked,
unpacked Cargo archives, offline. Both consumers enable only raw GHASH and the
CPU dependency; the runner separately forces one evidence backend at a time.
It rejects checkout dependencies and checks the resolved CPU dependency edge.
Nothing is uploaded and these builds do not change ordinary Cargo dispatch.

Both Rust 1.90.0 and 1.100.0 passed the optimized matrix below on both entry
points. Each positive build ran the unchanged NIST split vectors, the frozen
lifecycle suite, the downstream differential/boundary tests, and a test that
counts actual native products as the consumer supplies partial and full blocks.
Each denial control checked that even an empty finalization cannot publish an
output after the backend is unavailable.

| Forced candidate | Positive execution | Denial control |
| --- | --- | --- |
| x86_64 PCLMUL | Native Ryzen 9 9950X3D | QEMU x86 with AES but no PCLMUL |
| AArch64 PMULL | QEMU AArch64 | Same QEMU CPU with PMULL denied by evidence configuration |
| RV64 scalar CLMUL | QEMU RV64 with Zbc but no AES | QEMU RV64 with AES but neither Zbc nor Zbkc |

These are functional package tests. They do not supply additional native Arm
or RISC-V measurements, demonstrate a vector GHASH implementation or resolve
the AWS timing-control alarm.

The ordinary constructor continues to use portable GHASH.
All five named hosts now have branch and cache observations, with the Apple
sampling limitation above. The route decisions below account for that limitation
and the open AWS Arm timing-control alarm. No vector candidate qualifies on current hardware.
No target is admitted on the strength of another target's result.

### x86 production-route review (v0.28.2)

**Disposition: proceed to opt-in integration of hosted Linux x86_64 PCLMUL;
do not enable automatic dispatch in the existing constructor.** AMD and
Intel both have native correctness, linked-code, throughput, timing and
counter observations. The throughput workloads benefited even with startup
included; neither x86 timing screen raised an alarm. Some cache-miss counts
overlapped the empty controls. This supports using the tested algorithm, not
a constant-time guarantee, a FIPS validation, or a claim about other ISAs.
No new timing run was needed for this review.

On 2026-11-22 the **same six optimized Linux executables** ran natively on
Ryzen 9 9950X3D and AWS Xeon 6975P-C. Each process was pinned to logical
CPU 0 after checking vendor, SSE2 and PCLMULQDQ; the Xeon verified each
transferred executable's SHA-256 before launch. Each host passed 24 test
cases per compiler (48 per host). The five direct cases include exhaustive
field basis pairs, startup KAT failure and terminal quarantine; the field
target includes split updates and scalar AES pairings at all three widths.
Some field tests deliberately exercise the portable oracle, so the test total
is not a count of independent hardware vectors.

| Rust | Test executable | Passed on each host | Executable SHA-256 |
| --- | --- | ---: | --- |
| 1.90.0 | direct CPU | 5 | `81786d3a5c6d9fded278f6ac9f7af2b9da3ff677ef191e6eff40c7d576ba2ab9` |
| 1.90.0 | owner field / scalar AES | 15 | `dd75fd77b4a0d89d4a660f4359b2f6cbd9e44b82815b2c86b2e059c1e39621f5` |
| 1.90.0 | owner lifecycle | 4 | `276e27a618ff49a04cc7be6b384980e12f7cac6d0f2e5936f065b216d70222fb` |
| 1.100.0 | direct CPU | 5 | `c4862ba08930066487486903c49474e3a79fdfff2f95a9d4a4f4a23073bb74b5` |
| 1.100.0 | owner field / scalar AES | 15 | `0065f831eff4dda5f513f846f15ecfb811bd041c41d2b15d1a8d10a6e3f37d6f` |
| 1.100.0 | owner lifecycle | 4 | `a7751e826b41ece582e8f0612857d1aff5f86603d79c4461f570ee9be0704bc4` |

Build from the working tree based on `3d3b6cef`, not the clean base commit.
The kernel, admission module and incremental owner sources matched both
retained x86 timing manifests. To reproduce the correctness suites on a
supporting Linux x86_64 host (repeat with `+1.100.0`):

```sh
cargo +1.90.0 test --locked --offline --release -p brynja-crypto-cpu --no-default-features \
  --lib ghash_pclmul:: -- --include-ignored --test-threads=1
RUSTFLAGS='--cfg brynja_ghash_pclmul_evidence' cargo +1.90.0 test --locked --offline \
  --release -p brynja-crypto --no-default-features --features hazmat-ghash,cpu,hazmat-aes-block \
  --test ghash_field --test ghash_lifecycle -- --test-threads=1
```

**Public route contract and controls:**

1. Keep `Ghash::new` portable, including with all features enabled. Offer
   runtime selection through an explicit, fallible constructor and a default-off
   feature. Keep the raw field-product authority out of the facade.
2. Preserve the difference between missing CPU support and a failed startup
   test. Today the forced `RequiredProduct::detect()` converts *both* to
   `None`. That works when acceleration is mandatory, but using it for
   “prefer” would silently hide a failed KAT. Only absence may fall back;
   a failed KAT or quarantined owner must fail closed in both modes. Report
   the actual selected backend without deriving it from AES availability.
3. `brynja-verify run ghash packaged-x86-runtime` exercises both packaged
   entry points on both compilers: native PCLMUL, QEMU with AES but no PCLMUL,
   and a deliberately incorrect expected KAT answer in a **separate unpacked
   control build**. Both modes reject that last build without touching the
   workspace. The test also checks that the CPU facade cannot import the raw
   handle and compiles the feature on Cortex-M without a hosted detector.

Enable `ghash-runtime-execution` on either `brynja-crypto` or `brynja`.
Call `Ghash::new_with_backend(h, workspace, budget, Mode::Require)` for
native-or-error, or pass `Mode::Prefer` to permit portable fallback when
the instruction bundle is absent. Inspect `backend()` for the actual choice.
This interface does not select AES, perform authentication, or confer FIPS
validation. The earlier timing and throughput records describe the candidate
artifacts; they are not measurements of the new public dispatch binary.

The packaged facade's **public** route test also ran from the identical
release executables on the Ryzen and the Xeon (hash-checked transfers, Xeon
CPU 0). Both prefer and require selected PCLMUL, while ordinary construction
stayed portable; split input, a rejected over-budget update, the second GHASH
product and live clearing were checked. The executed SHA-256 values were
`defd015ac02e148816e0b1811125d30e931429519f706f250105701dd215528f`
(1.90.0) and `5744eb0e67044e53bf65535df0b92dcbfa5d05eb3fc404106ed94c1858a83d6f`
(1.100.0). In both linked binaries the startup probe and data-product
method called the same multiply function, which contained four PCLMUL
instructions. This is a dispatch check, not a whole-binary side-channel review.

This decision neither enables PMULL on Arm nor qualifies RISC-V vector GHASH.

### Arm public PMULL route

In v0.28.2 development the explicit constructor can return `Backend::Pmull`
on **little-endian AArch64 Linux and macOS**. Ordinary `Ghash::new` remains
portable. The CPU layer checks NEON and AES (required by the Rust intrinsic)
and PMULL itself, then runs the known-answer field product before admitting the
owner. Selecting GHASH does not select an AES execution backend.

This is a functional admission, **not timing qualification**. The original AWS
identical-input alarm remains inconclusive. The order-balanced follow-up is a
separate observation, not a replacement ([results and original data](#accelerated-arm-timing-screen-protocol-declared-before-collection);
[community investigation](https://github.com/valkyoth/brynja/discussions/4)).
No timing campaign is run by the dispatch tests.

On 2026-11-23 both compiler endpoints passed these functional controls:

| Environment | Packages tested | Scenarios per compiler |
| --- | --- | --- |
| Linux AArch64 under QEMU | Direct crate and facade | Normal PMULL, masked PMULL, wrong startup answer |
| AWS Neoverse-V2 Linux, pinned CPU 0 | Facade; identical hash-checked executables to QEMU | All three |
| Apple M2 Pro, native macOS build and execution | Direct crate and facade | All three |

The absence control only **removes** PMULL from the detector; all three
environments actually report NEON, AES and PMULL. It tests `Prefer` fallback
and `Require` refusal, not a physical CPU lacking PMULL. A separate build
changes only the expected KAT answer in a private unpacked crate. Both modes
must return `Quarantined` without touching caller workspace. The normal build
checks the selected backend, split updates, a rejected over-budget update,
two consecutive products and clearing. The raw handle remains unavailable
through the facade even with its broader CPU feature.

The SHA-256 identities of the native **normal facade** executables:

| Native target | Rust 1.90.0 | Rust 1.100.0 |
| --- | --- | --- |
| Linux AArch64 musl | `3d3d0185778382381ff79ec266c8e4ddf9e5ad192102696af2c15b22b2c6bb69` | `d60d08495c6d42ece7ed2b936f009a8e7498d5e4313d9228c3c43705daede14d` |
| macOS AArch64 | `a4f2b116c8039aa2d8e38430f451edecc0cf7e6e4f498c8087bee61f915366e2` | `aa9313149cf5486472996b1b53e20107ab5ff1fecfc2b769eb7263e126fc432f` |

The Linux linked multiplication function contains three polynomial multiply
instructions. The Mac builds inline three into the data-product path and
three into startup selection. These are artifact-specific observations.

To reproduce, run `brynja-verify run ghash packaged-pmull-runtime` on the
Linux x86_64 build host, or `python3 scripts/ghash/check-packaged-runtime.py
--pmull macos` on Apple Silicon. Both require the two pinned Rust endpoints;
the Linux cross-build also needs QEMU, their AArch64 musl and Cortex-M targets.
For native Linux replay, add `--save-facade NEW_DIRECTORY` to the Python
runner with `--pmull linux`, hash-check the six executables after transfer to
the PMULL host, then run each with `--exact route_contract` and
`BRYNJA_TEST_GHASH_ROUTE` set to its prefix (`native`, `absent` or
`quarantine`). No privileged access is needed.

### RV64 public scalar route

The explicit constructor admits Linux RV64 **scalar Zbc**. Zbkc alone
supplies the instructions but has only emulated coverage here; it does not
admit the public backend. The decision uses the X60 native field and
incremental tests, scalar AES pairings, linked-code review, throughput,
branch/cache observations and timing screen recorded above. Those observations
are specific to the candidate builds, not a constant-time claim for dispatch.
The unavailable and quarantine contracts are the same as on x86. The API
reports `Backend::Rv64Zbc`; it needs neither AES nor vector crypto.

`brynja-verify run ghash packaged-rv64-runtime` runs the direct crate and
facade archive tests under QEMU at Rust 1.90.0 and 1.100.0. The guest checks
the reported ISA in each scenario: Zbc with no AES, Zbkc without Zbc, and
AES without either carry-less multiplication extension. A fourth scenario
changes only the expected startup answer in a separate unpacked build. Both
selection modes must refuse that build, with no fallback or workspace change.

On 2026-11-22 the same static packaged facade executables also passed on the
native SpacemiT X60, pinned to CPU 0 after verifying their SHA-256 hashes.
Ordinary construction stayed portable and both explicit modes selected Zbc
in the pristine binaries. Both wrong-answer controls returned quarantine.
In both pristine executables the linked startup probe and data product each
contained three `clmul` and three `clmulh` instructions. This checks which
kernel was linked; it is not a new timing experiment.

| Rust | Pristine facade SHA-256 | Wrong-answer control SHA-256 |
| --- | --- | --- |
| 1.90.0 | `7424dbdd4bc8497850529e15db44f6fbacecfd76ea1019164284c6e77fcba4e7` | `0d62e291107baaf4ec25e03d92ad3f2434ce1d7179b091e95d4ffb0c4be3fa42` |
| 1.100.0 | `88db72992d187a3ac1a29669935db418853a1490db7b09411dbfe03f970d51b7` | `5a715048ceb218a7e88d67e1196a4f28afb31f91e7a7ce23f90c82c2fb144904` |

For native replay, run `python3 scripts/ghash/check-packaged-runtime.py
--rv64 --save-rv64-facade NEW_DIRECTORY` on the build host. Verify the four
transferred files against their build-host hashes. On a Linux RV64 Zbc host,
set `BRYNJA_TEST_GHASH_RV64_MODEL=hardware` and run each executable with
`--exact route_contract --test-threads=1`, setting `BRYNJA_TEST_GHASH_ROUTE`
to its filename prefix (`native` or `quarantine`). No root access is needed.

### RISC-V vector disposition for v0.28.2

Keep vector GHASH **unimplemented and unadmitted** for this milestone on the
available hosts. A fresh read on the native SpacemiT X60 (2026-11-22) found V
and scalar Zbc on all eight Linux ISA lines, but **zero** lines advertising
Zvkg or Zvbc. No vector-crypto instruction was attempted there. This is an
assessment of what this system exposes, not of every RISC-V processor.

The [ratified vector cryptography specification](https://docs.riscv.org/reference/isa/unpriv/vector-crypto.html)
distinguishes two possible paths. Zvkg provides a reduced field multiply
and a GHASH update on 128-bit element groups. Zvbc instead provides the low
and high halves of carry-less products on 64-bit elements; a GHASH kernel
would still need to combine and reduce those products. Neither base V nor
scalar Zbc supplies either vector extension.

To reproduce the architecture check, run
`brynja-verify run ghash rv64-vector-capability-qemu`. It needs QEMU user
mode for RV64, a RISC-V GNU cross compiler with Linux hwprobe headers, and
the RV64 GNU target for both Rust 1.90.0 and 1.100.0. The standalone guest
checks Linux-reported extension bits rather than taking the model label as
authority. It exercises scalar-only, base-vector-only, Zvkg-only, Zvbc-only
and both-vector-extensions configurations; vector configurations check
VLEN 128 and 256. In this matrix “only” is relative to these GHASH extensions.
Zvkg checks a full product followed by a nonzero-accumulator length-block
update; Zvbc checks both halves of a lane product. Missing/unknown hwprobe
results, incorrect widths or mismatched answers fail the check.

Both endpoints passed all nine configurations with QEMU 11.1.3. These are
instruction examples outside the shipped crates, not tests of a Brynja vector
backend or native performance. Reopen the vector work when a native system
exposes at least one matching extension with usable OS vector state. Before
admitting that specific path, implement and test its actual owner, fallback,
field and package contracts and collect the named native measurements.
