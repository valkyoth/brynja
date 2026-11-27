# Four-block ChaCha20 candidate (v0.30.1)

This unpublished, separate workspace evaluates the public `ChaCha20Sse2`
or `ChaCha20Neon` streaming owner against the scalar owner. It explicitly
uses SSE2 on x86-64 or NEON on little-endian AArch64: each 32-bit
lane processes the same word from a different block. It does not rely on the
compiler to vectorize scalar rounds. A separate Linux RV64 research candidate
in this fixture is **not** part of the cipher crate. The public SSE2 and NEON
owners are explicit opt-ins; there is no change to the default.
Named round and initial state buffers are cleared; this is not spill erasure.

Run locked/offline release tests and the benchmark on Rust 1.90.0 and 1.100.0:

```sh
cargo +1.90.0 test --manifest-path assurance/chacha20-parallel/Cargo.toml --locked --offline --release
cargo +1.90.0 build --manifest-path assurance/chacha20-parallel/Cargo.toml --locked --offline --release
taskset -c 0 assurance/chacha20-parallel/target/release/brynja-chacha20-parallel-probe
```

Repeat with `+1.100.0`; substitute an allowed CPU for 0 if necessary. For native comparisons use an otherwise idle host,
pin both routes to the same allowed CPU, use the same binary and stock target
flags, and retain every sample. In each size, alternate scalar-first and
candidate-first over 12 pairs after warming both routes. Compare the median
paired scalar/candidate ratio; above 1 means the candidate was faster.
64 and 255 bytes are scalar-tail controls; 256 and 257 cross the first group;
512, 1024, 1500, 4096 and 16384 represent larger records. Sub-batch controls
are not SIMD speedups. Inspect the final linked `chacha20_sse2::packed_rounds` with
`objdump -d -C` for packed additions, XORs and shifts implementing rotations.
In the [integrated owner run](x86-64-owner-throughput.txt), both linked round bodies had 32
each of `paddd`, `pxor`, `pslld` and `psrld`. At 1500 bytes, including the
scalar tail, median speedups for the final implementation were 1.386× (1.90)
and 1.226× (1.100); at 16 KiB they were 1.524× and 1.298× respectively. The [earlier prototype
run](x86-64-throughput.txt) is retained separately. These are single-host,
aligned-start in-place throughput observations, not timing qualification.

For Apple Silicon use the same sizes, repetitions, alternating order, scalar
control and stock endpoints. Run one native release executable per compiler,
with ordinary macOS scheduling (no Linux-style CPU pinning); retain every pair,
including slow samples. Inspect the linked packed round body, and compare
medians at 256 bytes and above, including 1,500 and 16,384 bytes. Report any
regression rather than retrying for a faster result. Linux QEMU tests correctness
only: do not use emulator timings to select a backend.

On the [native Apple M2 Pro run](apple-m2-pro-throughput.txt), median speedups
at 1,500 bytes were 1.322× (Rust 1.90) and 1.213× (1.100); at 16 KiB they
were 1.437× and 1.253×. Every measured size with at least one four-block
group improved on both compilers. At 64 bytes the 1.90 result was 0.989×;
no vector group runs at that length. The measured linked round bodies each
contained 32 packed 32-bit additions and 32 vector XORs. All four public
owner tests passed natively and under Linux musl QEMU on both compilers.

To repeat on an Apple Silicon Mac, run from this fixture directory with the
stock toolchains (the recorded host ran macOS 27.2.1):

```sh
for ver in 1.90.0 1.100.0; do
    cargo "+$ver" test --locked --offline --release --target-dir "target/$ver" --test parallel &&
    cargo "+$ver" build --locked --offline --release --target-dir "target/$ver" &&
    "target/$ver/release/brynja-chacha20-parallel-probe" || exit 1
done
```

For the independent Linux ARM correctness check, run
`python3 scripts/cryptography/check-chacha20-archive.py --neon-qemu-differential`
from the repository root on Linux x86-64 with `qemu-aarch64`, OpenSSL and both
Rust AArch64 musl targets installed. The oracle runs on the host; the archived
Rust consumer runs in the emulator. Neither OpenSSL nor the test runner is a
library dependency.

## RV64 V candidate: admission experiment

The Linux RV64 probe is a standalone experiment, not a published owner.
It requests exactly four 32-bit lanes at any supported VLEN. Only the separate
round function enables the V ISA; the binary and scalar comparison use the
stock RV64GC target with static linking. Its scalar ELF calling convention
follows the [RISC-V psABI](https://riscv-non-isa.github.io/riscv-elf-psabi-doc/#_standard_calling_convention).
Failure to detect V must refuse the forced route before any destination write.
This prototype covers aligned stream positions and scalar tails, not a
fragmented public RVV streaming owner or a constant-time qualification.

Before collecting performance: exercise RFC vectors, scalar comparisons,
counter rejection and Linux no-V refusal under QEMU. Repeat positive tests
at VLEN 128 and 256 on both compiler endpoints and inspect the linked round
function. On qualifying native hardware pin both routes to the same allowed
CPU and run the very same tested binaries, one launch per compiler, with the
existing alternating-pair protocol. Keep every sample. Do not select this
candidate if the paired median is at or below scalar at any planned size
from 256 bytes upward on either endpoint. The 64- and 255-byte rows are
scalar-tail controls, not vector speedups. Never use QEMU timing for admission.

**Decision: not admitted for v0.30.1.** On the [native SpacemiT X60 run](spacemit-x60-throughput.txt)
every measured size from 256 bytes to 16 KiB was slower than scalar. At
1,500 bytes the scalar/candidate time ratios were 0.949 (1.90) and 0.787
(1.100); at 16 KiB they were 0.938 and 0.748. Both native test binaries
passed the three aligned-record tests, and their hashes and those of the
benchmark programs were checked before and after execution. This rejects
this implementation on the tested host, not the V extension in general.
No consumer feature, CPU dependency or new public streaming owner on RV64.

To reproduce correctness locally on Linux x86-64, install the Rust RV64GC
Linux GNU target on both endpoints, a matching static GNU cross-linker/sysroot,
QEMU user-mode and llvm-objdump. Run `python3 assurance/chacha20-parallel/check-rvv.py`
from the repository root, or use the registered `chacha20` check. The baseline
RV64GC executable reads the [Linux ELF HWCAP V bit](https://docs.kernel.org/arch/riscv/vector.html)
without enabling vector state or changing affinity. QEMU refusal is not a
claim about all Linux kernels or all deployment policies.

To repeat the native comparison, use the same static RV64GC build as the
QEMU check. For example, from the fixture directory on the cross-build host:

```sh
export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=riscv64-linux-gnu-gcc
export CARGO_ENCODED_RUSTFLAGS=-Ctarget-feature=+crt-static
for ver in 1.90.0 1.100.0; do
    cargo "+$ver" test --locked --offline --release --test parallel --no-run \
        --target riscv64gc-unknown-linux-gnu --target-dir "target/$ver" || exit 1
done
```

Use the SUSE linker name instead when appropriate. For each version transfer
the printed test executable and the corresponding
`target/<version>/riscv64gc-unknown-linux-gnu/release/brynja-chacha20-parallel-probe`
to a V-capable Linux RV64 host. Check SHA-256 against the build-host copies,
run the tests with `--test-threads=1`, then launch the benchmark once with
`taskset -c <allowed-cpu>` and preserve its complete stdout. Builds on another
machine need not have the same digest as the recorded binaries.
