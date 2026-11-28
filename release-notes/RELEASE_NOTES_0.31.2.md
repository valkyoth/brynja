# v0.31.2 — Poly1305 and ChaCha20-Poly1305 CPU acceleration (in development)

This internal milestone follows the signed v0.31.1 tag. No crates are
selected for publication. Both public Poly1305 and AEAD owners remain
portable. No accelerated backend is admitted by this first experiment.

## First experiment: native x86-64 AVX2 arithmetic

The [unpublished probe](../assurance/poly1305/examples/four_block_probe.rs)
evaluates four consecutive blocks of **one message** as
`(h+m0)r⁴ + m1r³ + m2r² + m3r` modulo 2¹³⁰−5. It clamps the raw key once,
not the computed powers. Each AVX2 lane multiplies unsigned 26-bit-radix
limbs; reduction folds the high powers with factor five. The scalar tail
places the appended one bit after the actual bytes, including partial blocks.
The experiment uses public data only and deliberately lacks production
one-time-key and scratch-clearing ownership. Do not use it for secrets.

Before collecting throughput, require all 12 published Poly1305 vectors and
2,112 comparisons against the public portable owner, on Rust 1.90.0 and
1.100.0. Build in release mode with stock flags; pin each run to one allowed
CPU. For each size (16, 63, 64, 65, 256, 1500, 4096 and 16384 bytes), warm
both routes, then retain 12 paired elapsed times in alternating order. Each
batch processes `floor(524288 / size)` complete records including per-message
setup and finalization. Compare the median of paired portable/probe ratios.
Only pursue **this layout** for long records if the median exceeds one at
1500, 4096 and 16384 on both compilers. A positive result is not an admission:
the experiment must still beat the baseline with equivalent secret handling.
These are throughput measurements, not a constant-time test.

```sh
cargo +1.90.0 build --release --locked --offline --manifest-path assurance/poly1305/Cargo.toml --example four_block_probe
taskset -c 0 assurance/poly1305/target/release/examples/four_block_probe --bench
```

Repeat with `+1.100.0`; substitute an allowed CPU for 0 if needed. This
probe refuses to run without AVX2. ARM64 and qualifying RISC-V candidates,
native measurements, ownership and failure checks, and paired AEAD integration
are separate remaining work. QEMU results may check correctness, not speed.

### First native observation, not production admission

Both correctness runs passed on an AMD Ryzen 9 9950X3D (Linux x86-64).
The linked group function in each executable contained AVX2 `vpmuludq`.
[All 192 paired observations](../assurance/poly1305/avx2-four-block-ryzen.csv)
are retained, with wall times in nanoseconds per batch, pinned to logical CPU 0.

| Bytes | Rust 1.90.0 portable/probe | Rust 1.100.0 portable/probe |
| ---: | ---: | ---: |
| 16 | 1.390 | 1.384 |
| 63 | 1.025 | 0.852 |
| 64 | 0.436 | 0.691 |
| 65 | 0.539 | 0.681 |
| 256 | 0.810 | 1.108 |
| 1500 | 1.230 | 1.438 |
| 4096 | 1.402 | 1.595 |
| 16384 | 1.462 | 1.632 |

Below 64 bytes the probe runs no AVX2 group; differences there are not a SIMD
gain. Precomputing powers for just one group loses on both endpoints. Long
records met the experiment's continuation criterion. Next, measure the same
sizes with lifecycle-equivalent owners, including power storage/cleanup,
streaming splits and short-input routing, before any public API decision.
These MAC-only ratios do not predict an AEAD or another CPU's speedup.

Measured release executable SHA-256: `d73ae2b5b8903e3affd7f4fd47e4f5f1e0774565426eaf78ebc4938017ae9d69`
(1.90.0), `226e1899b06846b2d9f0990ba38d3463886785aabd736aa660f956414db9b2a3`
(1.100.0).

## Streaming and cleanup experiment

The [experimental owner](../assurance/poly1305/examples/avx2/stream.rs)
borrows and clears a one-time key and workspace. It buffers at most 15 bytes
between calls and rejects cumulative length overflow before touching state.
After completing a buffered partial block, **at least 1024 remaining contiguous
bytes** are required before computing a 160-byte power set and an 800-byte
AVX2 multiplication table. Both live only for that update and are guarded for
cleanup. Shorter updates use scalar arithmetic. This is an exact-RFC import
fixture, not a checked public key constructor. Clearing named storage is not
a claim about registers, spills, forgotten owners or process abort.

Before benchmarking, check both compiler endpoints against the 12 RFC cases,
the 2,112 generated records with four chunk sizes each, every two-way split
at selected lengths, each incorrect tag byte, and live-storage cleanup on
completion, rejection, abandonment and unwind. Check overflow without large
allocations. Exercise both sides of the routing threshold.

Use the first experiment's host, CPU pin, build flags, 12 alternating pairs
and batch size. Run `cargo test --example four_block_probe` in the fixture,
then its optimized example with `--stream-bench`. Both timed routes here take
the same key copy, consume a message owner, include setup/finalization/
destruction and split the same input at the same offsets. Record the original
lengths plus 1023, 1024 and 1025, and a 16 KiB record split into 1500-byte
and 17-byte updates. Keep all pairs. For the long-update design to proceed,
require median portable/owner time above 1 at 1500, 4096 and 16384 bytes
and for the 1500-byte split on **both** compilers. Report short-path costs
separately; they are not evidence of a SIMD gain. Do not tune and rerun a
losing configuration as part of this measurement.

### Streaming result on the Ryzen 9 9950X3D

All four predeclared long-update cases met the continuation criterion on both
compilers. Below are the medians of the paired portable/owner elapsed times;
above 1 means the experimental owner was faster. The [312 original pairs](../assurance/poly1305/avx2-stream-ryzen.csv)
include every short-input and split-update run.

| Message bytes | Update bytes | Rust 1.90.0 | Rust 1.100.0 |
| ---: | ---: | ---: | ---: |
| 16 | 16 | 0.974 | 1.084 |
| 63 | 63 | 0.793 | 0.982 |
| 64 | 64 | 0.754 | 1.038 |
| 65 | 65 | 0.764 | 0.976 |
| 256 | 256 | 0.653 | 1.002 |
| 1023 | 1023 | 0.628 | 0.984 |
| 1024 | 1024 | 1.001 | 1.114 |
| 1025 | 1025 | 0.993 | 1.079 |
| 1500 | 1500 | 1.066 | 1.168 |
| 4096 | 4096 | 1.238 | 1.370 |
| 16384 | 16384 | 1.315 | 1.463 |
| 16384 | 1500 | 1.082 | 1.195 |
| 16384 | 17 | 0.678 | 0.708 |

Message size alone is not a dispatch rule. A 16 KiB message in 17-byte
updates never takes the vector path and loses on both compilers. Near 1 KiB
the margin is small or absent on Rust 1.90.0. Keep the portable owner as the
public default. The next x86 step is to isolate the long-update kernel behind
the project's CPU admission and cleanup boundaries and check the linked
consumer; these measurements do not qualify a public backend, AEAD speed,
timing leakage or other processors.

Both optimized examples matched the RFC cases and the 8,448 split-message
comparisons against the portable owner. The split, overflow, tag and cleanup
unit tests passed on both endpoints and under x86-64 AddressSanitizer.
Disassembly of each timed executable contained `vpmuludq` in the four-block
group or its outlined closure. Measured executable SHA-256:
`408101f1a5bc66a15d87ccc09601def9235e8f660ebd7a60550b145a3f7c5f15`
(1.90.0), `c69ffdf82a487fea0e92810d1cf01057982c9b13ee156263d23f54b587ffe016`
(1.100.0).

## Hosted AVX2 admission and linked replay (checkout only)

The streaming example now admits a reusable, thread-local execution handle
before borrowing a one-time key or changing the caller's workspace. It checks
host AVX2 support, then runs a fixed known-answer test through the actual
four-block kernel. The test starts with a nonzero accumulator, processes two
groups with distinct lane inputs and compares all five result limbs. A wrong
answer or unwinding out of startup or a native update retires that handle.
It cannot start, update, finalize or verify another message; the required
route does not fall back. There is no thread pinning: as with the hosted GHASH
route, the advertised ISA must stay usable wherever the thread may run.

Run `python3 scripts/cryptography/check-poly1305-avx2-admission.py` on AVX2
Linux x86-64 with both compilers, LLVM objdump and QEMU user mode installed.
For each stock release ELF, the checker follows the startup and message paths
to the same vector group, checks for four-lane unsigned multiplication, and
rejects a parsed listing with those instructions removed. It then runs the
native corpus and runs the same binary under QEMU with AVX2 present and
masked. Only the latter must exit with “unavailable”. QEMU is a feature
selection check, not a throughput measurement.

Both endpoints passed (1.90.0 ELF SHA-256
`f6082549a0c750ca9d5726465c2e690d9b912445311bf10e3326ed85854384a4`;
1.100.0 `229b4ab23f0446f8f551b0421ff65823e55f11513c6c1c7d6715ca1f6cc2898b`).
The seven admission, streaming and cleanup tests also passed on both compilers
and under x86-64 AddressSanitizer. The earlier throughput numbers describe the
pre-admission build at `527daa33`, not these ELFs. No public CPU or AEAD route
is enabled. The next integration step is the opt-in CPU-crate kernel and its
one-time-key owner, followed by measurement of that shipped layout.
