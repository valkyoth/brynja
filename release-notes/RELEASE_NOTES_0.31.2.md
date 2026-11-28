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
