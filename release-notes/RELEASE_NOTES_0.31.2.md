# v0.31.2 — Poly1305 and ChaCha20-Poly1305 CPU acceleration (in development)

This internal milestone follows the signed v0.31.1 tag. No crates are
selected for publication. Ordinary Poly1305 and AEAD construction remains
portable. The standalone Poly1305 crate now has an explicit Linux x86-64
AVX2 owner and the AEAD crate has an explicit Linux x86-64 SSE2/AVX2 pair.
Other architectures remain open; neither route is enabled by default.

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

## Integrated x86 owner experiment

Compare the real checked-key constructor, update, finalize and drop on both
routes, with one reusable tested CPU handle outside the timer. Use the same
Ryzen, CPU 0, compiler endpoints, 13 size/chunk cells, 12 alternating pairs,
warmup and batch sizes as the streaming study. No global AVX2 flags. Require
median portable/native above one in all four previously named long cells on
both compilers before admitting this layout for throughput. Retain every
pair including unfavorable results; do not adjust the threshold after the run.

**Decision: do not ship this layout.** Both compiled owners returned correct
tags, but the layout failed all four long cells on the minimum compiler.
Median paired portable/native elapsed times on the Ryzen 9 9950X3D:

| Message / update bytes | Rust 1.90.0 | Rust 1.100.0 |
| --- | ---: | ---: |
| 1500 / 1500 | 0.472 | 1.387 |
| 4096 / 4096 | 0.473 | 1.576 |
| 16384 / 16384 | 0.478 | 1.655 |
| 16384 / 1500 | 0.468 | 1.413 |
| 16384 / 17 (scalar updates) | 0.919 | 0.923 |

[All 312 paired observations](../assurance/poly1305/avx2-integrated-ryzen.csv)
are retained. Unlike the earlier prototype's 25 packed weights, this kernel
used nine 32-byte rows, assembling the columns in the group routine. Rust
1.100.0 emitted 25 wide multiplies with no calls in that group; 1.90.0
outlined multiplies and called array-draining helpers. This is an observed
code-generation difference, not a demonstrated cause or a timing-leakage
assessment. No Rust version, target flag, default feature, or facade changed
to turn the negative result into a pass.

The [candidate patch](../assurance/poly1305/avx2-integrated-candidate.patch)
preserves the actual CPU crate, one-time-key integration, downstream benchmark
and replay tests without enabling any of them in released packages. To replay
from the repository root, use a **fresh disposable checkout** at the exact
base (the patch has zero context). No live checkout needs to be modified:

```sh
patchfile="$PWD/assurance/poly1305/avx2-integrated-candidate.patch"
replay=$(mktemp -d)
git archive 68ad7dda1b7fe77b159a82b90db06512ef093dc2 Cargo.toml Cargo.lock crates assurance/poly1305 | tar -x -C "$replay"
(
  cd "$replay" || exit 1
  git apply --unidiff-zero "$patchfile" || exit 1
  for v in 1.90.0 1.100.0; do
    cargo +"$v" test --release --offline --locked --manifest-path assurance/poly1305/Cargo.toml \
      --features native-owner --test integrated_vectors || exit 1
  done
)
```

The replay passed on both endpoints: all 12 RFC records, 65 generated
boundary/long records, split updates, all wrong tag-byte positions, and
post-consumption clearing of caller key storage. Both measured binaries also
passed a QEMU native-capability control and rejected masked AVX2 without
falling back. Measured Linux x86-64 ELF SHA-256:
`a31bbee2b03ac3a6f44523ff8faa3dcf40a34b029d63a2e7dc79495137814074`
(1.90.0), `bb3343227007c922fb35c3230a076d195ae775d34a6d5abe23b1c882ca1198eb`
(1.100.0). This is an internal result, not x86 or AEAD backend admission.

### Integrated 25-weight comparison

Keep the preceding owner, checked import, CPU probe and benchmark driver
unchanged. Replace only the kernel's nine-row representation with the original
layout of 25 prepacked vector weights, cleared at the end of each long update.
Apply the same four-cell pass rule to the two compilers on CPU 0, with one
campaign per compiler and all 312 paired samples retained. A result below
the threshold stays recorded; it does not trigger another run.

**Decision: retain the 25-weight kernel in the standalone crate behind
`poly1305-avx2`, off by default and currently Linux x86-64 only.** All four
required medians exceeded one. The 1500-byte result on Rust 1.90.0 was
essentially a tie, not a meaningful speed claim. Chunk boundaries matter:
the Rust 1.90.0 candidate lost at 1024 bytes (0.946×), and 17-byte updates
were slower on both compilers. Leave ordinary `start()` portable.

| Message / update bytes | Rust 1.90.0 | Rust 1.100.0 |
| --- | ---: | ---: |
| 1500 / 1500 | 1.001 | 1.254 |
| 4096 / 4096 | 1.117 | 1.498 |
| 16384 / 16384 | 1.173 | 1.629 |
| 16384 / 1500 | 1.017 | 1.292 |
| 16384 / 17 | 0.920 | 0.927 |

[All 312 paired samples](../assurance/poly1305/avx2-integrated-25-ryzen.csv)
measure stock optimized builds of the downstream `integrated_owner --bench`
fixture on the Ryzen 9 9950X3D. Measured ELF SHA-256:
`1bbf3ececad783e3078aba7bf6ab57ee71f7e29e734be6585b9cb9d62a42a690`
(1.90.0), `2855c224bf830d2d41c28a0c0d70bebf0b812eee2e4671212215e0dc4a7831a3`
(1.100.0). These are throughput observations, not timing-leakage evidence.

To replay the correctness and linked-instruction checks without benchmarking:

```sh
python3 scripts/cryptography/check-poly1305-avx2-admission.py
```

The final owner passed the 12 RFC cases, 65 generated boundary/long records,
split and bad-tag checks on both endpoints, and the integrated suite under
x86-64 AddressSanitizer. The screens follow startup and public updates to
the same kernel and require AVX2 wide multiplies. Positive and AVX2-masked
QEMU executions distinguish availability, not throughput. Separately, a
one-limb mismatch in the expected startup answer in a disposable build
returned `Quarantined` on both compilers. The unchanged portable verifier
instruction pins still pass without the feature.

## Linux x86-64 paired AEAD

Measure complete disjoint seal and valid open using the same checked pair and
the same portable owners as the public API. On the same Ryzen and CPU 0,
compare stock release builds at Rust 1.90.0 and 1.100.0. Use 20 bytes of AAD
and payloads of 64, 256, 1024, 1500, 4096 and 16384 bytes. Allocate scratch
and construct owners before timing; include derivation, full-tag computation
or verification, scratch cleanup and destination commit. Warm both routes,
alternate their order over 12 pairs, and process floor(524288/size) records
per batch. Report all observations; require a median portable/native ratio
above one at 1500, 4096 and 16384 for both operations and both compilers for
a long-record throughput claim. Do not rerun to pass.

Median portable time divided by paired time on this Ryzen 9 9950X3D:

| Payload bytes | Rust 1.90.0 seal / open | Rust 1.100.0 seal / open |
| ---: | ---: | ---: |
| 64 | 0.922 / 0.943 | 0.924 / 0.936 |
| 256 | 1.148 / 1.145 | 1.079 / 1.077 |
| 1024 | 1.193 / 1.183 | 1.176 / 1.190 |
| 1500 | 1.183 / 1.171 | 1.186 / 1.189 |
| 4096 | 1.292 / 1.283 | 1.292 / 1.292 |
| 16384 | 1.326 / 1.319 | 1.329 / 1.332 |

[All 288 samples](../assurance/chacha20poly1305/paired-x86-ryzen.csv) are retained.
The long-record criterion passed on both compilers, but portable was faster
at 64 bytes. These measurements concern throughput, not side-channel leakage.
Measured example ELF SHA-256: `b978e03c527ccf892505699dab735e6db08be4f658d9610761cb6597a6dfa753`
(1.90.0), `dc7a27dc0ba01a2147272de17679b130daf3c1a492a264d614c85241a64a07ea`
(1.100.0). With no arguments both binaries admitted the pair under QEMU
`-cpu max` and reported `Unavailable` with `-cpu max,-avx2`.

On a Linux x86-64 AVX2 host, replay the public paired API checks with:

```sh
python3 scripts/cryptography/check-chacha20poly1305-vectors.py --paired-x86 --rust 1.90.0 --oracle --differential
python3 scripts/cryptography/check-chacha20poly1305-vectors.py --paired-x86 --rust 1.100.0 --oracle --differential
```

Each compiler passed two RFC records and 848 independently generated records.
The interruption tests exercise both buffer layouts and enforce two separate
outcomes: an incorrect tag never starts decryption, whereas an internal
failure clears scratch, leaves the destination unchanged and retires the pair.
