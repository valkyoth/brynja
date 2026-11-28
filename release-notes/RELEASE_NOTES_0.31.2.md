# v0.31.2 — Poly1305 and ChaCha20-Poly1305 CPU acceleration (in development)

This internal milestone follows the signed v0.31.1 tag. No crates are
selected for publication. Ordinary Poly1305 and AEAD construction remains
portable. The standalone Poly1305 crate now has an explicit Linux x86-64
AVX2 owner and the AEAD crate has an explicit Linux x86-64 SSE2/AVX2 pair.
The Linux/macOS AArch64 NEON routes and standalone RV64 Linux RVV MAC
described below are also opt-in. There is no RISC-V AEAD pair.

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

## AArch64 NEON two-block probe (unpublished)

The [ARM experiment](../assurance/poly1305/examples/neon_probe/mod.rs) computes
two consecutive blocks of the same message as `(h + m0)r² + m1r` modulo
2¹³⁰−5. Only the original key is clamped. Short messages and the final
partial block use scalar arithmetic. This is a public-input experiment:
it does **not** implement production key ownership, clearing or streaming.
It is not reachable through any published crate or feature.

Run `python3 scripts/cryptography/check-poly1305-neon-probe.py` to cross-build
and replay. On Rust 1.90.0 and 1.100.0, each optimized Linux AArch64 musl ELF
passed 12 RFC cases and 2,112 generated records against both the independent
integer model (expected tags) and the portable owner. The runner rejected a
wrong tag on a long record. The linked two-block body has five two-lane
widening multiplies and twenty multiply-accumulates; removing the latter from
the inspected listing makes the instruction check fail.

| Rust | SHA-256 of ELF executed under QEMU |
| --- | --- |
| 1.90.0 | `60cd53d019b773c1510bf1b9aeeba558d537e338ea56f9627109e6cf16304c52` |
| 1.100.0 | `99f023ee61b3262c00eeedad74ddde1ba60a78292794e55d2217cfe983cbe095` |

Apple AArch64 compile checks passed on both compilers; neither that nor QEMU
establishes native throughput. Before measuring on a named physical ARM
host, use the following rule: stock optimized builds of both endpoints,
16/31/32/33/256/1500/4096/16384-byte messages, warm both routes, alternate
order over 12 pairs and retain every raw observation. Pin one eligible core
where the OS permits; otherwise report the scheduling limitation. Run the
following on that host for each endpoint (substitute `+1.100.0` for the second):

```sh
cargo +1.90.0 run --offline --locked --release --manifest-path assurance/poly1305/Cargo.toml --example neon_two_block -- --bench
```

Only proceed to a production-owner candidate on that host if the median of
paired portable/probe times exceeds one for **each** of 1500, 4096 and 16384
bytes on both compilers. A win for this raw probe does not admit a public
backend: the actual owner and the paired AEAD would need separate tests and
measurements. Do not benchmark QEMU or pool observations across platforms.

### Native ARM results: proceed to the owner experiment

The probe from commit `e0198e04` met the long-record criterion on both named
hosts. [All 384 paired observations](../assurance/poly1305/neon-two-block-native.csv)
are retained, including the 33-byte Linux case that was slower on Rust 1.90.
Values below are medians of the twelve portable-time / probe-time ratios;
greater than one favors the probe.

| Bytes | Apple M2 Pro 1.90 | Apple M2 Pro 1.100 | Neoverse-V2 1.90 | Neoverse-V2 1.100 |
| ---: | ---: | ---: | ---: | ---: |
| 16 | 2.078 | 2.633 | 1.572 | 2.535 |
| 31 | 1.352 | 1.586 | 1.378 | 1.558 |
| 32 | 1.335 | 1.447 | 1.262 | 1.199 |
| 33 | 1.177 | 1.563 | 0.962 | 1.045 |
| 256 | 1.309 | 1.457 | 1.159 | 1.187 |
| 1500 | 1.269 | 1.293 | 1.163 | 1.168 |
| 4096 | 1.263 | 1.266 | 1.183 | 1.185 |
| 16384 | 1.250 | 1.268 | 1.190 | 1.186 |

Each of the four binaries first replayed all 2,124 known-answer and generated
records on its native host, then ran the declared benchmark once. Hashes
matched before and after. The Linux runs used the same static musl ELFs
listed above, pinned to vCPU 0 on an AWS Neoverse-V2 guest
(`7.0.0-1018-aws`). The Apple runs used stock native Darwin release builds
on macOS 27.2.1 (26B131), with scheduling left to macOS; core type was not
controlled. Measured Mach-O SHA-256:
`3c84ab2d6c4372ee936acb953ae53f8091e9a9945a535f97f08714969b3ab028`
(1.90.0) and
`8d79dc575cc6b0423eb651c4da00c45b4186861b7ca1ce81f105f544d3ab1075`
(1.100.0).

These are whole-message probe results, **not** speedups of a clearing
Poly1305 owner or of ChaCha20-Poly1305. At 16 and 31 bytes the probe does
not execute its NEON two-block kernel at all. The next comparison must
include equivalent one-time-key handling, streaming and cleanup before
deciding whether to expose an ARM backend.

### Integrated ARM owner experiment

Adapt the existing checked one-time-key and streaming owner to use the
two-block NEON kernel for aligned update bodies of at least 1024 bytes.
Include key validation, clearing of the key, powers and packed weights,
scalar prefix/tail, handle checks and finalization in the measured record;
reuse the tested CPU handle. Before measuring, require the 12 RFC answers,
65 generated records with streaming partitions, all tag-byte rejections,
and caller-visible key clearing. On both native hosts, use stock optimized
1.90.0 and 1.100.0 builds, the prior scheduling policy, twelve alternating
pairs per configuration, and 524288 bytes divided by record length per batch
(rounded down to whole records). Report 16, 31, 32, 33, 256, 1023, 1024,
1025, 1500, 4096 and 16384 bytes in one update, plus 16384 bytes updated
in 1500- and 17-byte chunks. Per host, require a median portable/owner ratio
above one at each of 1500, 4096 and 16384 bytes in one update, on both
compilers. Retain every sample; no reruns to obtain a pass. Passing permits
further admission work, not automatic release or an AEAD performance claim.

Both hosts passed. These are medians of paired elapsed-time ratios, not a
comparison of the two machines. The Mac used normal macOS scheduling; Linux
was pinned to vCPU 0 on the same Neoverse-V2 guest as the probe.

| Bytes / update chunk | M2 Pro 1.90 | M2 Pro 1.100 | Neoverse-V2 1.90 | Neoverse-V2 1.100 |
| ---: | ---: | ---: | ---: | ---: |
| 16 / 16 | 0.896 | 0.897 | 0.847 | 0.889 |
| 31 / 31 | 0.988 | 0.942 | 0.903 | 0.876 |
| 32 / 32 | 0.936 | 0.916 | 0.917 | 0.867 |
| 33 / 33 | 1.001 | 0.964 | 0.939 | 0.893 |
| 256 / 256 | 0.982 | 0.979 | 0.968 | 0.964 |
| 1023 / 1023 | 0.994 | 0.996 | 0.982 | 0.987 |
| 1024 / 1024 | 1.277 | 1.254 | 1.247 | 1.164 |
| 1025 / 1025 | 1.273 | 1.241 | 1.238 | 1.159 |
| 1500 / 1500 | 1.335 | 1.293 | 1.280 | 1.200 |
| 4096 / 4096 | 1.415 | 1.358 | 1.370 | 1.281 |
| 16384 / 16384 | 1.447 | 1.403 | 1.423 | 1.306 |
| 16384 / 1500 | 1.336 | 1.297 | 1.297 | 1.225 |
| 16384 / 17 | 0.937 | 0.939 | 0.950 | 0.978 |

[All 624 samples](../assurance/poly1305/neon-integrated-native.csv) include
the short records and small updates: using this owner for a 16 KiB record
in 17-byte chunks was slower on all four configurations. Callers should not
infer a speedup from total message length alone.

Native downstream tests on each host/compiler passed before timing. They
exercised the actual MAC owner, not just the CPU entry point. Separate QEMU
tests on both compilers checked overflow before mutation, clearing after
interruption, and clearing the live weights on both return and unwind.
A one-limb change to the expected startup result in a disposable build
produced `Quarantined` rather than a working handle on both compilers. The
measured Linux ELFs each contain a call to the kernel whose body has five
NEON widening multiplies and twenty multiply-accumulates.

| Measured executable (SHA-256) | Rust 1.90.0 | Rust 1.100.0 |
| --- | --- | --- |
| Apple arm64 Mach-O | `4b6f641d1437d8385a2cf52f148ecfbf7dc9735680227af14d83961e16f5ee7d` | `18290f7a55fcabd6d977e0f82ed8f69b327c36dbc91b4c1d0c8ede5674553021` |
| Linux arm64 musl ELF | `40fee40fc528e4c35bc8457628de79fbfc21c1468f6b2b483e5beb06c5a48030` | `2e8f4643145ec4ce83057abf0ec7a9d9e5f23d114de3b4048398a586da2f2e7c` |

The [measured candidate](../assurance/poly1305/neon-integrated-candidate.patch)
is not a public feature. It assumes a little-endian AArch64 Linux or macOS
target compiled for NEON; its startup test is **not** a runtime ISA probe.
This evidence supports integrating an explicit owner for those targets. It
does not establish whole-AEAD throughput or side-channel qualification.
To replay the public test on a native builder without changing a live tree:

```sh
patchfile="$PWD/assurance/poly1305/neon-integrated-candidate.patch"
replay=$(mktemp -d)
git archive cc004264d3fcee7f5f9fe961d5705813b2637f39 Cargo.toml Cargo.lock crates assurance/poly1305 | tar -x -C "$replay"
(
  cd "$replay" || exit 1
  git apply --unidiff-zero "$patchfile" || exit 1
  for v in 1.90.0 1.100.0; do
    cargo +"$v" test --locked --offline --release --manifest-path assurance/poly1305/Cargo.toml \
      --features neon-owner --test neon_vectors || exit 1
  done
)
```

### AArch64 paired AEAD campaign

On Apple M2 Pro and AWS Neoverse-V2, compare complete disjoint seal and valid
open against portable, using the same fixture and criterion as the x86 AEAD
campaign. Use Rust 1.90.0 and 1.100.0 at stock release settings, a checked pair
reused across messages, 20 bytes AAD, six payload lengths (64 through 16384),
12 alternating observation pairs and floor(524288/size) records per batch.
Pin Linux to vCPU 0; leave macOS scheduling to the OS. Before measuring require
both RFC records, the 848 independent records through both layouts, and the
paired interruption tests. Keep all observations. Require a median
portable/paired ratio above one separately for both operations at 1500, 4096
and 16384 on both compilers on each named host. Do not rerun to pass.

Both hosts passed the criterion. [All 576 samples](../assurance/chacha20poly1305/paired-neon-native.csv)
are retained. Below are median portable/paired time ratios for seal / open.

| Bytes | M2 Pro 1.90 | M2 Pro 1.100 | Neoverse-V2 1.90 | Neoverse-V2 1.100 |
| ---: | ---: | ---: | ---: | ---: |
| 64 | 0.956 / 0.956 | 0.943 / 0.984 | 0.929 / 0.930 | 0.923 / 0.932 |
| 256 | 1.170 / 1.165 | 1.080 / 1.080 | 1.112 / 1.115 | 1.037 / 1.038 |
| 1024 | 1.303 / 1.298 | 1.174 / 1.153 | 1.257 / 1.258 | 1.116 / 1.114 |
| 1500 | 1.268 / 1.265 | 1.155 / 1.147 | 1.225 / 1.230 | 1.112 / 1.108 |
| 4096 | 1.366 / 1.370 | 1.201 / 1.202 | 1.312 / 1.316 | 1.160 / 1.158 |
| 16384 | 1.377 / 1.383 | 1.217 / 1.215 | 1.329 / 1.331 | 1.170 / 1.182 |

Each compiler/host passed 11 unit tests, two RFC records, and 848 independent
records through both buffer layouts before measurement. At 64 bytes portable
was faster everywhere. No timing-leakage or physical qualification is implied.
Measured binaries by Rust version (1.90.0, 1.100.0):

- macOS arm64: `83db809bb79f2d452b6a805829af5190ee25ec2889e7daa12e31e5ab70e1e050`,
  `b72b3630823e344c46d5011f3f9e6d4e9300a571b3c27bbe5519abd08f2a5f27`.
- Linux arm64 musl: `80577cfedf02587a951e4316ead4a0a09f622ba68e41ebd65e356c2b175d8c92`,
  `968d8d5192afbf3036586cbeb938d25e3cc1360c9ca4d7833af54e344c57e7fe`.

To replay on a supported native host, run
`python3 scripts/cryptography/check-chacha20poly1305-vectors.py --rust 1.90.0 --paired-neon --oracle --differential`
and repeat for 1.100.0. In this development checkout the leaf or either
façade can select `chacha20poly1305-neon`; callers explicitly supply
`execution::ArmPair::probe()` via `with_pair`. The MAC leaf separately exposes
`poly1305-neon`. Default constructors stay portable.

### RV64 Linux: standalone Poly1305 admission experiment

Evaluate one RVV 1.0 layout on SpacemiT X60: four adjacent full blocks in
four e32 lanes, multiplied by r⁴, r³, r² and r. Clamp r, not its powers.
Only the isolated arithmetic kernel may use V; both the probe and the
portable reference otherwise use stock RV64GC. This is unpublished
public-input research, not a clearing owner. No accelerated RVV ChaCha20
owner was admitted in [the previous native campaign](../assurance/chacha20-parallel/README.md#rv64-v-candidate-admission-experiment).
That precludes a native AEAD pair, but does not decide standalone Poly1305.

Before timing, require 12 RFC cases and 2,112 independent boundary/long
cases on Rust 1.90.0 and 1.100.0, VLEN 128 and 256 under QEMU, rejection of
a corrupted answer and clean refusal with V disabled. Check widening
multiplication in the linked kernel. Run the same static binaries natively
on CPU 0, correctness before timing, one benchmark launch per compiler.
Use 16/63/64/65/256/1500/4096/16384-byte messages, floor(524288/size) records
per batch, warm both routes, alternate order over 12 pairs, and retain all
samples. The required median portable/probe ratio is **above one at each of
1500, 4096 and 16384 bytes on both compilers**. A pass permits an integrated
owner experiment, not a public feature. A failure leaves RV64 portable;
do not time QEMU or repeat native measurements to secure a pass.

**Result: advance the standalone layout to a streaming-owner experiment.**
Both exact binaries passed all 2,124 records on the native Linux X60 after
passing at both emulated vector widths. With V disabled the probe refused
to run. [All 192 native sample pairs](../assurance/poly1305/rvv-four-block-x60.csv)
are retained. Each value below is the median of the 12 paired ratios of
portable time to probe time; values above one favor the probe.

| Bytes | Rust 1.90.0 | Rust 1.100.0 |
| ---: | ---: | ---: |
| 16 | 2.071 | 2.289 |
| 63 | 1.533 | 1.719 |
| 64 | 1.745 | 2.101 |
| 65 | 1.650 | 1.974 |
| 256 | 2.487 | 2.759 |
| 1500 | 2.882 | 3.052 |
| 4096 | 3.041 | 3.199 |
| 16384 | 3.094 | 3.222 |

The 16- and 63-byte cases never enter the vector kernel. These results
compare complete probe calls on public messages, not equally hardened
owners: they do not measure streaming, key clearing or side-channel
resistance. No RVV feature or AEAD pair is enabled by this result.

To reproduce the correctness checks and export the native inputs, run
`python3 scripts/cryptography/check-poly1305-rvv-probe.py --export NEW_DIRECTORY`.
On an RV64 Linux host with V, run `taskset -c 0 ./probe-1.90.0 < public.tsv`
from the exported directory before `taskset -c 0 ./probe-1.90.0 --bench`;
substitute `probe-1.100.0` for the other compiler. The SHA-256 digests of
the binaries measured on the X60, checked before and after execution, were:

- Rust 1.90.0: `165c66a8cca9c0910608c6b8b160ed7bf65787344ebc80cc34100e867f44f786`.
- Rust 1.100.0: `986251007e7f869cc014dd3e1cfb57b0e44207806cea55031c4c787e0dc1d3c5`.

### Integrated RV64 Linux streaming owner experiment

Measure the four-block layout only when a contiguous update has at least
1024 bytes after completing a buffered block. The candidate uses the same
portable prefix, tail, length checks, one-time key and finalization as the
portable owner. Include key admission and cleanup, packed weights and powers,
and message creation in each record; reuse only the CPU handle. Before
measurement require the 12 RFC records, 65 generated streaming cases with
all 16 tag-byte rejections and caller-key clearing, on the X60 and under
QEMU on both compilers. Check refusal without V separately.

Use the same Linux X60, CPU 0, stock RV64GC static release builds (Rust
1.90.0 and 1.100.0). Run once per compiler; warm both routes, alternate
order over 12 pairs, and use floor(524288/size) records per batch. Measure
16/63/64/65/256/1023/1024/1025/1500/4096/16384 bytes in one update, plus
16384 bytes in 1500- and 17-byte updates. Keep all samples. Require a
median paired portable/owner time ratio above one for *each* of 1500, 4096
and 16384 bytes in one update on *both* compilers. Do not rerun to pass.
Passing permits a standalone backend review, not an automatic public API,
a paired AEAD, or a timing-leakage claim.

**Result: the clearing streaming owner passed all six long-record
comparisons.** The table reports medians of the 12 paired portable/native
elapsed-time ratios; [all 312 sample pairs](../assurance/poly1305/rvv-integrated-x60.csv)
are retained, including the slower cases.

| Message bytes / update bytes | X60, Rust 1.90.0 | X60, Rust 1.100.0 |
| ---: | ---: | ---: |
| 16 / 16 | 0.819 | 0.819 |
| 63 / 63 | 0.899 | 0.891 |
| 64 / 64 | 0.897 | 0.892 |
| 65 / 65 | 0.911 | 0.901 |
| 256 / 256 | 0.962 | 0.958 |
| 1023 / 1023 | 0.989 | 0.987 |
| 1024 / 1024 | 2.670 | 2.290 |
| 1025 / 1025 | 2.599 | 2.241 |
| 1500 / 1500 | 2.786 | 2.418 |
| 4096 / 4096 | 3.341 | 2.886 |
| 16384 / 16384 | 3.578 | 3.099 |
| 16384 / 1500 | 2.926 | 2.530 |
| 16384 / 17 | 0.927 | 0.924 |

Below the 1024-byte threshold no vector groups execute. In particular, a
16 KiB message delivered in 17-byte updates was slower than portable; the
same message delivered in 1500-byte updates was faster on both compilers.

Before timing, both native builds passed the RFC and streaming suite; the
same tests passed under QEMU at VLEN 128 and 256. An emulated CPU without
V refused the required route (`Unavailable`). Separate tested builds
with a corrupted startup answer returned `Quarantined` even with V.
Unit tests exercised length overflow, message retirement on interruption,
and clearing the packed weights on return and unwind. Both measured
ELFs contain the five widening multiplies and twenty widening
multiply-accumulates in the RVV column kernel. The native executable
SHA-256 digests, checked before and after timing, are:

- Rust 1.90.0: `122237f6cd62b88225d46d8d0775c5271045ce666c5cd54e3ca689ac9cd69e4a`
- Rust 1.100.0: `a5871b2934bf0211d2112015b10fe31f3173e641ada9ab1299af8ad4f8f5c81f`

The [candidate patch](../assurance/poly1305/rvv-integrated-candidate.patch)
is not in any shipped crate. To replay the correctness suite on a native
RV64 Linux system with usable V, from the repository root:

```sh
patchfile="$PWD/assurance/poly1305/rvv-integrated-candidate.patch"
replay=$(mktemp -d)
git archive 83642108 Cargo.toml Cargo.lock crates assurance/poly1305 | tar -x -C "$replay"
(
  cd "$replay" || exit 1
  git apply --unidiff-zero "$patchfile" || exit 1
  for v in 1.90.0 1.100.0; do
    cargo +"$v" test --locked --offline --release --manifest-path assurance/poly1305/Cargo.toml \
      --features rvv-owner --test rvv_vectors || exit 1
  done
)
```

Before exposing an opt-in standalone owner, review Linux vector-state
admission for the calling thread, package inclusion of the assembly, and
the CPU safety boundary. This benchmark did not test a paired AEAD.

### RV64 Linux: packaged standalone owner

Enable `poly1305-rvv` on `brynja-mac-poly1305`, then call
`rvv::Rvv::probe()` before passing the thread-local handle to
`OneTimeKey::start_rvv`. Admission requires both HWCAP V and an explicit
current-thread ON result from Linux's read-only vector-control query. Next-exec
settings do not grant permission now; unsupported or denied queries fail closed.
The library does not change policy or affinity. Linux does not permit a thread
with V enabled to turn it off before exec; ISA availability across scheduling
remains a platform requirement. See the [Linux vector ABI](https://docs.kernel.org/arch/riscv/vector.html).

On the Linux 6.6.63 X60, the final archive-built, dynamically linked executables
passed the 12 RFC cases, 65 generated streaming records, tampered tags and
caller-key clearing on both compiler endpoints. The same owner executables
returned `Unavailable` in a child with V disabled for its exec and under QEMU
with V absent. The default-feature import was rejected. The 77 instruction
encodings of the private column function matched the measured candidate
on both compilers. This is not a timing experiment on the final binaries.

| Rust | Packaged owner SHA-256 | Packaged vector-test SHA-256 |
| --- | --- | --- |
| 1.90.0 | `115daa922c825e6bf81d26f94bbba0f852464e1855e3d7084706a26117df80e3` | `b3cd8a712c49092aa2a53c481bdef2aaa4954234a0457a8d35439cbb3d5351a4` |
| 1.100.0 | `6bfdb974b6ffcc89758e4db353b0f27e3c0a6c70772ab84ecb2591f0eee5a874` | `cc588b188382f1f68dc830015d63dbdceb974b11242d4447acede5fe8ae43261` |

An earlier static GNU libc test binary did **not** refuse cleanly under the
native denied-exec control on Rust 1.90.0: the fault address was in glibc's
`__memcpy_vector`, outside the crate. The application and its runtime must
themselves be able to run under the configured ISA policy. The successful
native denial tests used the system's dynamically linked libc 2.41.

To reproduce, run `python3 scripts/cryptography/check-poly1305-packages.py
--rvv-export NEW_DIRECTORY` on the build host. Copy that directory and
`assurance/poly1305/tests/native_rvv_policy.py` to an RV64 Linux host with
usable V and run `python3 native_rvv_policy.py NEW_DIRECTORY`. The denial
control changes only a fresh child's next-exec setting. No root privileges,
sysctl changes, native timing reruns or registry publication are required.
