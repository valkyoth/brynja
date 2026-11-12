# Integrated AES expansion: native performance observations

Four observations were collected on 2026-11-10 under the policy declared in
[the performance diagnostic](aes-accelerated-performance.md), in the declared
order: AWS Neoverse-V2 Rust 1.90.0/1.99.1, then local AMD Ryzen 9 9950X3D Rust
1.90.0/1.99.1. Each observation had one measurement invocation. All 1,728
samples are retained, without a speed threshold, cropping or retries.

These new observations include the integrated hardware-assisted expansion.
The earlier portable-expansion observations remain historical baselines and
were neither overwritten nor reclassified. No production Rust changed here.

## What the samples show

The table gives median nanoseconds per operation from batches of 64, rounded
to one decimal. Each triple is AES-128 / AES-192 / AES-256. These are secret
encryption API calls including output observation and clearing, not isolated
round instructions or multi-block throughput.

| Host | Rust | Accelerated raw-key encryption (ns) | Accelerated cached-key encryption (ns) |
| --- | --- | --- | --- |
| Neoverse-V2 | 1.90.0 | 205.5 / 222.7 / 260.1 | 29.3 / 30.1 / 33.0 |
| Neoverse-V2 | 1.99.1 | 206.0 / 218.0 / 263.7 | 30.3 / 30.0 / 32.5 |
| Ryzen 9 9950X3D | 1.90.0 | 59.2 / 59.2 / 74.2 | 11.8 / 12.5 / 13.3 |
| Ryzen 9 9950X3D | 1.99.1 | 60.0 / 60.1 / 74.8 | 11.9 / 12.7 / 13.2 |

The raw-key operation expands and clears a temporary schedule for each block.
The cached operation excludes schedule construction and destruction from its
timer, so the two columns deliberately measure different ownership tradeoffs.
All widths, both owners, encryption, decryption, public encryption and
construction/clearing remain in the full paired summaries; the table is only
the secret-encryption subset.

Hardware-backed block operations and cached-schedule construction were faster
than their paired portable implementations in these observations. Raw-key
construction/clearing was slower through the accelerated API in every measured
configuration. Raw-key construction does not expand a schedule and the
accelerated owner also validates authority. Do not conceal this cost or infer
that every accelerated API operation is faster. Schedule construction,
per-operation expansion and cached block operations are separate quantities.

## Validation and retention

Before measurement, both API routes and both compiler endpoints passed their
correctness-only fixture on each host: eight configurations, each with four
Rust harness tests and 48 known-answer/clearing cases. Each observation also
repeated its own fixture tests and exact-binary correctness preflight. All 786
local tooling/registry tests passed, including architecture-specific marker,
sample-retention, timeout, affinity-restoration and no-retry controls.

The compact observation record is
[`integrated-performance-20261110.json`](../../assurance/aes-native-observations/v0.27.3/integrated-performance-20261110.json).
It records all 96 paired median comparisons, four retained executable identities,
compiler/target/flags/profile identities, source/package hashes, host context,
and raw-output/summary hashes. Raw outputs were parsed again locally; all 48
case summaries per observation matched the saved summaries exactly. Every
retained executable hash was rechecked, and AWS source-bundle contents were
compared with the local working tree.

AWS artifacts are retained under
`target/aes-native-performance-20261110/aws/`, with their archive at
`target/aes-native-performance-20261110/aws-observations.tar.gz`, SHA-256
`94e0a803b607e3179c80bb385cd1a630e80bee6d0c4a40661e2721bfb095b8d9`.
The remote scratch checkout remains retained. AMD observations remain in
`target/aes-performance/amd-integrated-msrv-20261110/` and
`target/aes-performance/amd-integrated-current-20261110/`.

An initial remote Python regression invocation failed because the transferred
bundle omitted `verification/checks.toml`. This happened before fixture builds
or measurement. Its diagnostic remains in `logs/tooling.log`; after supplying
the hashed registry bundle, all 13 performance-tool tests passed in
`logs/tooling-attempt2.log`. No observation was discarded or retried.

## Limits

Both hosts used logical CPU 0. AWS reported no governor/boost information and
no SMT sibling; AMD reported powersave, enabled boost and sibling 16. Neither
host was isolated or held at a controlled frequency. Virtualization, host load,
scheduling, cache state, timer overhead and compiler specialization remain
limitations. The two hosts are not a controlled cross-machine comparison.

The direct static API, GNU host target and opt3/fat-LTO/cgu1/overflow/unwind
profile are the measured scope. Hosted admission overhead, other profiles,
Apple/Intel hardware and multi-block scaling are not measured. These are
unauthenticated working-tree diagnostics, not clean-tag certification or
performance guarantees. There is no speed pass/fail verdict.

The accelerated fixed-versus-random side-channel experiment remains separate
and unfinished. These performance samples do not establish constant-time,
power/EM or physical fault resistance. No publication gate was added.
