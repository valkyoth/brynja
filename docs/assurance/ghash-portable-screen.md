# Portable GHASH: first host screen

Scope: one baseline x86-64 Linux build on each of Rust 1.90.0 and 1.100.0.
No accelerated backend, GCM tag, authentication, remote workload or physical
side-channel qualification. Treat the assembly check and the linked timing
experiment as **different artifacts**.

## Timing protocol (declared before measurement)

For each compiler run one optimized, fat-LTO, single-codegen-unit executable
on the lowest logical CPU in the process affinity mask. Use one launch;
run three campaigns in order: identical inputs (negative control), fixed vs
pseudorandom subkey, fixed vs pseudorandom block. Use public synthetic bytes,
common staging locations and alternating within-pair order. One timed batch
is 16 one-block updates plus finish/clear. For each campaign discard exactly
64 warmup pairs and retain all 2,048 remaining pairs without trimming.
Flag absolute paired t >= 4.5; nonzero constant differences also alarm.
Keep each raw sample log and binary hash, including alarms. No retry-to-pass.
The comparison is diagnostic, not a formal confidence bound or evidence of
independence across samples. It cannot rule out smaller timing differences,
other chunk shapes, other targets or compiler settings.

## Observations (2026-11-20)

One AMD Ryzen 9 9950X3D, Linux x86-64, logical CPU 0. Signed paired t values
below are for fixed minus comparison, on the entire batch.

| Rust | Identical control | Vary subkey | Vary block |
| --- | ---: | ---: | ---: |
| 1.90.0 | +0.27 | −1.13 | −1.25 |
| 1.100.0 | −1.40 | +0.77 | −0.70 |

None crossed the declared threshold. The [raw pairs and summaries](../../assurance/ghash-observations/first-x86_64/)
preserve the binary hashes and actual compiler identities. They describe the
working tree based on `e6c5c05f`, not the unmodified commit. At collection,
the SHA-256 of the harness source was
`a5c627124014eea62eccb729267df6491be06a7492887f3c6ef36f3c6b9701e8`;
the GHASH owner and field source hashes were respectively
`95507a0f9c026289c2ba56b9c85e13e3a48b18070ca8b6af84a5e57c0d581d61`
and `9dac5151c83b3b858ec804c64e771dadfec33ba5470eaedb5f876e51c5864823`.
Common staging is a source-level control, not a linked-code placement guarantee.

## Emitted code

Separately built the actual `brynja-crypto` library with default features off
and its repository release profile; emitted MIR, optimized LLVM IR and assembly.
The GF multiply is inlined into `Ghash::update`. Both LLVM outputs select data
using field bits, while the inner loop branch uses its iteration count. On
both x86-64 compilers the resulting loop uses register shifts, masks and XOR;
there is no memory operand, call, or data-dependent branch in that loop. Its
only conditional jump follows decrement of a counter initialized to 128.
Outside the loop, input traversal and budget checks branch on public length,
offset and position. Subkey and accumulator loads use fixed offsets, not
field values. The checker fingerprints the whole reviewed update assembly body
and requires fresh review if it changes. This does not inspect a downstream
application's final-linked code, establish spill erasure, or qualify CPUs.

## Reproduction

The post-review cross-target check separately compiles the opt-in production
library on Rust 1.90.0 and 1.100.0 and fingerprints the complete inlined
`Ghash::update` body separately for each compiler and target. Inside the multiply loop the only conditional jump
is the back edge on the public 128-round counter: Cortex-M decrements with
`subs` and branches with `bne`; RV32 uses `addi` and `bnez`; Android AArch64
uses `subs` and `b.ne`. Data selection uses masks, not indexed tables.
Cortex-M and RV32 also spill intermediate words to fixed stack offsets; the caller's
workspace cleanup does **not** erase those slots. No native measurements,
final-linked review, or memory-disclosure resistance are claimed on these
targets. The original x86 timing records were not recollected.

- `python3 scripts/ghash/check-portable-host.py codegen`: rebuild both library artifacts.
- `python3 scripts/ghash/check-portable-host.py cross-codegen`: compare the reviewed
  six bodies for `thumbv7em-none-eabi`, `riscv32imac-unknown-none-elf`
  and `aarch64-linux-android` (install all three targets on both toolchains).
- `python3 scripts/ghash/test-portable-host.py`: verify and re-analyze the
  retained samples and exercise checker controls; does not remeasure.
- `python3 scripts/ghash/check-portable-host.py timing --output NEW_DIRECTORY`:
  collect a **new** observation, without overwriting an existing one. An alarm
  returns nonzero after preserving both compiler records.
