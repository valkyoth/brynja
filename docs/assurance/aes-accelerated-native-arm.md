# Native AWS ARM linked-code replay

This v0.27.3 development observation replays the existing bounded ARM
instruction/byte policies against freshly linked consumers executed directly
on an AWS Neoverse-V2 host. The target is explicitly
`aarch64-unknown-linux-musl`, not the host's usual GNU target. It complements
the earlier native GNU-target correctness campaigns; it does not qualify GNU
linked binaries, Apple Mach-O binaries, or arbitrary application builds.

## Configuration and results

Rust 1.90.0 and 1.99.1 each cover direct/facade consumers, abort/unwind panic
strategies and static/hosted admission. Builds use opt-level 3, fat LTO, one
codegen unit, overflow checks and byte-checked Cargo archives. Static consumers
use `+aes,+neon`; hosted consumers use `-aes` with NEON as a target baseline.
A baseline-compiled native probe must establish the AES bundle before static
execution. The inspection tools come from the Rust 1.99.1 LLVM tools component;
the recorded tools and retained executables are hashed before and after review.

All 16 linked-operation consumers executed their exact known-answer, clearing
and quarantine population and passed the unchanged policies for:

- AES-128/192/256 hardware expansion and both round directions;
- six raw/cached constructors, copy, volatile clearing and retained destruction;
- cached and per-operation public/secret callers and their admitted call edges;
- session direction, health and generation checks.

All 16 separate startup consumers also passed unchanged startup policies and
native known-answer execution. Every consumer then executed 628 single-byte
known-answer corruptions and required terminal quarantine: 10,048 native
corrupted-binary executions in total. The eight hosted consumers additionally
rejected both warm-cache and cold-detector simulated missing-AES observations,
for 16 controls. These are deliberately altered software observations, not
physical fault experiments or observations of an AES-less processor.

The existing policy explanations remain in the
[per-operation review](aes-accelerated-linked-arm-ephemeral.md),
[static startup review](aes-accelerated-startup.md) and
[hosted startup review](aes-accelerated-hosted-startup.md). Their earlier QEMU
observations are not relabeled native: this document records separate native
builds and executions. No instruction policy was loosened or regenerated for
this replay, and no production Rust changed.

## Reproduction and retained observations

On a Linux AArch64 host with both pinned toolchains, their musl target libraries,
`rust-lld`, `llvm-nm` and `llvm-objdump` available, run each compiler and admission
combination explicitly:

```sh
python3 scripts/aes/check-aes-accelerated-linked.py --toolchain 1.90.0 --mode arm-native --admission static --review-arm-ephemeral
python3 scripts/aes/check-aes-accelerated-startup.py --toolchain 1.90.0 --mode arm-native --admission static
```

Repeat with `--admission hosted` and `--toolchain 1.99.1` for the other declared
configurations. `arm-native` refuses x86 and macOS hosts. The linked runner's
existing `native` mode remains Linux x86; startup's default remains `arm-qemu`.
Native reports record direct executable invocation with no QEMU prefix, and
their completion markers explicitly name native AArch64 musl consumers.
Capture-only runs still cannot emit review-success markers.

The compact record is
[`aws-arm-linked-20261110.json`](../../assurance/aes-native-observations/v0.27.3/aws-arm-linked-20261110.json).
It binds the ordered source bundles, host context, all 32 executable hashes,
per-consumer review hashes and retained logs. Full artifacts are retained in
`target/aes-native-aws-arm-linked-20261110/observations.tar.gz`, SHA-256
`e7f56db8495b05e5d115730751c2a9d42f1496c97489838affcc918f6046ef92`.
The remote scratch checkout is also retained. Retrieved source bundles are
compared with the working tree, and pure instruction/byte reviews are replayed
locally against the retrieved ELF files and inspection output. Mutation totals
include repeated dependency reviews, not counts of distinct vulnerabilities.

Regression coverage rejects wrong-host/mode combinations, x86-review flags on
native ARM, capture/review combinations, and missing or extra native probe
markers. All 784 tooling/registry tests passed. Fresh registered local checks
also passed for both native x86 kernel configurations, all four QEMU ARM
per-operation configurations and all four QEMU static/hosted startup
configurations. Existing QEMU success markers remain unchanged.

## Boundaries

This is unauthenticated development evidence from an uncommitted working tree
based on v0.27.2, not a clean-tag certification record or an imported current-pass
receipt. Only the named retained bodies and bound call boundaries are covered:
not arbitrary downstream inlining, every call site, exception-table dispatch,
unwinder/OS qualification, or complete register/spill erasure. The Rust detector
and Linux capability report remain trusted for hosted admission.

No timing measurements were collected; correctness work could overlap.
This does not establish timing/power/EM resistance or physical fault protection.
Other native platforms, separately declared timing/performance experiments and
the remaining release work stay open. No HSM requirement or publication gate
was added.
