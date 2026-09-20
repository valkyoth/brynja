# Portable/caller residue audit

Development diagnostics, **not release evidence or an erasure acceptance gate**.
No production API, backend selection, or release workflow is changed by this
fixture. F1 remains open. The sixteen opaque accelerated kernels do not cover
the portable implementations or all code surrounding an accelerated call.

## What executes

Five `inline(never)` C-ABI wrappers invoke the real default-feature-disabled
public `HardenedSha256`, `HardenedSha512`, `HardenedSha3_256`, `HardenedSha1` and
`HardenedMd5` streaming APIs. Each finalizes into a borrowed secret destination,
drops the output owner, and returns only a status. They do not expose the digest.
Separate known-answer tests check the five `abc` digests before output drop.

The optional fixture-only `scoped` feature selects five corresponding borrowed
workspace wrappers. Each constructs secret-free local storage before `with`,
updates/finalizes through the borrowed handle, drops the output, and lets the
scope clear before returning. The input/output/status ABI and observer are
unchanged. Construction is inside the observed wrapper; this is not a probe of
an arbitrary external caller's existing workspace or registers. Known-answer
tests use the selected API profile, not always the old movable implementation.

Linux observers seed caller-clobbered registers before the call and snapshot
them immediately on return, before Rust can overwrite them. Arguments are only
live buffer addresses and public lengths. The snapshot includes nine integer
registers and XMM0–15 on x86-64; X0–17 and V0–7/V16–31 on AArch64. It does not
read uninitialized/dead stack memory, touch Arm's reserved X18, or alter
callee-preserved registers. Deliberately retaining and clearing controls test
the observer, and a classifier test checks the eight-byte marker threshold.
Prefix/suffix canaries check snapshot bounds. The two safe public-call tests
also pass focused Miri; that run does not exercise the assembly observer.

Only repeated **synthetic public test bytes** are used. Fourteen public lengths
from 0 through 256 exercise padding and block boundaries, with two markers:
28 cases per algorithm per configuration. Input and unowned output suffixes
must remain unchanged; every owned destination must clear. Logs contain counts,
not raw register bytes, pointers, inputs, or digests.

An input-marker match demonstrates residue across **this wrapper plus the public
API**. It does not isolate a specific private kernel or instruction. No match
does **not** establish erasure: this narrow recognizer cannot identify arbitrary
digest/schedule values, transformed input, partial bytes, upper vector lanes,
stack spills, or residue on other paths. All records say
`qualifies_register_cleanup: false`, even when every test passes.

## Reproduce

From the repository root, with both endpoint compilers and QEMU installed:

```sh
python3 assurance/register-cleanup/test_callers.py
python3 assurance/register-cleanup/check_callers.py --arm --emit
python3 assurance/register-cleanup/check_callers.py --scoped --arm --emit
cargo +1.98.1 clippy --locked --offline --manifest-path assurance/register-cleanup/caller-audit/Cargo.toml --all-targets -- -D warnings -A clippy::chunks_exact_to_as_chunks
```

The driver uses fresh build directories under ignored `target/caller-residue-*`,
records source hashes and compiler identities, and retains observations plus
MIR/LLVM/assembly for manual inspection. It rejects missing/duplicate records,
skipped controls, invalid counts and source changes during collection. It does
not automatically certify emitted-code cleanup. Arm execution is QEMU, not
native; no native Windows or Apple observation is made here.

Each run records `api_profile` and requires exactly one matching runtime marker.
Missing, duplicated or substituted profile markers fail; a movable run cannot
be presented as a scoped observation. The fixture feature is passed only to
the fixture, not to separately compiled dependencies. Nine collector regressions
cover this selection, observation bounds, missing controls and build overrides.

## Initial observations

On the sources following `0d356c11`, these numbers count cases with at least one
eight-byte repeated-input match, out of 28 per column. They are diagnostic
observations, not stable expected test results or security scores.

| Compiler / execution / profile | SHA-256 | SHA-512 | SHA3-256 | SHA-1 | MD5 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1.90.0 / native Linux x86-64 / debug | 0 | 0 | 0 | 0 | 14 |
| 1.90.0 / native Linux x86-64 / release | 6 | 0 | 10 | 6 | 0 |
| 1.98.1 / native Linux x86-64 / debug | 0 | 0 | 0 | 0 | 14 |
| 1.98.1 / native Linux x86-64 / release | 6 | 0 | 0 | 6 | 0 |
| 1.90.0 / QEMU Linux Arm / debug | 0 | 0 | 12 | 0 | 0 |
| 1.90.0 / QEMU Linux Arm / release | 0 | 0 | 0 | 8 | 0 |
| 1.98.1 / QEMU Linux Arm / debug | 0 | 0 | 12 | 0 | 0 |
| 1.98.1 / QEMU Linux Arm / release | 0 | 0 | 10 | 6 | 0 |

All functional/owned-destination checks pass in these configurations. The
positive residue observations prevent interpreting that result as complete
normal-return cleanup. The zeros, including SHA-512, leave their audit work open.

## Recheck after the private kernel and secret-copy ports

The same unmodified diagnostic was rerun at
`f76c57af564fcbcba89fa3e63bd8de30d4cb0432`. All eight compiler/target/profile
configurations pass their five functional/observer tests. They still do **not**
qualify whole-API erasure. Observed repeated-input matches out of 28 cases:

| Compiler / execution / profile | SHA-256 | SHA-512 | SHA3-256 | SHA-1 | MD5 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1.90.0 / native Linux x86-64 / debug | 0 | 0 | 0 | 0 | 14 |
| 1.90.0 / native Linux x86-64 / release | 24 | 0 | 10 | 0 | 0 |
| 1.90.0 / QEMU Linux Arm / debug | 0 | 8 | 12 | 0 | 0 |
| 1.90.0 / QEMU Linux Arm / release | 14 | 16 | 22 | 0 | 14 |
| 1.98.1 / native Linux x86-64 / debug | 0 | 0 | 0 | 0 | 14 |
| 1.98.1 / native Linux x86-64 / release | 24 | 0 | 10 | 0 | 14 |
| 1.98.1 / QEMU Linux Arm / debug | 0 | 8 | 12 | 0 | 0 |
| 1.98.1 / QEMU Linux Arm / release | 14 | 16 | 22 | 0 | 14 |

These are compiler-sensitive diagnostics, not a score or a quantitative
comparison of security. Changes in register allocation and wrapper code can
change the marker count without changing the private kernel's cleanup contract.
No match can establish absence of transformed secrets or stack copies.

The current Rust 1.98.1 x86-64 release SHA3 wrapper still performs a 1,040-byte
`memcpy` from `rsp + 1080` to `rsp + 32` after `update` succeeds, then passes
the latter address to consuming `finalize_secret`. Its successful return path
does not wipe the former region before reclaiming the stack frame. This is an
inspection of emitted code, not a read of dead stack memory. The separately
qualified permutation and destination-copy boundaries do not cover this move.

Local source-bound observations are retained under
`target/caller-residue-ql5q_sap/observations.json` with SHA-256
`0ee7f16b727500fb07d8fd5770266fab933e2d96bbf1261e739961e66ef7260b`.
The inspected `brynja_caller_residue_audit` 1.98.1 x86-64 release assembly has
SHA-256 `09909ab5878e36cd69038dca0aebb84dcb94a0cc6ede1b6a4c79b8edb0071483`.
These ignored development artifacts are not a release receipt or native approval.

### Historical ownership-design decision before expanding the public API

Keeping secret state inline in a freely movable Rust value prevents promising
that all previous locations are erased: a semantic move may copy bytes without
notifying that value. A private finalizer cannot recover an arbitrary prior
caller address. This matches Rust's documented
[move and pinning model](https://doc.rust-lang.org/std/pin/index.html#what-is-moving).

The proposed next design is an additive, caller-owned in-place hardened API:
initialize secret state only in its final storage, retain exclusive access for
its active lifetime, finalize there, and clear before releasing storage. The
existing by-value API would remain available with its existing owned-memory
guarantee, not silently acquire a stronger guarantee. This needs owner approval
because it expands the public API beyond private backend remediation.

An in-place lifetime alone is not register or spill erasure. Absorb/padding/
squeeze and higher-construction transfers still need qualified opaque paths,
error/unwind and ownership tests, emitted-code review and platform coverage.
Pinning alone does not suppress compiler temporaries; no such claim is made.
Do not close F1 or collect final native qualification on this diagnostic result.

The owner subsequently approved the additive scoped APIs. They are implemented;
the following recheck observes five of them. The historical proposal above is
not a new approval request or a claim that those five APIs remain unimplemented.

## Scoped versus movable recheck, 2026-09-20

Production sources are those at `daa8e33b`; this checkpoint changes the
development fixture/collector, not production Rust. Each profile runs 28 cases
per algorithm on both compiler endpoints, both Linux architectures and both
debug/release profiles (1,120 observations per API profile).

All five scoped algorithms have **zero repeated-input marker matches** in all
eight configurations. All functional checks, owned-output clearing and observer
controls pass. This narrow result does not prove removal of transformed secrets,
partial bytes, stack spills, upper vector lanes or interruption snapshots.

The movable recheck has zero matches for SHA-256, SHA-512, SHA3-256 and SHA-1.
MD5 still has 14/28 matches in x86 debug under both compilers, x86 release under
1.98.1, and Arm release under both compilers; its other configurations have zero.
These observations are not comparative security scores. The old movable API
retains its owned-memory guarantee, not a whole-register claim.

Inspection of the 1.98.1 x86 release scoped SHA3 wrapper finds its 1,032-byte
`memcpy` during secret-free initialization, **before** `update`. Unlike the
earlier movable wrapper, no bulk populated-owner copy occurs between `update`
and `finalize_secret` in this wrapper. This specific observation is not a proof
covering callees, all error paths, other compilers or other algorithms.

Ignored, source-bound records:

- `target/caller-residue-heo5fer6/observations.json` (scoped), SHA-256
  `01b618abca82e5da85d870876a19b7a3551fa8b09aeed74fab9d41aa0cdb5141`.
- `target/caller-residue-83c83esq/observations.json` (movable), SHA-256
  `7e7e7164e77bd94476372346aa5b0cd4f3dfd3d2ea96e21e979f4d31e5ddf454`.
- Scoped 1.98.1 x86 release fixture assembly, SHA-256
  `4bfedc0cc1f909f64fd880f415d52658c4ceef6f43217b7f99a4c97cd50e673f`.

The scoped fixture also passes strict Clippy and ASan/LSan with leak detection
and fatal error exits forced. These are development checks, not release receipts
or native approvals. No release-gate commands or behavior changed.

## Remaining source boundaries

These are inspected source boundaries, not all dynamically tested by this
portable-only fixture. Paths below are relative to the repository root.

| Boundary | Representative sources | Remaining obligation |
| --- | --- | --- |
| Portable SHA-2 | `crates/brynja-hash-sha2/src/hardened/compress32.rs`, `compress64.rs` | Both hardened SHA-224/256 and the SHA-512 family now have baseline x86-64/Arm scalar-boundary development checks. Other-target models still expose scalar round temporaries; higher-level owner copies remain separate. |
| Portable Keccak | `crates/brynja-hash-sha3/src/hardened/permutation.rs` | Baseline x86-64/Arm scalar permutation now has source-bound development checks. Other-target models, caller absorb/squeeze and moved-owner copies remain open. |
| Portable legacy | `crates/brynja-legacy-sha1/src/compress.rs`, `crates/brynja-legacy-md5/src/compress.rs` | SHA-1 and MD5 now have baseline x86-64/Arm scalar-boundary development checks; their other-target models remain open. Tail framing/ownership is separate from compression. |
| Single accelerated Keccak | `crates/brynja-crypto-cpu/src/hardened_execution/keccak.rs`, `crates/brynja-hash-sha3/src/hardened/accelerated/engine.rs` | Session import/commit now stays inside the opaque kernel. Higher-level absorption, padding and squeeze remain to be addressed. |
| Batch staging | SHA-2 `src/hardened_batch/engine.rs`, `src/hardened_batch512/engine.rs`; SHA-3 `src/hardened_batch/engine.rs`; MD5 `src/batch/hardened_execution/vector.rs` | Packing, feed-forward/output transfer, portable tails and partial lanes require their own review. |
| Ownership and finalization | Primitive hardened owners, consuming finalizers, core secret-region output initialization | Moving a by-value Rust owner may create compiler copies; clearing its final owned region is not proof that earlier copies or registers clear. |
| Higher constructions | KMAC, TupleHash, ParallelHash framing/readers and threaded output transfer | Inherit the primitive limitations and add framing/transfer paths; not covered by these five probes. |

The remediation must keep secret loads/transformations within qualified
boundaries and address caller staging explicitly. A late `vzeroall`, an ordinary
slice fill, or a wrapper around only compression cannot establish that property:
the compiler can spill or copy values before it, or load them again afterward.
Preserved caller registers and caller-owned buffers must remain valid. Any
portable replacement must retain targets without crypto/SIMD instructions,
existing feature defaults, quarantine/error behavior and public APIs. Kernel
normal-return cleanup still cannot erase asynchronous snapshots or platform
storage. Do not start final native qualification or close F1 on these diagnostics.

Emitted release code also makes the ownership-copy issue concrete: the 1.98.1
x86 SHA3 wrapper copies its 1,040-byte state to a separate stack region for the
consuming finalizer. Clearing that finalizer's owner is not erasure of the old
location. This was observed in emitted code, not by reading dead stack storage;
the runtime observer does not measure stack residue. Moving secret-bearing Rust
values and preserving existing by-value APIs therefore need separate treatment
from the private compression/permutation kernel ports.
