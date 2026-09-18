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
cargo +1.98.1 clippy --locked --offline --manifest-path assurance/register-cleanup/caller-audit/Cargo.toml --all-targets -- -D warnings -A clippy::chunks_exact_to_as_chunks
```

The driver uses fresh build directories under ignored `target/caller-residue-*`,
records source hashes and compiler identities, and retains observations plus
MIR/LLVM/assembly for manual inspection. It rejects missing/duplicate records,
skipped controls, invalid counts and source changes during collection. It does
not automatically certify emitted-code cleanup. Arm execution is QEMU, not
native; no native Windows or Apple observation is made here.

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

## Remaining source boundaries

These are inspected source boundaries, not all dynamically tested by this
portable-only fixture. Paths below are relative to the repository root.

| Boundary | Representative sources | Remaining obligation |
| --- | --- | --- |
| Portable SHA-2 | `crates/brynja-hash-sha2/src/hardened/compress32.rs`, `compress64.rs` | Scalar schedule/round/feed-forward values still enter Rust registers and compiler temporaries. |
| Portable Keccak | `crates/brynja-hash-sha3/src/hardened/permutation.rs` | Scalar theta/rho/pi/chi/iota values remain outside opaque kernel boundaries. |
| Portable legacy | `crates/brynja-legacy-sha1/src/compress.rs`, `crates/brynja-legacy-md5/src/compress.rs` | MD5 now has baseline x86-64/Arm scalar-boundary development checks; its other-target model and SHA-1 rounds remain open. Tail framing/ownership is separate from compression. |
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
