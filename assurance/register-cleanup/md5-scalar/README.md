# Scalar MD5 register-cleanup development checks

This probe includes the actual private `compress/native.rs`. It is not a second
implementation or a complete high-level erasure qualification. From the repo root:

```sh
python3 assurance/register-cleanup/check_md5_scalar.py
```

The production path uses baseline integer instructions on x86-64 and
little-endian AArch64. It applies without Cargo CPU features to both ordinary
and hardened MD5 and to scalar batch tails. No SIMD/crypto ISA is required; no
backend admission, dispatch authority or public API changes. Other targets and
Miri/Kani retain the Rust model and its documented residue limits.

Fixed 16-byte state, 64-byte block and public constant/shift tables are the only
operands. All secret loads, rounds and feed-forward stay inside one opaque,
stack/call-free block. Seven volatile x86 registers and the public R14 counter,
or X4-X11 on Arm, clear before normal return. The compiler preserves incoming
callee-saved registers; those caller-owned values must not be destroyed.
The normal owner still clears its block and buffered count afterward.

The driver checks thirty compiler/target/profile configurations (Rust 1.90.0
and 1.98.1), plus eight actual crate builds. Linux x86 runs natively and Arm
runs under QEMU; Windows and Apple results are cross-compilation only. Every
runtime configuration checks 1,024 independent arbitrary state/block pairs,
32 unaligned placements, sixteen guard-page combinations with read-only inputs
and tables, and immediate-return register snapshots. The independent reference
uses RFC 1321 equations and the sine construction and is cross-checked against
the `abc` vector. Canaries bound the state, input and observer output.

Thirteen x86/fourteen Arm controls and mutants independently poison/remove each
volatile working-register wipe, alter the round count/rotation/message index,
or remove feed-forward. Positive poison-before-wipe controls must pass. Emitted
code mutations inject a pre-boundary load, a spill or a post-cleanup reload and
must fail. These checks do not instrument assembly with ASan; guard pages provide
the direct bounds checks that opaque assembly requires.

A local high-level release timing comparison against `80b1108d`, using five
alternating runs of 1,024 synthetic-input hashes, measured after/before median
ratios of 1.4065 (64 bytes), 1.0238 (1 KiB), and 0.9871 (16 KiB). Digest correctness
and secret-output Drop clearing were asserted. These host-local observations
show short-message overhead, not a performance guarantee.

F1 remains open: other scalar algorithms, other architectures, input/padding,
output copies, owner moves, caller registers and interruption snapshots are not
qualified by this boundary. MD5 remains collision-broken. No release workflow,
native approval, independent-review or FIPS claim changes here.
