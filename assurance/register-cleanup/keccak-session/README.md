# Keccak session transfer regression probe

Development-only, not release qualification. This fixture calls the real public
`KeccakSession::permute` with pointers, then immediately snapshots selected
volatile vector registers using an ABI-correct assembly call site. It tests the
session layer around the opaque kernel, not SHA-3 framing or whole-process
erasure. Release gates are unchanged.

For each of 128 synthetic states it checks the result against the ordinary
permutation and checks exact return-vector contents. X86 observes XMM0–15;
Arm observes V0–7 and V16–31. Registers are seeded before the call. On Arm debug
builds, V0 may contain the public constant 1: Rust's byte `write_volatile`
alignment precondition computes `popcount(align_of::<u8>())` using
`FMOV/CNT/UADDLV`. Every other observed byte must be zero. This was traced in
Rust 1.90 emitted assembly; unmatched values are never assumed non-secret.
The exact allowlist rejects every other single-bit value and wrong widths.

Two executed controls deliberately leave an all-ones marker or reload the
actual output's first sixteen bytes after the public call. Both must be observed
and rejected. Snapshot canaries and quarantine/state-preservation checks are
included. No register bytes, pointers or digests are logged.

Rust 1.90.0 and 1.98.1, debug/release, pass on native Linux x86-64 and QEMU Arm.
For example (repeat with `+1.90.0` and `--release`):

```sh
RUSTFLAGS='-C target-feature=+avx2' cargo +1.98.1 test --locked --offline --manifest-path assurance/register-cleanup/keccak-session/Cargo.toml --test session -- --nocapture
RUSTFLAGS='-C linker=rust-lld -C target-feature=+neon,+sha2,+sha3' CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER='qemu-aarch64 -cpu max' cargo +1.98.1 test --locked --offline --manifest-path assurance/register-cleanup/keccak-session/Cargo.toml --target aarch64-unknown-linux-musl --test session -- --nocapture
```

Use a known AVX2-capable native host for the first command. Generic builds skip
the hardware probe and do not count as evidence. QEMU is not native Arm evidence.
These observations do not cover general registers, upper x86 vector lanes,
callee-saved vectors, stack spills, pre-existing caller copies, interruption,
other platforms or compiler configurations. The separate raw-kernel fixture
checks all kernel working registers and emitted spill-free boundaries. Portable
hashing, absorb/squeeze and movable-owner cleanup remain open under F1.
