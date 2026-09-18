# Scoped SHA-2 downstream probes

Six wrappers borrow caller-owned workspaces for SHA-224, SHA-256, SHA-384,
SHA-512, SHA-512/224 and SHA-512/256. Secret output is destroyed before return.
Tests exercise every public workspace and compare a SHA-256 known-answer digest.
No new external dependency or unsafe code is used.

The fixture's optional `general` feature adds a parameter-bound SHA-512/t wrapper
and checks all 510 parameters, typed secret output, canonical masking and exact
destination clearing. Use `--all-features` to include it.

Run `cargo test --locked --offline --manifest-path assurance/register-cleanup/in-place-sha2/Cargo.toml`.
The adjacent `check_in_place_sha2.py` tests the packaged first-party closure and
requires eight compiled mutations to fail at runtime in debug and release.
Mutations affect scope/handle/update cleanup, terminal-state handling, IV reset,
finalization, counter overflow and failed secret-output clearing. Production
sources are copied to a temporary directory, never mutated in the checkout.
Eight additional general-t mutants cover scope/handle/update cleanup, terminal
failure, parameter IV, output masking, secret identity and failed output clearing.

Emit MIR/LLVM/assembly from this fixture to inspect the borrowed-workspace ABI.
There may still be compiler-created copies within absorption/padding/output
operations. This fixture does not establish complete register/spill erasure or
native qualification. No release-gate command is added.
