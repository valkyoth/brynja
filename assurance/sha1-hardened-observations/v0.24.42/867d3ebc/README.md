# Refreshed hardened SHA-1 observations

Capture source: `867d3ebcbe81dcba37cbf60cd307416d0e6144d9`, Rust 1.98.1.
Apple M2 Pro, local AMD, AWS Intel and AWS Arm artifacts have passed source, compiler, route,
transcript and checksum validation. Their original JSON bytes are retained here,
outside Cargo's removable build directory.

All four include 512 actual hardened kernel comparisons, 1,135 packaged oracle
messages, 24 ownership/query rejection checks, ten algorithm/error mutants,
ten compiled cleanup removals and native-target MIR/LLVM/assembly checks.

The initial Intel and AWS Arm downloads were lost with the local `target/`
directory before archival. Both captures were rerun on owner-provided native
hosts at the same commit. Their new outputs were retrieved directly into this
archive and checked byte-for-byte against the remote SHA-256 checksums before
committing. No recorded result was reconstructed from remembered PASS output.
The native index now accepts the complete four-lane correctness evidence with
explicit residual limits.
Historical parent-directory artifacts have different source bindings and are
not replacements.

These are self-attested native correctness observations, not independent
verification, FIPS validation, timing/migration proof or register erasure.
