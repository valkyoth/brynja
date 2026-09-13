# Refreshed hardened SHA-1 observations

Capture source: `867d3ebcbe81dcba37cbf60cd307416d0e6144d9`, Rust 1.98.1.
Apple M2 Pro and local AMD artifacts have passed source, compiler, route,
transcript and checksum validation. Their original JSON bytes are retained here,
outside Cargo's removable build directory.

Both include 512 actual hardened kernel comparisons, 1,135 packaged oracle
messages, 24 ownership/query rejection checks, ten algorithm/error mutants,
ten compiled cleanup removals and native-target MIR/LLVM/assembly checks.

The Intel and AWS Arm runs passed, but their downloaded JSON files were lost
with the local `target/` directory before archival. Checksums and remembered
PASS results cannot substitute for those artifacts. The index remains pending
until their original files are recovered or matching native captures rerun.
Historical parent-directory artifacts have different source bindings and are
not replacements.

These are self-attested native correctness observations, not independent
verification, FIPS validation, timing/migration proof or register erasure.
