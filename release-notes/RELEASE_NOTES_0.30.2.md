# v0.30.2 — ChaCha20 installed public API acceptance (internal candidate)

No application migration is needed. The portable constructor remains portable,
including through the compatibility import. SIMD is selected by explicitly
importing an available leaf owner. No production cipher code or dependency was
added. The façade version change is metadata only.

On Rust 1.90.0 and 1.100.0, the [installed-consumer campaign](../assurance/chacha20-consumer/README.md)
tested both portable routes, native Linux x86-64 SSE2 and emulated Linux
AArch64 NEON. RISC-V still uses the portable public API. These results are not
new performance, timing or register-erasure evidence. No crates.io publication
is selected; the planned publication checkpoint remains v0.30.6.

The scoped gate checks the static CPU source hashes and the portable SHA-256
package and source policy without rebuilding hardware campaigns. The CPU
crate matches signed v0.30.1. The script inventory also verifies the digest
of its one permitted GHASH C diagnostic. The separate historical
`validate-release-metadata.sh` passes the CPU and SHA-256 checks, then stops
on the legacy-hash evidence pin for `crates/brynja-core/src/lib.rs`. This
milestone does not refresh or qualify that historical evidence.
