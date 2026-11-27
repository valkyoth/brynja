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

The scoped gate checks the static CPU source hashes without rebuilding the
hardware campaigns. The package matches signed v0.30.1. The script layout
inventory also passes. The separate historical `validate-release-metadata.sh`
now passes its static CPU check but still stops on the older SHA-256 façade
ownership policy. This is not a pass of that historical gate.
