# v0.29.2 — Packaged portable AES-GCM and GMAC (candidate)

This internal milestone tests the APIs shipped in the Cargo archives. It
introduces no new encryption algorithm, public API or acceleration. No crates
are selected for publication.

Run `python3 scripts/aes-gcm/check-portable-acceptance.py` from the checkout,
or use `brynja-verify run gmac packaged-portable-acceptance` to record the
result. Both commands exercise direct and facade imports on Rust 1.90.0 and
1.100.0. The [frozen example and inputs](../assurance/aead-portable-acceptance/README.md)
cover public known answers, error handling, tag separation and caller-visible
cleanup. The full replay also compares 11,025 AES-GCM messages in two buffer
layouts and 2,730 GMAC messages per compiler and import route against Go.
CI uses a shorter smoke run that omits the Go comparison.

Separate source checks on this candidate passed the pinned 6,750-case GMAC
NIST replay, both bounded Kani transaction proofs, the failed-import cleanup
test under Miri, and the five GMAC integration tests under x86-64 Linux
AddressSanitizer. These observations do not turn the shipped archive into
a formally verified binary.

Cortex-M is compile-only. This is portable functional evidence, not timing
qualification, physical erasure or certification. Accelerated integration is
a separate milestone. The signed tag and review disposition are separate
release steps.
