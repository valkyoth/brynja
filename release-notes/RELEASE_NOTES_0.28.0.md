# v0.28.0 candidate — portable GHASH

This internal milestone follows tagged v0.27.6. The unfinished v0.27.7 AES
fault-integrity experiment remains research only. No crates.io upload is
selected and this record is not release approval.

Enable `hazmat-ghash` explicitly on the chosen crate to use
`brynja_crypto::ghash::Ghash` (also `brynja::crypto::ghash::Ghash`). It accepts
bounded byte chunks of pre-framed data. Finishing requires whole blocks and
returns a clearing owner for the raw secret intermediate. The caller retains
responsibility for the borrowed key. This is neither a standalone MAC nor GCM.

The [GHASH verification record](../docs/VERIFICATION_STATUS.md#portable-ghash-v0280-development)
describes the known-answer and differential tests, live-buffer cleanup checks,
and the limits of the x86-64 host screen. These records do not qualify other
targets, hardware acceleration, or physical side channels. Portable downstream
package acceptance remains v0.28.1 work.

The facade advances to 0.28.0; supporting crates keep their internal versions.
Rust 1.90.0 remains the MSRV, with 1.100.0 at the current endpoint.
The isolated sanitization adapter moves to 2.2.0; GHASH does not use it.
The ordinary finite local checks and exact-commit GitHub/CodeQL policy still
apply. A working-tree preflight is not the final gate: that gate requires a
clean committed candidate and a commit-bound passing pentest/retest record.
No historical timing, sanitizer or proof campaign is a tag prerequisite.

The [review disposition](../docs/assurance/ghash-review-disposition.md)
distinguishes the fixes from retained limits; a scoped retest remains pending.

## Working-tree preflight (2026-11-20)

All 30 commands in the scoped checklist passed, including targeted reruns
after correcting the AES compiler-probe artifact discovery and GHASH
registry assertions. The registry suite passed 1,089 tests. The SBOM graph,
dependency policy and advisory scan passed. These results are not a signed
candidate, an independent review or a GitHub result.

Separately, the manually dispatched historical metadata check still rejects
the two AES feature declarations in the CPU manifest. Both declarations and
the older whitelist were already present at v0.27.6. That check is not in the
30-command checklist; its historical evidence was not refreshed here.
