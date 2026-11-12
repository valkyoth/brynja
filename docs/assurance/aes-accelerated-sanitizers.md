# Packaged accelerated AES sanitizer coverage

This v0.27.3 development check executes static x86 AES-NI through byte-checked
Cargo archives, separately through `brynja-crypto` and the `brynja` facade.
It uses `nightly-2026-09-11`, explicit `x86_64-unknown-linux-gnu`, AES/SSE2
specialization, and debug/release profiles with overflow checks in release.
A baseline feature probe runs before any specialized executable is entered.
The host must keep the admitted ISA available for the complete run.

The archive's integration test is reused unchanged for the direct route; only
its two API import paths change for the facade route. The test also imports
the CPU crate's typed error. All dependencies resolve to the checked archives,
and the existing accelerated graph validator checks the exact active package
and feature populations. No hosted or portable fallback route is admitted.

Each profile requires exactly 13 named passing tests, no ignored or filtered
tests and exactly three NIST completion markers: 568 AES-128, 700 AES-192 and
810 AES-256 cases. Both operation-local and cached schedules, encryption and
decryption, explicit secret-output/key clearing, quarantined secret/public
destinations, constructor rejection and caller-unwind Drop cleanup are covered.
These tests do not inject faults into the hardware round instructions.

## Active sanitizer controls

ASan is enabled for the consumer and its Rust dependencies using
`-Zsanitizer=address`; leak detection and fatal errors are forced. The installed
standard library is not rebuilt with instrumentation. Each profile first builds
a test-only control binary with the same target, dependency selection and
environment. It must diagnose both a deliberate one-byte heap overread and a
deliberate 64-byte leak, each with exit code 23. The leak is allocated on a
completed worker thread to avoid retaining its pointer on a live caller stack.
Both runtime exit-code options are set to the same value because their common
setting must not conflict. Neither a crash, arbitrary nonzero exit nor a missing
diagnostic satisfies these controls. Failed controls stop before the AES tests.

The deliberately invalid unsafe code exists only in
`assurance/aes-accelerated-campaigns/sanitizer-control.rs`, outside the production
crates and their package contents. Its expected errors are retained and labeled
as controls, not AES findings. A sanitizer diagnostic in the actual AES tests
always fails the run. Logs, command exit codes, compiler identity and dependency
metadata are retained beneath `target/aes-accelerated-sanitizers`.

Ambient Rust overrides, sanitizer settings and loader hooks are rejected, and
builds use the existing isolated Cargo environment. Registry tests cover exact
test populations, diagnostics, wrong control exits, environment rejection,
archive-only imports, profile commands and early termination without a success
marker.

```sh
brynja-verify run aes --needed --category aes-accelerated-sanitizers
```

Two registrations cover four profile/route combinations, 52 passing test
executions and eight intentionally failing sanitizer controls. This is sampled
dynamic memory/lifecycle coverage on one native x86 host, not a complete memory
safety proof, ARM execution, compiler matrix, constant-time, final-linked code,
spill erasure, physical-fault resistance or release approval. The remaining
work stays in [the development ledger](aes-acceleration-development.md).
