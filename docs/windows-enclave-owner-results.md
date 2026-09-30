# Windows enclave owner integration results

The bounded SHA-256 crate API is implemented and development-tested. This record
is implementation-author evidence, not an independent retest, a completed release
sweep or production-signed qualification. The broader Windows milestone remains
open. See the [API contract](windows-enclave-owner.md).

## Native development execution

Both debug and optimized release tests passed on the Azure Windows Server 2025
x64 development host with VBS/HVCI running, Secure Boot disabled and test signing
enabled. Rust 1.98.1 used MSVC 14.44.35207 and SDK 10.0.26100.0. The unchanged
development-signed worker hash is
`a939358b9abca529c2c59b02c8226bdaf6648629331a29937d53d771afd5b945`.

Each profile passed twelve portable/native unit tests and the separately
requested development campaign. That campaign checked sixteen public message
vectors, five retained rehash rounds, request-size rejection, cancellation,
reuse, abandoned/forgotten handles, recoverable caller unwinding, explicit close,
parent Drop and release of held file handles. The public production constructor
rejected the development signature. A private unit-test-only constructor then
exercised the same Rust owner against the enclave. No development bypass is
exported or enabled by a Cargo feature.

The [observation record](../assurance/windows-protection-observations/owner-integration-20260930.json)
binds the thirteen tested owner source files, baseline revision, image, native
configuration and local archive/log hashes. The source was uncommitted during
collection; exact hashes were compared to the final local module bytes before
recording. Raw files are saved outside `target/` in
`release-reports/windows-azure-replacement-2026-09-30/`. No owner test process
remained after capture, and the signed image hash was unchanged.

An initial native link failed because the selected SDK requires onecore.lib for
several enclave functions. The import library was corrected; the successful
debug/release runs came afterwards. Cross-compilation alone had not detected
that link failure. No test failure was relabeled as passing.

## Regression checks

- Eleven real-source lifecycle/image tests pass with Rust 1.90.0 and 1.98.1.
  The synthetic image fixture binds all 4,624 bytes and rejects every truncation,
  malformed identity/import cases, and debug-policy flags even with a matching hash.
- Nine compiled admission/lifecycle mutants fail their tests through
  `scripts/cryptography/test-windows-enclave-owner.py`; compilation failures are
  not accepted as mutant rejection. Generated production policy source compiles
  with the real API in that harness.
- Twelve owner/result trait and lifetime compile-fail doctests pass. Packaged
  strict consumers pass debug/release and reject 107 export/ownership cases.
- Eight focused portable lifecycle/protocol tests pass under Miri. This does not
  model Windows OS calls or execute the enclave worker.
- Affected all-feature tests and doctests, Linux and Windows-target strict
  Clippy, Windows-target minimum-Rust compilation, README examples, package,
  workspace, unsafe inventory and first-party Rust policies were checked.
  The Windows OS ABI additions reject twelve extra import/link/relocation mutants.

## Remaining qualification

Production signing succeeds only when a deployer supplies a valid reviewed image
and the full Windows trust/load/initialization checks pass; no such production
success was exercised here. Wider algorithms, hardware/SIMD routes, Windows Arm,
compiler/register and updated dump qualification, and independent pentest remain
separate work. The new safe host integration does not transfer old dump evidence
to itself or close the entire Windows release milestone. Release gates and
publication scope are unchanged.
