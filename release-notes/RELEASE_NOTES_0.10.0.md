# Brynja 0.10.0 Release Notes

Status: released; pentest, remediation retest, hosted checks, signed tag, and crates.io publication complete

Brynja 0.10.0 implements an abstract secret-lifetime and destruction-duty
contract plus isolated RFC 9850 test support. It does not implement a
byte-backed production secret owner, proven local-memory erasure, integer
encoding, TLS framing, a protocol parser or state machine, cryptography, PKI,
or a production-ready transport and must not be used to secure network traffic.

## Secret Lifetime Contract

`brynja-core 0.7.0` adds `SecretLifecycleContract`,
`SecretInitialization`, and `SecretState` without allocation or external
dependencies. Secret initialization is affine and write-only: only exact
complete write acknowledgments can produce a live abstract state. Partial
progress, overrun, cancellation, exhaustion, provider failure, and ordinary
drop cannot expose a readable state.

The state is private, non-clonable, non-formattable, contains no bytes, and has
no read method. It is a lifecycle model, not secret storage or an erasure
implementation. The v0.11.0 primitive remains the only path to an admitted
byte-backed local-memory owner.

## Destruction Duties

The contract names local memory, external stores, accelerators, caches, and
DMA-visible regions explicitly. Initialization failure, cancellation,
exhaustion, provider failure, replacement, obsolescence, and drop invoke every
configured duty in fixed order even if an earlier duty fails. Completion is
single-consumption; any failed duty produces a terminal failure carrying only
the first closed target identity.

Explicit transitions return that failure. Because Rust `Drop` cannot return a
value, every `SecretDestructor` must provide `handle_drop_failure`. Failed
partial-initialization and live-state drops invoke it with the closed failure
after attempting every configured target. The handler must synchronously make
the failure durable or initiate the platform's fail-stop response; returning is
a security assertion that silent continuation is impossible under the declared
operating contract.

An implementation returning `DestructionComplete` makes a security assertion
that its complete target duty succeeded. Brynja 0.10.0 intentionally provides
no concrete production local-memory destructor, so no test, safe fill, debug
canary, or destructor token is claimed as proof of byte erasure.

## Test-Only RFC 9850 Key Logging

The permanently unpublished `brynja-test-support 0.1.0` package implements all
ten pinned SSLKEYLOGFILE labels and LF, CRLF, and CR line endings. It requires
the exact 32-byte ClientHello random, rejects an empty secret, emits uppercase
hex with canonical spacing, and preflights the complete output line so every
rejection preserves the complete caller buffer.

Production key logging remains prohibited. No production package depends on
test support, and workspace policy plus broken fixtures reject direct,
optional, feature, target-specific, publishable, or resolved-graph smuggling.

## Verification

- every exact initialization boundary and every early-exit cause is covered;
- partial initialization and live-state drop duties are observed explicitly;
- replacement destroys the old state before admitting new initialization;
- all destruction targets are attempted after individual target failures;
- failed drops in both lifecycle phases notify the mandatory terminal handler;
- compile-fail documentation rejects secret-state cloning and formatting;
- every RFC 9850 label, every line ending, canonical output, empty secrets,
  closed diagnostics, and every short output capacity are tested; and
- requirement history records distinct implemented and tested revisions with
  actual code and test targets.

The release gate additionally covers Rust 1.90.0 through 1.97.1, host and
OS-less targets, `no_std`, isolation, source/requirement reproducibility,
package contents, SBOM, dependency policy, advisories, and documentation.

## Release Cadence Boundary

This is the last release under the original per-version pentest and publication
cadence. After signed v0.10.0, every roadmap version retains its signed tag,
complete automated gate, and green GitHub and CodeQL requirement, while each
fifth minor version (`0.15.0`, `0.20.0`, and so on) is a scheduled cumulative
pentest and crates.io checkpoint. Patch-numbered roadmap versions belong to the
range beginning at their minor version. The v0.15.0 pentest reviews all changes
after v0.10.0 through v0.15.0; v0.20.0 reviews all changes after v0.15.0 through
v0.20.0. Exceptional security, compatibility, or publication triggers remain
available.

## Publication Set

The candidate selects `brynja-core 0.7.0`, eight dependency-only modern
support patches at `0.1.6`, and mandatory `brynja 0.10.0` last.
`brynja-crypto` remains unchanged at `0.1.0`; legacy and repository-only
packages remain unpublished.

Publication is blocked until the committed PASS/PASS report and final candidate
pass GitHub, and the user explicitly authorizes the signed release tag.

## Pentest Disposition

The repository-owner assessment found one Medium defect: failures reached
through partial-initialization or live-state `Drop` were discarded after the
destruction duties ran. The mandatory `handle_drop_failure` contract and
two-phase failing-Drop regression test described above remediate the issue.
The assessment also retained the self-attested destructor-completion boundary
as informational and load-bearing for v0.11.0. The repository owner retested
signed remediation candidate `1818f36` and reported it green with zero open
findings. The permanent report records `PASS`/`PASS`.

## Verification Status

Project tests, CI, pentesting, fuzzing, Miri, sanitizers, or future Kani
harnesses are not independent cryptographic or protocol verification. Brynja
has no FIPS 140-3 validation, certificate, approved module, or validated
operational-environment claim.
