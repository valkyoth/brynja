# Brynja 0.8.0 Release Notes

Status: pentest and retest passed; awaiting GitHub

Brynja 0.8.0 implements a protocol-neutral transactional caller-buffer write
cursor. It does not implement integer encoding, TLS framing, a protocol parser,
a state machine, cryptography, PKI, arenas, secret destruction, or a
production-ready transport and must not be used to secure network traffic.

## Transactional Write Cursor

`brynja-core 0.5.0` provides `WriteCursor<'output>` over caller-owned mutable
bytes. The cursor stores only the exclusive borrowed slice and a private
`usize` position. Construction performs no allocation and changes no byte.

`write(&[u8])` and `write_repeated(u8, usize)` check the complete end offset and
destination range before mutation. `write_parts(&[&[u8]])` first computes the
complete aggregate length with checked arithmetic, then checks the complete
destination before copying its first part. Empty inputs and parts are valid.

A successful operation writes only its exact destination and advances once by
the complete length. Arithmetic overflow or insufficient capacity leaves every
caller-buffer byte and the cursor position unchanged. Multiple parts supplied
to one call are one transaction; separate successful calls are intentionally
separate transactions and are not rolled back together.

The repository-owner assessment confirmed that a successful `checked_end`
preflight currently makes each following mutable range lookup infallible. The
cursor now asserts that relationship in debug builds and retains the existing
fail-closed optional-range fallback in release builds so future refactors make
invariant erosion visible without adding a panic path to production behavior.

`written()` exposes only an immutable borrow of the successful prefix.
`finish(self)` consumes the cursor and returns the original caller buffer only
when its capacity was used exactly; otherwise it returns `TrailingCapacity`
without further mutation.

## API And Diagnostic Boundaries

`WriteCursor` is private-field, `must_use`, non-`Clone`, non-`Copy`, and
implements neither `Debug` nor `Display`. Its exclusive lifetime prevents safe
outside access to the caller buffer while the cursor remains active.

`WriteError` is a closed value-free category with `InsufficientCapacity`,
`LengthOverflow`, and `TrailingCapacity` variants. It carries no output bytes,
offset, requested length, available length, arbitrary string, allocation, or
provider-native detail and may therefore implement `Debug` safely.

The cursor copies bytes but does not own secret semantics or promise erasure.
Callers and later secret-owning types remain responsible for clearing sensitive
input and output regions.

## Verification

- every start position and requested length around an eight-byte caller buffer
  is compared with exact expected success or failure behavior;
- every capacity failure preserves a sentinel-filled complete buffer and the
  original cursor position;
- multi-part writes verify aggregate preflight, empty parts, source ordering,
  and no mutation before complete capacity is available;
- a `usize::MAX` repeated length proves end-offset overflow remains distinct
  from ordinary capacity exhaustion and mutation-free;
- zero-length single, multi-part, and repeated writes are checked at every
  output boundary;
- empty output, immutable written-prefix inspection, consuming exact
  completion, output identity, and compact representation are verified;
- compile-fail doctests reject cursor cloning, formatting, and outside output
  mutation while its exclusive borrow remains active; and
- workspace lints forbid indexing, explicit panic paths, unchecked arithmetic,
  unsafe code, and external dependencies.

The full release gate additionally covers Rust 1.90.0 through 1.97.1, all host
and OS-less targets, `no_std`, modern/legacy isolation, source and requirement
reproducibility, assurance policy, package contents, SBOM, dependency policy,
advisories, documentation, and live standards/tool drift.

The repository-owner assessment of signed candidate
`ebabb656697a5a98ac01a79b801c012daa31ca24` found no exploitable cursor
defect. It recorded the intentionally excluded zeroization responsibility as
informational and one Low defense-in-depth observation about the mutable range
lookups following successful preflight. All three operations now assert their
proven destination invariant in debug builds while preserving the
bounds-checked, fail-closed release fallback.

The repository owner retested signed remediation candidate
`79027316d1d023b0f55870d8371b22a2c536a7ae` and reported it green with no
remaining finding. The permanent report records `PASS`/`PASS` and zero open
findings.

## Requirements And Protocol Claims

The write cursor is a source-free shared foundation. No protocol surface or
normative protocol requirement advances to implemented, tested, or evidenced.
Integer encoding, canonical formats, nested framing, patching, TLS/DTLS/QUIC
serialization, arenas, overlap policy, mutable accounting, secret destruction,
and protocol state remain owned by later milestones.

Project tests, CI, pentesting, fuzzing, Miri, sanitizers, or future Kani
harnesses are not independent cryptographic or protocol verification. Brynja
has no FIPS 140-3 validation, certificate, approved module, or validated
operational-environment claim.

## Publication Set

The candidate selects `brynja-core 0.5.0`, eight dependency-only modern
support patches at `0.1.4`, and the mandatory `brynja 0.8.0` facade.
`brynja-crypto` remains unchanged at `0.1.0`; legacy and repository-only
packages remain unpublished. The guarded publisher enforces exact pins,
dependency order, and the facade-last rule.

Publication remains blocked until this permanent `PASS`/`PASS` report and the
final release evidence are committed, GitHub is green, and the user explicitly
authorizes the signed release tag.

## Limitations

This milestone copies already-formed byte sequences only. It does not derive,
interpret, backpatch, frame, authenticate, encrypt, own, or erase them. It does
not provide atomic rollback across separate successful cursor calls.
