# Brynja 0.7.0 Release Notes

Status: implementation complete; awaiting pentest

Brynja 0.7.0 implements a protocol-neutral borrowed read cursor. It does not
implement TLS framing, integer decoding, a protocol parser, a state machine,
cryptography, PKI, mutable resource accounting, secret ownership, or a
production-ready transport and must not be used to secure network traffic.

## Borrowed Read Cursor

`brynja-core 0.4.0` provides `ReadCursor<'input>` over caller-owned immutable
bytes. The cursor stores only the borrowed slice and a private `usize`
position. It allocates nothing and returns slices or fixed-array references
that retain the caller input lifetime.

`take(usize)`, `take_length(Length<MAX>)`, and `take_array::<N>()` compute the
end offset with checked arithmetic and inspect ranges through bounds-checked
slice access. A successful operation advances by exactly the requested length.
Overflow, truncation, or fixed-array conversion failure leaves both position
and the remaining suffix unchanged.

`finish(self)` consumes the cursor and succeeds only after exact input
consumption. Any unconsumed suffix returns `TrailingData`. Zero-length reads
are valid and leave the position unchanged at every input boundary.

## API And Diagnostic Boundaries

`ReadCursor` is private-field, `must_use`, non-`Clone`, non-`Copy`, and
implements neither `Debug` nor `Display`. This prevents implicit parser-state
forks and accidental byte formatting while keeping all returned data borrowed
from the caller.

`ReadError` is a closed value-free category with `Truncated`,
`LengthOverflow`, and `TrailingData` variants. It carries no input bytes,
offset, requested length, available length, arbitrary string, allocation, or
provider-native detail and may therefore implement `Debug` safely.

## Verification

- a composite six-byte read rejects every truncated prefix and accepts only
  the exact input;
- every non-empty trailing suffix is rejected by explicit completion;
- every start position and requested length around an eight-byte fixture is
  compared with the expected exact range behavior;
- every failure preserves position and the borrowed remaining suffix;
- `usize::MAX` end-offset overflow is distinct from truncation and does not
  mutate the cursor;
- zero-length array reads are checked at every boundary;
- typed lengths, fixed arrays, borrow identity, and compact representation are
  verified;
- compile-fail doctests reject cursor cloning, formatting, and output borrows
  that outlive the caller-owned input; and
- workspace lints forbid indexing, panic paths, unchecked arithmetic, unsafe
  code, and external dependencies.

The full release gate additionally covers Rust 1.90.0 through 1.97.1, all host
and OS-less targets, `no_std`, modern/legacy isolation, source and requirement
reproducibility, assurance policy, package contents, SBOM, dependency policy,
advisories, and live standards/tool drift.

## Requirements And Protocol Claims

The read cursor is a source-free shared foundation. No protocol surface or
normative protocol requirement advances to implemented, tested, or evidenced.
Wire integer decoding, canonical formats, nested framing, TLS/DTLS/QUIC
parsing, transactional writes, arenas, copied-secret zeroization, and protocol
state remain owned by later milestones.

Project tests, CI, pentesting, fuzzing, Miri, sanitizers, or future Kani
harnesses are not independent cryptographic or protocol verification. Brynja
has no FIPS 140-3 validation, certificate, approved module, or validated
operational-environment claim.

## Publication Set

The release selects `brynja-core 0.4.0`, eight dependency-only modern support
patches at `0.1.3`, and the mandatory `brynja 0.7.0` facade. `brynja-crypto`
remains unchanged at `0.1.0`; legacy and repository-only packages remain
unpublished. The guarded publisher enforces exact pins, dependency order, and
the facade-last rule.

Publication remains blocked until the repository-owner pentest is complete,
the permanent report is committed as `PASS`/`PASS`, GitHub is green, and the
user explicitly authorizes the signed release tag.

## Limitations

This milestone reads borrowed byte ranges only. It does not interpret bytes,
validate canonical encoding, bound protocol-specific work, own or erase
secrets, mutate output, manage arenas, authenticate peers, or protect traffic.
