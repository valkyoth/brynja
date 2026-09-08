# General SHA-512/t authority and public API contract

Status: v0.24.26 implements ordinary/hardened byte/bit hashing for every valid t,
typed secret outputs and explicit declassification. v0.24.27 closes the
[secret lifecycle evidence](sha512-t-lifecycle.md); the owner pentest/retest is green.
v0.24.28 freezes [portable public acceptance](sha512-t-public-acceptance.md)
against extracted packages; its owner pentest/retest is green.
v0.24.29 adds [final scalar work/resource/profile evidence](sha512-t-final-evidence.md);
its exceptional owner review is pending. Do not mark the family complete yet.
The six named SHA-2 functions remain complete and unchanged. This extension
is a separate row, closing only at v0.24.29. No CPU backend is admitted.

## Authority and rights

The authority is the August 2015 FIPS 180-4 final, especially §5.3.6 and its
dependencies §§3.1–3.2, 4.1.3, 4.2.3, 5.1.2, 5.2.2, 5.3.5 and 6.4.
Sections 5.3.6.1–5.3.6.2 and 6.6–6.7 supply the named /224 and /256 checks.
[Official publication](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) and
[exact PDF](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) were
reviewed on 2026-09-07. The local PDF SHA-256 is
`0455b406d89648d20cbde375561e19c245b9815e894164c2670772e3d54deb82`.

The landing page still lists the August 2015 final and the 2023-03-07 revision
announcement. No separate correction is listed there; this is an observation,
not a promise that no erratum exists. Recheck before implementation freeze and
on authority-lifecycle drift. Future editions must receive a new explicit
review; never replace a pinned PDF silently. SP 800-107 Rev. 1 is already in
the source ledger as hash-use/security context, not an authorization for every t.

The existing source ledger and local-rights policy retain official PDFs only
under ignored `references/local/`. Git and crate packages contain our original
contract, URLs and digests, not NIST document copies. NIST's
[publication rights policy](https://www.nist.gov/open/license) is recorded as
context; this change does not broaden redistribution permissions or imply
NIST endorsement. Repository code remains MIT OR Apache-2.0.

## Parameter and algorithm identity

All 510 integers `1..=511` except `384` are in the general mathematical domain.
Do not narrow this to byte multiples. Reject zero, 384, 512 and every larger
representable value. The public parameter is a validated integer, never a
caller-supplied label, IV, unchecked byte count or mutable field.

IV generation uses the normal SHA-512 initial words XORed with
`0xa5a5a5a5a5a5a5a5`, then hashes the ASCII prefix `SHA-512/` followed by the
shortest decimal representation of t. No leading zero, sign, whitespace, NUL
or locale-dependent formatting is allowed. The 9–11 byte label needs exactly
one SHA-512 padding block. Hash the actual message with this derived IV and
return its leftmost t bits, **not a truncation of ordinary SHA-512**.

For t=224 or 256, bits must equal the existing named implementations, but the
general result remains a distinct typed identity. t=384 is not SHA-384 and is
invalid. General values do not inherit protocol, signature, HMAC, PKIX or FIPS
admission. Only /224 and /256 are specifically approved identities in this
edition; Brynja itself has no FIPS validation, including those named functions.
Short outputs have correspondingly weak generic collision/preimage bounds
(at most approximately t/2 and t bits); full-width strength is never implied.

## Package and selection

Use `brynja-hash-sha2`, not another compression crate or duplicated engine.
Use the explicit default-off `general-sha512-t` feature in that leaf. No modern
facade reexport or protocol selection occurs implicitly. If a facade adapter
is later added it must forward that explicit feature and preserve the identity.
The leaf remains allocation-independent no_std, Rust 1.90.0 through the current
default, first-party Rust only, with source files no larger than 500 lines.
No third-party dependency, new unsafe boundary or hardware session is needed.

## Public API matrix

Names and signatures below have been callable since v0.24.26.
Any necessary contract change must update the machine register and tests with
an explicit review; implementations must not expose stubs for missing rows.
All parameter values have every row below. The ordinary profile is public-data
only; hardened ownership is mandatory for confidential input or derived state.

| Operation | Public surface | Introduced |
| --- | --- | --- |
| Parameter admission | `Sha512TBits::new(u16) -> Result<Self, Sha512TError>`; `bits()`, `output_bytes()` | 0.24.25 |
| Public IV diagnostics | `write_iv_label(self, &mut [u8]) -> Result<usize, Sha512TError>`; `initial_words(self) -> [u64; 8]` | 0.24.25 |
| Public digest | `Sha512TDigest::parameter()`, `as_bytes()` | 0.24.25 |
| Public digest import | `Sha512TDigest::from_bytes(parameter, &[u8]) -> Result<Self, Sha512TError>`; `AsRef<[u8]>` | 0.24.25 |
| Ordinary state | `Sha512T::new(Sha512TBits)`, `update(&mut self, &[u8]) -> Result<(), Sha512TError>` | 0.24.26 |
| Ordinary finish | `finalize(self)`, `finalize_bits(self, BitString)` -> typed public digest result | 0.24.26 |
| Ordinary one-shot | `sha512_t(parameter, &[u8])`, `sha512_t_bits(parameter, BitString)` -> typed public digest result | 0.24.26 |
| Hardened state | `HardenedSha512T::new(parameter)`, `update(&mut self, &[u8])` | 0.24.26 |
| Explicit public finish | `finalize_public(self, PublicDeclassification)`, `finalize_bits_public(self, BitString, PublicDeclassification)` -> typed public digest result | 0.24.26 |
| Secret finish | `finalize_secret(self, &mut [u8])`, `finalize_bits_secret(self, BitString, &mut [u8])` -> secret digest owner result | 0.24.26 |
| Hardened one-shot | `hardened_sha512_t_public`, `hardened_sha512_t_bits_public`, `hardened_sha512_t_secret`, `hardened_sha512_t_bits_secret` | 0.24.26 |
| Secret output access | `Sha512TSecretDigest::parameter()`, borrowed `as_bytes()`; Drop clears entire destination | 0.24.26 |
| Secret declassification | Consuming `Sha512TSecretDigest::declassify(self, PublicDeclassification)` -> public digest result; clears consumed storage | 0.24.26 |
| Explicit cancellation | `HardenedSha512T::cancel(self)`; ordinary cancellation is consuming Drop | 0.24.26 |

One-shot argument order is parameter, message, then destination when secret.
The v0.24.25 contract refinement makes the value APIs externally usable before
hashing exists: exact-width **public** digest import rejects nonzero unused low
bits rather than masking them; `TryFrom<u16>` repeats checked admission. Import
does not verify or compute a hash. Labels write 9..=11 bytes, preserving the
entire destination on insufficient capacity and any trailing bytes on success.
IV diagnostics return public derived initial words, not arbitrary-state import
or message hashing. Both need only fixed workspace and no secret cleanup:
the input is public t, never a key, confidential input or prior hash state.
These value operations passed the v0.24.25 owner pentest; hashing is a new scope.

Hardened public one-shot calls additionally require a final
`PublicDeclassification` argument, using the existing explicit acknowledgement.
Anyone can construct that acknowledgement. It makes the public conversion
deliberate at the call site; it is not access control, caller authentication,
an audit log or a runtime authorization check. It prevents implicit typed
conversion, not misuse of explicitly exposed secret bytes. Applications own
their disclosure policy and any authorization or audit requirements.
Hardened public and secret functions have the same checked error type. No reset,
clone, serialization, raw state/IV import or implicit secret digest export is
promised. No XOF, decode or decryption exists for this fixed one-way hash.
Complete bytes stream through update; consuming finalization accepts the
remaining canonical `BitString`, containing zero or more complete bytes and
at most one 0–7-bit tail. Reuse the existing SHA-2 MSB-first `BitString`
descriptor and checked append semantics, without introducing another tail type
or permitting later updates after a partial byte.

## Output and failure contract

Public digests privately store t and at most 64 bytes; `as_bytes()` exposes
exactly `ceil(t/8)` bytes. Bits are MSB-first. Unused low bits of the last byte
and all unused private storage are zero. Equality must include parameter
identity, not merely rounded byte contents. General and named digest types do
not silently convert. Public digest copying is allowed only after explicit
declassification; no secret owner implements Clone, Copy, Debug or Display.

Secret output is an affine, lifetime-bound wrapper over the existing sealed
secret-region owner and the validated parameter. Require destination length
exactly `ceil(t/8)`, rejecting both short and oversized buffers. On **every**
secret-output error, clear the entire supplied destination, even when its
length is invalid; guard it before any other fallible action. Success exposes
only a borrowed canonical byte view and retains classification until Drop or
explicit consuming declassification. The latter makes a public copy and clears
the original destination. Raw borrowed bytes cannot enforce information flow;
copying them requires the caller to preserve their confidentiality and cleanup.
Safe exclusive borrows prevent input/output aliasing. Caller-created copies
and source inputs remain the caller's responsibility.

Public output returns a value, so no partial caller output is observable on
failure. Reject length overflow before mutating streaming state; an update
rejection leaves the previous state usable. Finalization consumes the state
even on error. Hashable messages have fewer than 2^128 bits. Errors distinguish
invalid parameter, message length, output size and secret-memory ownership or
clearing failure; malformed partial bytes are
rejected by existing canonical input constructors. No production panic is an
error mechanism.

## Secret lifecycle and resource bounds

Inventory private chaining words, partial block, schedule, round working words,
block copies, final staging, lengths and discriminants. IV labels/derived IVs
depend only on public t but must not accidentally retain a prior secret buffer.
Use the existing mandatory compiler-resistant clearing primitive from
`brynja-core`; never make internal cleanup depend on optional
`brynja-sanitization` or caller access to private state. Hardened capability
traits are sealed. Clearance applies at consuming success/rejection, cancel,
recoverable unwind and Drop; borrowed update/preflight rejection instead retains
the entire live state unchanged. Destructors remain non-panicking around adjacent
cleanup. The [lifecycle inventory](sha512-t-lifecycle.md) distinguishes owned
regions from borrowed input, public metadata and transient/register values.

Mem::forget, abort/double-panic abort, forced termination, power loss, registers,
compiler-created copies/spills, caches, swap, dumps, DMA and movable caller
copies remain explicit residuals. No pinning/locking or erasure-after-abort
claim follows from this contract. Accelerated hardened use is forbidden absent
equivalent separately reviewed cleanup and migration evidence.

Initialization costs one compression block; absorb costs linear input work;
finalization costs one or two blocks and at most 64 output bytes. All storage
is fixed-size. Invalid secret destinations still cost O(destination length)
to clear completely; callers must bound even rejected destination sizes.
No background work, global cache, hidden allocation or per-byte
callback is allowed. Callers impose time budgets through bounded update chunks
and may cancel between calls. One-shot work is explicitly synchronous and
linear; no mid-call interruption guarantee is made. Work depends on public
input length and t, not secret contents. Include output length and identity in
application policy; this API is not a general authentication construction.
Network-facing callers must enforce their own total input limits, time budgets
and rate limits at ingestion. The FIPS message-length ceiling is an algorithm
bound, not a practical denial-of-service limit.

## Required evidence and stage boundaries

The machine register is `requirements/sha512-t-contract.toml`. Its current
tests exhaust all 65,536 u16 inputs, the 510 allowed parameter descriptors,
labels, rounded widths and masks, and reject altered authority/domain/API
claims. These are **contract-model tests**, not Rust SHA-512/t digest evidence.
v0.24.25 additionally executes all 510 IVs against a separate Python oracle
whose constants are derived from integer square/cube roots of primes, plus
exhaustive Rust parameter/canonical-digest tests and a downstream no_std fixture.
The existing named-IV derivation test remains a useful unchanged cross-check.

v0.24.26 adds 4,590 independent digest comparisons across all 510 parameters,
ordinary/hardened incremental and one-shot APIs, canonical bit tails, typed
secret output, compiler-rejected misuse, and all eight shared SHA-2 owner regions.
The source-bound emitted-code check covers consuming public/secret finalizers
and declassification on normal and recoverable-unwind paths on Rust 1.90.0 and
1.98.1 in debug/release. Double-panic termination remains an explicit exclusion.
This is scoped evidence, not a proof of every compiler-created copy or register.
The existing mandatory SHA-2 owner is reused; IV derivation sees only public t.

- v0.24.25: actual Rust parameter/digest APIs, exact IV generation; independent
  IV oracle across all 510 t, invalid values, named IVs and short labels.
- v0.24.26: every matrix API, ordinary/hardened and byte/bit digests; independent
  digest oracle across every t; named identity, empty/million-byte, irregular
  streaming, padding at 111/112/127/128 bytes and all seven tail widths.
- v0.24.27: typed-output, errors, cancellation, unwind, Drop, non-forgeability,
  compile-fail ownership and emitted cleanup across supported compiler/targets.
- v0.24.28: frozen package-external no_std fixture, all rows, every t, malformed
  destinations, canonical output, feature isolation, real consumer examples.
- v0.24.29: rerun that same fixture on final source, affected Miri/Kani/ASan,
  constant-work/cleanup and performance evidence, native unsupported/admission
  disposition and exceptional pentest. Only then mark general SHA-512/t complete.

No oracle, compiler proof, sanitizer, native timing or cleanup execution for
unimplemented general APIs is claimed at v0.24.24. Existing full named SHA-2
acceptance does not silently stand in for those future tests.
