# Scoped hardened storage

Status: named/general SHA-2 and SHA-3/SHAKE/cSHAKE API development checkpoint; wider rollout and complete
register/spill qualification pending. No independent verification or FIPS claim.

The first additive API is `brynja_hash_sha3::hardened_in_place`, with
`Sha3_224Workspace`, `Sha3_256Workspace`, `Sha3_384Workspace` and
`Sha3_512Workspace`. Each provides `new`, `Default` and `with`. Its borrowed
state provides `update`, byte/bit `finalize_secret`, byte/bit `finalize_public`,
and `cancel`. Public finalization requires `Sha3PublicDeclassification`;
secret finalization returns the existing `HardenedSha3SecretOutput`.

`Shake128Workspace` and `Shake256Workspace` likewise provide `new`, `Default`
and `with`. Their state supports `update`, `finalize_xof`, `finalize_bits_xof`
and `cancel`. Finalization returns a borrowed reader, not a moved secret owner.
Readers support `squeeze_secret`, `squeeze_public`, consuming
`squeeze_final_bits_secret` / `squeeze_final_bits_public`, and `cancel`.
The bit methods take canonical `Fips202BitString` / `Fips202Output`; secret
output uses the same typed destination owner as fixed-output SHA-3.

`Cshake128Workspace` and `Cshake256Workspace` expose the same state/reader
operations. Their `with(N, S, callback)` and `with_bits(N, S, callback)` initialize
the prefix only after borrowing the final storage. Empty N/S is SHAKE. Setup
failure clears storage and skips the callback. The outer `Result` covers setup;
the inner value is the callback result (often another `Result`, hence `??` in
the compiled module example). N/S and message inputs remain caller-owned.

The module's compiled example demonstrates returning a secret output from a
scope. The state cannot escape. Its lifetime is independent of the separately
borrowed destination, so callers can use a returned output after the workspace
has been cleared. Neither storage, state nor reader implements
Copy/Clone/Debug/Send/Sync. XOF readers cannot escape the callback either.

## Named SHA-2

`brynja_hash_sha2::hardened_in_place` provides `Sha224Workspace`,
`Sha256Workspace`, `Sha384Workspace`, `Sha512Workspace`, `Sha512_224Workspace`
and `Sha512_256Workspace`, each with `new`, `Default` and `with`. The borrowed
handle supports `update`, `finalize_secret`, `finalize_bits_secret`,
`finalize_public`, `finalize_bits_public` and `cancel`. Bit input uses canonical
MSB-first `BitString`; public output requires `PublicDeclassification` and secret
output returns `OwnedSecretRegion`.

These scopes use the existing portable hardened SHA-2 implementation. Each scope
loads its exact public IV before allowing secret input into the borrowed storage.
Initialization may move secret-free storage, but no active secret owner moves
into finalization. Update errors clear the state and make further operations
return `HardenedSha2Error::StateConsumed`. No accumulated-length/preflight query
is exposed. Storage and handles are neither Copy/Clone/Debug/Send nor Sync.
The same scope/Drop/forget/output guarantees and exclusions below apply.
Named accelerated scopes are available separately as described below.

## Named SHA-2 execution scopes

The default-off `hardened-execution` feature exposes
`hardened_execution::in_place::{Sha224Workspace, Sha256Workspace, Sha384Workspace,
Sha512Workspace, Sha512_224Workspace, Sha512_256Workspace}`. Construction takes
an explicit existing `hardened_execution::Execution`: portable, static, or
hosted when `runtime-execution` is enabled. No new platform authority is added.
The same migration/deployment requirements apply. Hosted x86 remains unavailable
under the existing policy; compiled static SHA-NI remains supported.

These workspaces own the engine and CPU session scratch before secrets arrive.
`with(callback)` rechecks the same authority, resets public work counters and
restores the exact public IV in cleared storage. Its outer `Result` covers
admission; the inner value is the callback result (`??` in the module example).
Admission failure does not invoke the callback or access its captured buffers;
it cannot clear a destination it has not received. Secret-destination clearing
starts when a finalization method receives that destination.
An authority cannot be replaced or renewed, and a quarantined workspace never
invokes a new callback or silently falls back. A healthy workspace can start a
new computation after the previous scope clears.

Borrowed handles support `update`, byte/bit `finalize_secret`, byte/bit
`finalize_public`, and `cancel`. Every update error clears and terminally disables
that computation, including length errors (unlike the older by-value API).
No accumulated-length/preflight methods are added. Final outputs retain the
existing `SecretOutput`/`Report` contract: route and work counts are public
metadata, not hidden message-length guarantees. Public output still requires
explicit declassification; all secret errors clear the complete destination.

Handle and outer-scope guards independently clear hash storage, including
forgotten handles and recoverable unwind. Existing CPU operation guards clear
private scratch and retain their quarantine behavior. Neither the active engine
nor its scratch moves through finalization. General-t execution is described
below. Scoped higher constructions remain rollout work; this is not complete
register/spill qualification.

## General SHA-512/t

With the default-off `general-sha512-t` feature, `hardened_in_place` also exposes
`Sha512TWorkspace::new(parameter)` and its borrowed `Sha512T` handle. The validated
`Sha512TBits` identity is public and fixed for the workspace; `parameter()` does
not expose accumulated message length. `with` derives the public parameter IV
before accepting secret input, including on reuse.

The handle has the same update, cancel and byte/bit finalization operations.
Secret finalization returns `Sha512TSecretDigest` with the exact parameter and
canonical partial-byte mask, never a public byte importer. Public finalization
requires `PublicDeclassification` and returns `Sha512TDigest`. Update failure
clears and disables the handle (`Sha512TError::StateConsumed`); secret-output
errors clear the complete destination. A separately borrowed secret digest may
outlive the callback, but the state cannot escape it.

With both `general-sha512-t` and `hardened-execution`, the separate
`hardened_execution::in_place::Sha512TWorkspace::new(parameter, execution)`
offers the same scoped identity through an explicit wide execution route.
It derives the public IV inside each scope after authority validation, before
accepting secret input. Narrow SHA-256 authority is rejected. Secret output is
the existing `GeneralSecretOutput` containing `Sha512TSecretDigest` and a public
work report; public output is `Output<Sha512TDigest>` and requires explicit
declassification. No secret output uses `Sha512TDigest::from_bytes`.
The report retains one portable IV-derivation block per computation and discloses
message/padding work as before; it is not a length-hiding guarantee.
The outer admission result, full-destination clearing, terminal update errors,
forget/unwind cleanup and authority rules match the named execution scopes.

The compiled module example demonstrates secret output outliving the scope;
the workspace/handle cannot be copied, cloned, formatted, sent or shared.
Fourteen compiled negative examples cover these traits, handle escape, overlap,
authority lifetime and implicit secret-to-public conversion.

## Fixed-output SHA-3 execution scopes

The default-off `hardened-execution` feature also exposes
`brynja_hash_sha3::hardened_execution::in_place::{Sha3_224Workspace,
Sha3_256Workspace, Sha3_384Workspace, Sha3_512Workspace}`. Each constructor takes
the existing `KeccakSession`, not ordinary public-data authority or scratch.
The workspace retains the sponge engine, session scratch and 168-byte clearing
output stage before secret input. The handle borrows that storage through update
and consuming byte/bit finalization. Public output requires explicit
`Sha3PublicDeclassification` and commits only after success; secret output is
typed and its entire destination clears on any finalization error.

`with` clears storage and checks the same session before invoking the callback.
As with scoped SHA-2, the outer result covers admission, not captured buffers
which were never supplied to an operation. Scope and handle guards independently
clear the sponge/stage, including cancellation, forgotten handles and recoverable
unwind. Every update error terminates the current computation. Reuse starts a
fresh zero state but never reverses authority quarantine or silently falls back.
`report()` returns only the existing backend/health observation, not message
length or authority. No preflight/length query is exposed on the handle.

The existing static deployment and hosted platform requirements are unchanged.
Register/spill/framing qualification is separate; neither scope ownership nor
functional testing establishes whole-register erasure.

## SHAKE/cSHAKE execution scopes

The same `hardened_execution::in_place` module provides `Shake128Workspace`,
`Shake256Workspace`, `Cshake128Workspace` and `Cshake256Workspace`. Construction
binds a `KeccakSession` without accepting secrets. SHAKE uses `with(callback)`;
cSHAKE uses `with(name, customization, callback)` or `with_bits` with canonical
bit strings. Prefix absorption happens only after borrowing the workspace;
empty name/customization selects SHAKE. Admission or prefix failure skips the
callback and clears storage, but cannot clear captured destinations not yet
passed to an operation.

`finalize_xof` / `finalize_bits_xof` consume the absorbing handle and transfer
its reference into a distinct reader. Sponge, session scratch, domain metadata
and the 168-byte output stage remain in the workspace. `squeeze_secret` returns
an affine output owner borrowing a separate destination, which may outlive the
scope. `squeeze_public` explicitly declassifies up to 168 bytes transactionally;
larger reads use `squeeze_public_with_scratch`, with scratch covering the output.
The entire supplied scratch clears on every exit. Final-bit reads consume the
reader and mask canonical low bits; invalid secret-output shapes clear the full
destination. Empty reads still validate phase and authority.

Every operation error terminates and clears the computation, even if a long
read has already produced some internal chunks. Failed secret reads clear the
whole destination; public destinations remain unchanged. Separate handle and
scope guards cover cancellation, Drop, forgotten states/readers and recoverable
unwind. Successful operations clear staging before returning. No secret length
or preflight query is exposed. Authority/revocation and deployment requirements
are unchanged, and none of this establishes complete compiler-copy, register or
spill erasure.

## KMAC framing prerequisite

The shared private KMAC packer now initializes its key-length encoding through
`&mut` storage rather than returning an initialized secret encoding. Framing
scratch is allocated before accepting secret bits, borrowed by the packer and
cleared by its guard and its own destructor. Bytepad no longer consumes that
storage. The final partial suffix is borrowed directly by a finalization callback,
not copied into a returned tail owner. Portable and accelerated KMAC use the
same helper, retaining bulk absorption and exact SP 800-185 bit framing.

This internal groundwork does not establish whole-framing register/spill
qualification. Integer calculations and compiler-created copies remain outside
the owned-memory claim. Existing constructors and parameter policy are unchanged.

## Scoped fixed KMAC

`brynja_mac_kmac::hardened_in_place::{Kmac128Workspace, Kmac256Workspace}`
own a portable cSHAKE workspace plus key-strength classification, verification
scratch and comparison accumulator. Construction accepts no secrets. `with` and
`with_bits` borrow storage before key/customization absorption and return an
outer setup result around the callback's result. Setup failure does not invoke
the callback or clear destinations it never received.

Handles support streaming updates, consuming byte/bit tag and secret-output
finalizers, verification, explicit cancellation and feature-gated conformance
methods. `verify_exact` additionally binds the public candidate bit length to the
application's expected length. Verification work depends on public candidate
length; callers must bound it at ingestion. No accumulated-message length or
preflight query is exposed. An update failure destroys the borrowed state and
clears metadata immediately, including a recoverable unwind caught by the caller.

An outer metadata guard and the underlying cSHAKE scope guard independently
cover forgotten handles. Finalization transfers only reference-bearing handles
into the cSHAKE reader. Secret-output errors clear the full supplied destination;
public errors preserve it. Typed secret output may outlive the scope, but not its
destination borrow. This does not change the older movable APIs. Scoped KMACXOF
readers and accelerated KMAC remain pending; these two workspaces are portable.

Tests cover all six fixed NIST examples, the fixed-output half of the existing
256-case independent arbitrary-bit corpus, 896 additional portable comparisons,
strength/shape failures, verification mismatches, forgetting, unwind and reuse.
Twenty-four compile-fail examples enforce trait/escape/overlap restrictions.
The existing packaged test rejects thirteen additional compiled regressions in
both debug/release profiles. This is development assurance, not independent
qualification or proof of complete register/spill erasure.

## Ownership and failure behavior

Storage is secret-free at construction and after every scope. During `with`, an
exclusive borrow prevents its semantic move or overlapping use. Finalization
moves only the reference-bearing handle. No new unsafe code, allocation, heap
pinning, thread support, feature default or dependency is required.

Handle finalization/cancellation/Drop clears every region of the existing
SHA-2 or FIPS 202 hardened owner in place. An outer cleanup guard independently clears
the owner on callback return or recoverable unwind, including `mem::forget` of
the handle. An update error clears and terminally disables the handle. Failed
secret finalization clears the entire destination; failed public finalization
leaves its destination unchanged. The workspace can be used for a new computation
only after the prior scope has ended and its guard has cleared storage.

Reader errors also clear and terminally disable their state, including a failed
secret read on an already consumed reader. Empty reads do not revive a failed
reader. Final-bit reads consume and clear the reader. The new scoped APIs expose
no accumulated input/output length or preflight length queries.

The final output owner still requires normal destruction; deliberately forgetting
that separate output owner defeats its Drop-based destination clearing. Abort,
process termination and interruption snapshots are outside the guarantee.

## What this does not establish

The existing movable hardened APIs retain their existing owned-memory guarantee.
They have not been silently upgraded. Scoped storage removes semantic moves of
the active owner but does not prohibit compiler-created copies or spills inside
an operation. Absorb/padding/squeeze paths still need separate qualification.
The private opaque permutation and secret-copy boundaries cover only their own
normal-return work. Callers' inputs, register state, caches, dumps and platform
storage are not erased by an ownership API.

This initial module uses the portable hardened implementation, including its
already implemented baseline scalar permutation ports. It does not enable an
optional hardware/SIMD route. The separate execution namespace above retains
explicit acceleration. Other accelerated scopes, other
hash families and higher constructions remain rollout work before the broader
F1 remediation can be declared complete. Release gates and publishing are unchanged.

## Development checks

All four identities are compared against existing byte/bit APIs over chunk sizes,
rate/padding boundaries and tail widths. Tests cover exact storage identity,
all-region clearing, bad output sizes, counter failure, cancellation, forgotten
handles, recoverable unwind and reuse. Forty-eight compile-fail examples reject
handle escape, overlapping workspace use and forbidden traits. A separate
downstream fixture checks the public API and a known-answer digest.

The four XOF identities additionally cover all input/output tail widths, arbitrary
N/S bits, mixed secret/public incremental output over multiple rate boundaries,
empty reads, reference-to-reader address stability, error-state destination
behavior, forgotten readers, unwind and reuse. Seventy-two additional compiled
negative examples cover workspace/state/reader traits, escape and overlapping
workspace use. These comparisons use the existing implementations, not a new
independent cryptographic oracle. The packaged downstream fixture also checks a
SHAKE128 known answer and all four XOF identities.

`python3 assurance/register-cleanup/check_in_place_sha3.py` executes positive
controls and six fixed-output plus eight XOF compiled lifecycle/output mutants
in debug and release. It is
a development driver, not a new release-gate mechanism. The existing workspace
test/doctest path exercises the in-crate tests without changing gate commands.

Its `--native-x86` option requires actual AVX2 execution and additionally rejects
eight fixed-output execution mutants and ten scoped XOF execution mutants in
debug/release, then runs a packaged accelerated consumer. The XOF cases remove
independent scope/handle cleanup, operation failure/success cleanup, terminal
destination guarding, customization, output masks or final shape validation,
or corrupt the absorbing-to-reader transfer. Seventy-six new compile-fail
examples reject forbidden workspace/state/reader traits, escaping borrows,
overlap and expired authority. Existing NIST SHAKE vectors and the 628-case
cSHAKE official/independent corpus exercise the new scoped output APIs. Native
AVX2 and emulated Arm checks are kept distinct from future native qualification.

For named SHA-2, `python3 assurance/register-cleanup/check_in_place_sha2.py`
checks all six identities against existing ordinary byte/bit implementations,
including padding boundaries, all tail widths, irregular chunking, invalid
destination sizes, counter failures, forgotten handles, unwind and reuse.
Seventy-two compile-fail examples enforce escape/overlap/trait restrictions.
The development driver rejects eight compiled cleanup, lifecycle, IV, output
and counter mutants in debug/release and tests the packaged downstream API,
including a SHA-256 known answer. These are not a replacement for independent
review or complete framing/register/spill qualification.

General SHA-512/t additionally checks all 510 parameters, all tail widths,
invalid destination widths, exact output identity, clearing and scope failure.
The existing independent 4,590-vector corpus now exercises the scoped API too.
Thirteen compiled negative examples cover ownership and secret/public type
separation. The development driver rejects eight additional compiled general-t
mutants in both profiles and tests all parameters through the packaged API.

Named execution scopes check six identities over byte/bit padding boundaries,
chunk sizes, work counts, all invalid destination widths, stable engine address,
clearing, terminal errors, forgotten handles, unwind and reuse. Seventy-eight
compile-fail examples also enforce authority lifetime, escape and forbidden
traits. The development driver includes six compiled execution cleanup/output/IV
mutants in debug/release. The packaged fixture's optional `execution` and
`hosted` features exercise the new API; required-ISA test switches prevent
silently counting unavailable routes as accelerated coverage. Native SHA-NI and
emulated Arm static/hosted runs are distinct from final native qualification.
The development driver's `--native-x86` mode first validates the Linux CPU
feature inventory, then rejects three additional compiled authority-recheck,
counter-reset and failed-state mutations in both profiles.

General-t execution scopes extend the 4,590-vector independent corpus to
portable and available static wide execution. Lifecycle tests check all 510
parameters, all eight tail widths, padding boundaries, exact report/parameter
identity, stable engine storage and clearing; focused tests cover failure,
forgetting, unwind, wrong-family admission and revocation. The same development
driver checks eight additional compiled cleanup, IV, mask, secret-identity,
destination and report mutants in both profiles. The packaged fixture tests
all parameters and available hosted wide execution. Emulated Arm results do
not substitute for native wide-kernel qualification.

Fixed-output SHA-3 execution scopes test all four identities, rate boundaries,
chunking, all eight input tail widths, exact engine/staging address stability,
destination failures, overflow, revocation, forgetting, unwind and reuse.
The existing curated NIST corpus additionally runs its 40 fixed-output vectors
through these scopes when the static route is available. Fifty-two compile-fail
examples enforce traits, escape/overlap and authority lifetime. The development
driver's `--native-x86` mode validates AVX2 support on every advertised Linux CPU
and rejects eight compiled cleanup, authority, phase, suffix and destination
mutants in debug/release. It also executes the packaged native consumer.
The fixture's hosted feature tests available hosted execution; mandatory-route
switches prevent treating an unavailable backend as accelerated coverage.
