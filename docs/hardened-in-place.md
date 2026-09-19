# Scoped hardened storage

Status: scoped named/general SHA-2, SHA-3/SHAKE/cSHAKE, KMAC/KMACXOF,
TupleHash/TupleHashXOF, ParallelHash/ParallelHashXOF and legacy SHA-1/MD5 APIs
are integrated development checkpoints. Remaining caller-copy/framing work and
complete register/spill qualification are pending. No independent verification
or FIPS claim.

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

The shared hardened execution engine now transfers input, padding, compression
blocks and output staging through the reviewed borrowed-copy helper. It retains
the partial input byte by reference and applies the public padding/output masks
through `apply_secret_byte_mask`; named public commits use borrowed copying too.
Public IV initialization and length metadata are unchanged. This removes those
explicit ordinary-copy sites, not caller-side bit-string validation copies or
all whole-API register/spill residue. Existing cleanup guards remain mandatory.

Handle and outer-scope guards independently clear hash storage, including
forgotten handles and recoverable unwind. Existing CPU operation guards clear
private scratch and retain their quarantine behavior. Neither the active engine
nor its scratch moves through finalization. General-t execution is described
below. Scoped higher constructions remain rollout work; this is not complete
register/spill qualification.

### Portable SHA-2 borrowed transfers

Portable hardened SHA-2 now uses `BitString::split_borrowed` for named and
general-t final input. The partial byte stays borrowed through padding; a
borrowed one-byte copy followed by public-mask insertion replaces the by-value
padding expression. Absorption, buffered/full compression blocks, padding and
digest staging also use the reviewed core copy helper. General-t final output
masking uses the borrowed mask helper for both moved and scoped owners.

The no-dependency hash-interface crate retains its ordinary `split` and
constructor unchanged. The added accessor preserves the backing allocation and
input lifetime; it does not make construction register-clean or erase caller
storage. Public IV/length metadata and explicitly declassified outputs retain
their existing contracts. Owned-region/scope cleanup still applies independently
of these transfers; complete API register/spill qualification remains pending.

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

The shared hardened accelerated sponge now absorbs bytes, partial input bits,
domain suffixes and padding through the reviewed borrowed XOR helper. Squeezing
copies rate-bounded slices through the borrowed-copy helper without returning
secret bytes by value. Named/scoped public commits and final-byte masks use the
same borrowed-copy/mask boundaries. Existing staging and operation guards still
govern failure cleanup; empty reads still check authority without advancing the
stream. These helper changes do not qualify caller-side bit-string validation,
cSHAKE prefix construction, portable sponge paths or whole-API register/spill
erasure.

### Borrowed FIPS 202 representation validation

`Fips202BitString::new` now borrows its final byte for canonicality validation
through core's `secret_byte_mask_is_zero`, rather than copying that byte into
ordinary Rust arithmetic. The public length/shape checks and errors are
unchanged. Validity is intentionally observable; the helper explicitly
declassifies only its Boolean predicate. Repeated arbitrary masks could reveal
all bits, so it is not an equality or secret-provenance barrier.

The baseline x86-64/little-endian Arm boundary reads exactly one byte, returns a
normalized predicate, clears its secret working register and sets condition
flags independently of input on normal return. Other targets and Miri/Kani use
a safe model. The development fixture checks all 65,536 byte/mask pairs,
immediate registers/flags, read-only page edges, compiler output and mutations.
Native x86 and QEMU Arm coverage is distinguished from compilation-only Apple,
Windows and Android coverage. This does not qualify complete API register/spill
erasure, caller copies, interrupted execution or platform storage. The
dependency-free MSB-first `brynja-hash-core::BitString` remains a separate
follow-up; this checkpoint neither changes its dependency graph nor claims to
remove its by-value validation/partial-byte transfers.

## Portable scoped ParallelHash and ParallelHashXOF

ParallelHash also now initializes integer framing through borrowed storage: its
portable sequential/scheduled roots and execution collectors create empty
encoding owners, fill them through `&mut`, and borrow the bytes for absorption.
Reuse clears the complete 17-byte encoding and length before writing; Drop clears
both. An empty or invalid encoding cannot be read. No populated encoding owner
is returned from initialization.

Portable ParallelHash leaf helpers now use scoped SHAKE128/256 storage and pass
the complete borrowed bit-string to finalization. The previous returned partial
tail array and populated leaf sponge moves are removed. The 32/64-byte leaf
output remains a typed borrow of the supplied destination.

`brynja_hash_parallel::hardened_in_place::{ParallelHash128Workspace,
ParallelHash256Workspace}` now retain portable root sponge storage, two 16-byte
counters and a 64-byte leaf-output region. Construct empty storage, then call
`with` or `with_bits` with a caller-owned nonempty block buffer; its length is B.
The scoped handle accepts complete-byte updates and consuming finalizers with
canonical-bit final input and output. Public finalization requires explicit
declassification and preserves its destination on errors; secret finalization
clears its whole destination on errors and returns a typed clearing output borrow.
The scope may return that separate output borrow, never its state handle.

Update failures are terminal. Cancelling/dropping a handle clears metadata and
the whole block. Independent outer guards clear them even if the handle is
forgotten or the callback unwinds; the borrowed cSHAKE scope clears its sponge.
No public count, accumulated-length or capacity-preflight query is provided.
Workspaces and handles are neither Copy/Clone/Debug nor Send/Sync. These additive
APIs do not replace the existing by-value APIs or enable acceleration by default.

`ParallelHashXof128Workspace`/`ParallelHashXof256Workspace` also expose scoped
absorbing handles and incremental readers. `finalize_xof`/`finalize_bits_xof`
append the zero output-length trailer, consume absorption and transfer only the
root sponge borrow. The counters, leaf-output region and block are cleared before
the first squeeze. Mixed secret/public byte reads retain the reader; a final
canonical-bit read consumes it. Public reads require explicit declassification.
Every read error terminates the reader, including subsequent empty reads, with
public preservation and secret-destination clearing. Cancellation/drop clears
the borrowed sponge; outer scope cleanup covers forgotten readers and unwind.
The same non-Copy/Clone/Debug/Send/Sync and no-scope-escape constraints apply.

Portable scoped scheduling uses `ParallelHash128CollectorWorkspace` and
`ParallelHash256CollectorWorkspace`, with empty root sponge/counter storage.
`with`/`with_bits` borrow storage for one existing exact-plan object; populated
root/counter owners are never returned. Existing plan leaf jobs already hash
through scoped portable SHAKE storage into separately borrowed secret outputs.
The new `merge` consumes those typed results, validates exact plan identity and
shape, enforces the next index, and clears each consumed output even on error.
Errors terminate the collector. Finalization requires the exact planned leaf
count and consumes the handle; public failures preserve destinations and secret
failures clear them.

Both fixed and XOF output are available. XOF transition clears the merge counter
before returning a scoped root reader; the independent outer guard also handles
forgotten collectors/readers and recoverable unwind. No accumulated-count or
preflight query is exposed on the collector. The existing plan's total shape and
job indices remain caller-visible, and leaf-result metadata is not yet a scoped
thread-handoff redesign. This is portable scheduling, not complete
register/spill qualification.

With the existing default-off `hardened-execution` feature,
`execution::in_place::ParallelHash128Workspace`/`ParallelHash256Workspace` now
provide scoped fixed-output acceleration. They take separate supplied root and
leaf Keccak sessions (which may borrow the same authority). Both sponges and
CPU scratch remain in caller-owned workspaces. An empty leaf scope checks its
authority between leaf computations; non-authorizing reports are not used for
admission. Updates, including empty updates, leaf work and finalization check
the original authorities. Any failure terminates without portable fallback.

Public output is transactional through 168 bytes of internal staging or the
caller staging passed to `with_scratch`/`with_bits_and_scratch`. Staging must cover
the destination; secret output has no staging-width restriction. Metadata, block
and supplied staging clear on all scope exits, including skipped callbacks,
forgotten handles and recoverable unwind. Setup cannot clear captured outputs
not yet passed to a state method. Non-authorizing `root_report`/`leaf_report`
contain route/health only. The new `ParallelHashError::Execution` retains the
underlying fixed failure category, not secret data.

The accelerated `ParallelHashXof128Workspace`/`ParallelHashXof256Workspace`
share the same root/leaf construction and four scope entry points. Consuming
XOF finalization clears absorption metadata, leaf output and block, retaining
only root and staging borrows in the reader. The completed leaf authority is
not used for squeezing; root revocation rejects even empty reads without
fallback. Public read errors preserve destinations, secret read errors clear
them, and both terminate the reader. Mixed public/secret reads and consuming
partial-bit reads use the same scoped output guard as portable XOF. Staging
bounds each public read, not the total stream, and does not limit secret reads.
Scope cleanup covers cancelled, forgotten and unwinding readers.

Explicit accelerated scheduling also provides `execution::in_place::ParallelHash128CollectorWorkspace`/
`ParallelHash256CollectorWorkspace` and separate `ParallelHash128LeafWorkspace`/
`ParallelHash256LeafWorkspace`. Roots bind one supplied session; leaf workspaces
bind their own, possibly from the same authority. Existing exact-plan jobs gain
only a crate-private execution adapter to preserve typed result provenance.
Public leaf execution clears its destination even if authority rejects before
entering the scope. A completed result borrows the plan and destination, not the
leaf workspace/authority. Later worker revocation cannot change those completed
bytes. Root merges/finalization and XOF reads check the root's authority.

Scheduled roots reuse the scoped counter/framing guard and transactional output
adapter. They expose built-in or caller public staging, consumed-leaf merge,
fixed output and borrowed XOF readers. Caller-selected portable/accelerated root
and leaf combinations remain explicit; neither supplied route falls back, and
root route reports do not attest which route produced every leaf. CPU admission,
authority lifetimes and thread restrictions are unchanged.

The portable std executor now exposes `with128`/`with256` and canonical-bit
variants for these collector workspaces. It retains the root on the calling
thread, computes bounded leaves in parent-owned disjoint clearing slots, joins
every started worker and consumes typed exact-plan results in order. The callback
receives a completed scoped collector only after successful collection and a
cancellation check. It can return a separately borrowed secret output, not a
root or reader. The shared nonblocking operation gate remains held throughout
the callback. Admission/worker failures skip it, so destinations captured only
by the callback are not cleared by this API. Recoverable callback unwinding
clears the workspace and poisons the executor gate; abort cannot run Drop.

This portable scoped handoff does not transfer sponge state or CPU authority
between threads and does not select acceleration. The separate opt-in
`brynja_hash_parallel_std::execution::in_place::Executor` now supports independent
root/leaf selection using the existing `Config`/`Request` contract. Each worker
constructs authority locally and uses a scoped SHAKE leaf workspace; the calling
thread retains its scoped cSHAKE collector. Parent-owned disjoint clearing slots
hold the typed leaf outputs until ordered merge. No authority or live sponge
state crosses a thread boundary. Fixed/XOF byte/bit output, explicit mixed
routes, cancellation, and typed failures preserve the existing no-fallback
contract. Secret admission failures clear destinations; public output is staged
and committed under the operation gate only after all workers have joined.
Reports count completed accelerated leaves rather than inferring acceleration
from preference alone. This does not qualify cached detection or VM migration.
Scoped multibuffer scheduling now has a typed result bridge under the existing
`hardened-batch-execution` feature: `ParallelHash128Plan::batch` and
`ParallelHash256Plan::batch` select exactly one to four contiguous leaves.
`execution::in_place::batch::{Batch128,Batch256}::execute_into` borrows the
worker-local clearing executor/workspace and transfers completed CVs into a
caller-owned `[[u8;64];4]`. Intermediate CVs and scratch clear before return;
no populated sponge owner moves. `Leaves128`/`Leaves256` are Send, not Sync,
Copy, Clone or Debug, and carry exact plan/index provenance, not live authority.
Portable and accelerated scoped collectors consume them with `merge_batch`.
Wrong plans, order errors and revoked roots reject terminally; every merge/drop
clears the entire result array, including inactive slots and short-CV tails.
Require rejects ineligible groups; Prefer permits scalar tails. Results report
actual vector participation without treating a requested route as proof of work.
The explicit bounded CV copy is between two clearing owners, not a declassification
or a promise to erase compiler-created copies. Forgetting a completed result
cannot run its Drop: a threaded scheduler must keep its own parent storage guard.
Completed CV loans now use the reviewed borrowed-copy helper, as do scoped and
execution streaming input buffers (including partial final bytes), collector
public commits and scoped threaded public commits. Existing guards still clear
source/transport/staging storage on failure or Drop. This removes those explicit
ordinary copy sites without changing provenance, scheduling or declassification
requirements; the helper's normal-return working-register claim is not a
whole-ParallelHash register/spill guarantee.
The std `execution::batch::in_place::Executor` supplies that parent guard under
the existing `runtime-batch-execution` feature. It creates authority and empty
workspace inside each worker, returns only completed exact-plan loans, and
merges them into a scoped coordinator-local root in submission order. Bounded
waves contain at most `workers` groups (one to four leaves each); thread count
is separate from SIMD width. All started workers join after failure or unwind.
The parent clears every byte of each allocated CV slot even if a result is
forgotten. No populated sponge owner or authority crosses a thread boundary.
The existing `Config`, `Request`, preferences and reports apply. Root and leaf
routes remain independent; Require rejects unavailable or incomplete groups,
Prefer permits scalar tails, and backend failures never authorize fallback.
Fixed/XOF byte/bit secret outputs clear on failure and Drop; public outputs
commit transactionally while the executor gate remains held and all staging
clears. Bounds cover workers, total leaves and per-group leaf permutations,
not root/output work. Allocation failure is reported, not silently retried.
Registers, spills and compiler-created
copies remain outside this checkpoint's guarantee; `panic = "abort"` cannot run
scope destructors.

## Legacy SHA-1 scoped workspace

`brynja_legacy_sha1::hardened_in_place::{Sha1Workspace,Sha1}` adds an allocation-free
portable workspace and borrowed handle. `with` restores only the public IV in
cleared storage before accepting input. The handle cannot escape its scope;
workspace and handle are neither Send, Sync, Copy, Clone nor Debug. The separate
scope guard covers forgotten handles and recoverable unwind. Existing by-value
states and accelerated APIs are unchanged; no modern facade gains legacy SHA-1.

The handle exposes byte updates, consuming byte/bit finalization to public or
typed secret destinations, and cancellation. Update failure clears and closes
the handle; later calls return `Sha1Error::StateConsumed`. There is no public
length/preflight oracle or snapshot. Public output needs explicit declassification
and is transactional. Secret initialization begins before finalization, so errors
and recoverable unwind clear even the supplied destination. A completed secret
output borrows only its destination and can outlive the workspace scope.

The six owned state regions use existing `Sha1Owner::wipe`; no populated owner
is returned by value through this API. The portable compression dispatch is
unchanged. Complete padding/output compiler-copy, register/spill qualification
remain pending. Forgetting a separate
output prevents its Drop, and abort cannot run guards. Memory hygiene never
repairs SHA-1's collision weakness or admits it for new security protocols.

With `hardened-execution`, `hardened_execution::in_place::Sha1Workspace<'authority>`
borrows an existing hardened executor. `new(&executor)` accepts no secret data;
`with` checks the same authority before handing out a borrowed
`Sha1<'scope, 'authority>`. Its outer result is admission, and its inner value is
the callback result. Scope admission cannot clear a destination captured only
by the callback: secret-output initialization starts on entering finalization.
Finalization and cancellation consume the handle; secret output can outlive the
scope, but neither the handle nor workspace can outlive its executor.

An independent scope guard clears all six owner regions even after `forget`.
Operation and handle guards clear failures immediately. A length rejection
terminates this computation without revoking healthy sibling users; backend
failure, broken invariants and recoverable callback/operation unwind quarantine
the shared executor. Reuse cannot recover quarantined authority or silently
fall back to portable. Existing CPU scratch cleanup remains per-compression.
The original by-value APIs, static deployment guarantees and hosted feature
detection caveats are unchanged. This additive API is not whole-API register,
spill or compiler-copy qualification. Scoped MD5 SIMD batching is described below.

## Legacy MD5 scoped workspace

`brynja_legacy_md5::hardened_in_place::Md5Workspace` owns the five existing
clearing regions. `with` lends a non-Send/non-Sync `Md5` handle; the parent
cleanup guard remains outside that handle, including after `mem::forget`.
Initialization restores only the public little-endian MD5 IV directly in
cleared storage. Updates never move a populated owner and fail terminally.
Consuming public/secret byte and bit finalization and cancellation mirror the
portable scoped SHA-1 contract. Public failures preserve output; secret errors
and recoverable unwind clear the entire destination before returning control.
The returned secret owner borrows its destination independently of the scope.

MD5 retains checked u128 message accounting, with the low 64 bits encoded in
little-endian padding; this is not SHA-1's u64 admission rule. There is no public
capacity/length oracle, snapshot, reset or ordinary-state conversion on the new
handle. Existing by-value APIs, kernels, feature defaults and batch authorities
are unchanged. This is portable single-message storage; full
register/spill/compiler-copy qualification remains pending. MD5 remains collision- and chosen-prefix-broken, not an authentication
primitive, and abort cannot run cleanup guards.

The opt-in `hardened_execution::in_place::{Workspace, Batch}` separately provides
scoped eight-lane MD5 SIMD storage borrowing the existing hardened executor.
Its parent guard clears even forgotten handles; public/secret outputs preserve
the existing work, selection, cancellation and quarantine contracts. See
[hardened MD5 batching](legacy-md5-hardened-execution.md).

## Borrowed transfer follow-up

The shared single-message SHA-1/MD5 engines and SHA-1 hardened execution engine
now absorb bounded slices through the reviewed borrowed-copy helper. Their
partial final bytes remain borrowed through padding via `split_borrowed`;
padding masks and final state-to-staging transfers use the borrowed helpers too.
The portable engines retain their pre-write fail-stop offset assertions and
checked message-length admission. MD5's u128 accounting and low-64-bit
little-endian length encoding are unchanged. Existing by-value and scoped APIs
share these engine changes, without changing their signatures or output policy.
The MSB-first input constructor, public length metadata and complete
caller/compiler-copy/spill qualification remain separate open work.

`python3 assurance/register-cleanup/check_legacy_transfers.py` is a development
driver, not a new release gate. It rejects twelve compiled input/tail/staging
copy omissions and padding corruptions in each debug/release profile. The MD5
tests include fifteen frozen independent-oracle partial-bit answers so a shared
engine regression cannot pass merely by comparing two equally broken paths.
SHA-1 retains its NIST bit vectors; both independent bit-oracle campaigns remain
separate checks.

`brynja_core::copy_secret_region` exposes the existing checked transfer routine
for already-owned disjoint byte regions. It preserves both regions on a length
mismatch, accepts empty transfers and never takes over cleanup or declassifies
data. SHA-224/256 and SHA-512-family hardened batching now use it for lane packing/unpacking,
message blocks, scalar-state transfer, padding-block transfer, digest staging,
final destination commit and explicitly authorized declassification. Both output
paths preflight every slot before writing; consumed secret outputs still clear
their originals. Prepared source borrows do not copy the digest bytes.
SHA-2 batch partial-bit padding and SHA-512/t final-byte masking also use
`apply_secret_byte_mask` with public masks and borrowed byte storage. Complete
input views use metadata-only slicing instead of `BitString::split`, avoiding
an internal by-value partial byte. Public IV/count setup remains ordinary public
computation. Other families, input-construction validation and higher-level
callers remain separate obligations. Normal-return working-register evidence
for these helpers is not whole-API residue qualification.

Hardened SHA-3/SHAKE/cSHAKE batching also uses the borrowed helper for scalar
state transfer, SIMD lane gathering/scattering, squeeze staging, final output
commit and explicit declassification. Canonical partial-output bytes use the
public-mask helper. Commit prepares all source slices before any destination
write, including sparse slots and empty XOF outputs. An unexpected transfer
invariant retains executor quarantine; ordinary request rejection remains
reusable.

Batch absorption now uses `brynja_core::xor_secret_byte_bits` to XOR low-bit-first
fragments from disjoint borrowed bytes directly into the owned state. Public
source/destination offsets and bit counts are validated before access. Fragments
crossing source-byte boundaries are split without returning or assembling a
secret byte in Rust. Public suffix/padding bytes retain their existing framing.
The helper's baseline x86-64/little-endian Arm boundary clears working registers
on normal return; the safe portable/Miri/Kani model does not have that register
guarantee. Input construction, other callers and whole-API compiler-copy/spill
qualification remain separate unfinished obligations.

The portable hardened SHA-3/SHAKE owner also uses borrowed copies for partial
input buffering, fixed-digest staging, rate-bounded XOF output and public digest
commits. Partial-output masks operate on borrowed bytes. Squeezing returns only
public cursor indices internally, not secret bytes by value; empty reads do not
advance the sponge, and invalid staging/cursor ranges fail before writing.
Existing secret-output initialization and cleanup guards remain responsible for
destination ownership. Portable absorption XOR, padding copies, partial-input
masks and public suffix/padding-bit insertion now also use borrowed helpers.
Affine and scoped SHA-3/SHAKE/cSHAKE finalizers retain the original tail borrow
instead of receiving its byte by value. Equal-length copies and constant
full-byte XOR ranges cannot reject, preserving infallible finalization without
discarding a caller-controlled range error. Tests check all 65,536 byte-pair XORs
and 2,880 padding/chunk/rate/domain combinations, including suffix spillover.
The shared cSHAKE prefix packer now borrows a caller-local pending byte instead
of owning populated byte storage by value. Its guard clears that exact byte on
success, error and recoverable unwind. Unaligned input is combined with borrowed
bit-fragment XOR; aligned input retains its direct bulk-absorption path. Input
tail selection borrows the canonical source byte without calling the by-value
split helper. Emitted-byte counters are checked before each sink invocation.
Input construction and other higher-level callers still require separate
follow-up; this is not whole-API register or compiler-spill qualification.

## TupleHash integer framing


The private TupleHash integer encoder is constructed empty, then filled through
`&mut` for `left_encode(item_bits)` and `right_encode(output_bits)`. Both the
portable and accelerated paths borrow those bytes rather than receive populated
encoding owners by value. Reuse clears the entire 17-byte region and its length
before writing, and Drop clears both regions. Empty or invalid encoded lengths
fail closed. This removes that explicit owner-return transfer, not every possible
compiler-created copy of length metadata. Scoped portable and accelerated
TupleHash/XOF workspaces use this encoder; complete register/spill qualification
remains unfinished.

## Scoped fixed TupleHash

`brynja_hash_tuple::hardened_in_place::{TupleHash128Workspace, TupleHash256Workspace}`
construct secret-free portable storage with `new`/`Default`. `with` and
`with_bits` borrow sponge and metadata before absorbing the customization with
the exact `TupleHash` cSHAKE function name. The outer result covers setup; the
callback receives a scoped `TupleHash128` or `TupleHash256` handle.

Handles accept whole byte/bit items or `begin_item(bit_length)`. The returned
`TupleHash128ItemWriter`/`TupleHash256ItemWriter` exclusively borrows the parent,
accepts byte/bit fragments and requires explicit exact-length `finish`.
Dropping or cancelling an unfinished writer immediately clears its parent.
Forgetting a writer leaves the parent incomplete, even if all declared bits
were supplied: subsequent operations cannot produce output and scope exit
still clears storage. Overlong fragments, incomplete completion, checked length
overflow and other errors clear and terminate, rather than permitting retry.

`finalize_secret`/`finalize_secret_bits` consume the handle and return the existing
typed `TupleHashSecretOutput` borrowing a separate destination. Bit finalizers
take a slice and valid-bit count so invalid shapes also clear secret destinations.
`finalize_public`/`finalize_public_bits` require `TupleHashPublicDeclassification`
and preserve public destinations on error. There are no accumulated-length,
item-count, remaining-length or preflight queries. Empty items are distinct from
an empty tuple; non-byte-aligned items retain bulk absorption for subsequent
byte fragments. State, workspace and writers are not Copy/Clone/Debug/Send/Sync.

Independent scope cleanup covers forgotten handles and recoverable unwind.
Caller inputs, compiler-created copies, registers/spills and abort remain outside
the owned-memory claim. Existing APIs, defaults and acceleration authority are
unchanged. Scoped accelerated fixed-output counterparts are described below;
accelerated scoped XOF remains unfinished.

## Scoped TupleHashXOF

`hardened_in_place::{TupleHashXof128Workspace, TupleHashXof256Workspace}` reuse
the fixed workspaces' portable storage, customization and exact-length writer
discipline. `with`/`with_bits` expose `TupleHashXof128`/`TupleHashXof256`; these
accept `push_item`, `push_item_bits` and `begin_item`. `finalize_xof` consumes the
state, appends `right_encode(0)` and transfers only references into the matching
`TupleHashXof128Reader`/`TupleHashXof256Reader`. Open, incomplete or forgotten
writers cannot authorize this transition.

Readers provide incremental `squeeze_public` (explicit declassification) and
`squeeze_secret` (typed clearing output). Consuming `squeeze_final_bits_public`
and `squeeze_final_bits_secret` take a destination and valid-bit count: zero
for empty output, 1..=8 otherwise. Partial output is canonical; public failures
preserve destinations, while secret failures clear the entire destination even
on invalid shape or an already terminated reader. Empty reads also enforce
terminal state. Dropping/cancelling readers clears their borrowed storage;
independent outer scope guards also cover forgotten handles and recoverable
unwind. A secret output borrowing separate storage may outlive the scope.

Workspace, state and reader are not Copy/Clone/Debug/Send/Sync; neither state nor
reader can escape or overlap its scope. No secret-length or item-count query
is added. This is portable owned-memory lifecycle coverage, not complete
register, spill or compiler-copy erasure. Abort and caller-owned inputs remain
outside the guarantee. Existing accelerated APIs remain separate and unchanged.

## Scoped accelerated TupleHash and TupleHashXOF

The default-off `hardened-execution` feature exposes
`execution::in_place::{TupleHash128Workspace, TupleHash256Workspace}`, also
available under `hardened_in_place::accelerated`. Construction takes an existing
hardened `KeccakSession`, accepts no secret input and retains that authority for
every scope. Static and hosted platform guarantees are exactly the existing
cSHAKE guarantees; no new CPU feature detection, admission or fallback is added.

`with`/`with_bits` borrow the accelerated sponge, CPU scratch and seven-region
tuple metadata before customization or item absorption. Fixed handles expose
the same exact-length item-writer and consuming public/secret finalizers as
portable scopes. `report` exposes only existing public backend/health metadata,
never accumulated message lengths or item counts. State/workspace/writer are
not Copy/Clone/Debug/Send/Sync, cannot escape their borrows, and cannot outlive
the supplied authority.

Transactional public output requires scratch for the entire destination: the
default scope supplies 168 bytes, while `with_scratch` and
`with_bits_and_scratch` borrow caller-provided arbitrary-width staging. A short
scratch region rejects output without partial public writes; the complete
scratch slice clears on every scope exit. Secret output is independent of
public staging width, clears destinations on errors and clears on typed-output
Drop. Invalid bit shapes are checked before output, including empty buffers.

Caller mistakes terminate the computation, not the healthy authority. A fresh
scope may reuse healthy storage after cancellation, failure, forgotten handles
or recoverable callback unwind. Revocation remains terminal for that authority:
current operations fail and later scopes reject without invoking the callback.
Admission failure cannot clear a destination that the callback never supplied.
This prevents explicit secret-owner moves but does not prove register, spill or
compiler-copy erasure; abort and caller input remain outside the guarantee.

`execution::in_place::TupleHashXof128Workspace`/`TupleHashXof256Workspace`
retain the same supplied session and scope storage. Their consuming
`finalize_xof` writes `right_encode(0)` and transfers only the storage borrow
into the reader. Readers support mixed incremental `squeeze_public` and
`squeeze_secret`, followed by consuming `squeeze_final_bits_public` or
`squeeze_final_bits_secret`. Each public fragment must fit the scope's staging;
total output can exceed it across multiple reads. Secret output is typed and
does not need matching public staging. Short staging, invalid output shapes and
revocation preserve public destinations or clear secret destinations and
terminate the affected handle. Empty reads do not revive failed readers.
Reader Drop/cancel, forget and recoverable unwind retain the outer scope's
cleanup guarantee. No state/reader can escape the scope or supplied authority;
this is still not whole-API register/spill/compiler-copy qualification.

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
destination borrow. This does not change the older movable APIs. These two
workspaces are portable; accelerated KMAC scopes are described below.

Tests cover all six fixed NIST examples, the fixed-output half of the existing
256-case independent arbitrary-bit corpus, 896 additional portable comparisons,
strength/shape failures, verification mismatches, forgetting, unwind and reuse.
Twenty-four compile-fail examples enforce trait/escape/overlap restrictions.
The existing packaged test rejects thirteen additional compiled regressions in
both debug/release profiles. This is development assurance, not independent
qualification or proof of complete register/spill erasure.

## Scoped accelerated fixed KMAC

With `hardened-execution`, `brynja_mac_kmac::execution::in_place` provides
`Kmac128Workspace` and `Kmac256Workspace`. `new(session)` accepts the same
explicit hardened `KeccakSession` used by existing execution APIs, before any
secret input. `report()` contains only backend/health metadata. Each scope
rechecks that exact authority; quarantine is never revived and no fallback is
introduced. The hosted/static platform trust requirements are unchanged.

`with`/`with_bits` and their conformance counterparts expose borrowed states
with the portable fixed-scope update, public-tag, typed-secret-output, exact
verification and cancellation API. Public tags require transactional staging:
the default scope provides 168 bytes. `with_scratch` and
`with_bits_and_scratch` accept caller staging for larger tags; scratch must
cover the entire destination and is fully cleared even on setup rejection or
recoverable unwind. `with_bits_and_scratch_conformance` supports weak/partial
test keys behind the existing conformance feature. Secret output and chunked
verification do not have the public-staging limit. Setup rejection skips the
callback and cannot clear captured output buffers it never received.

Only borrowed sponge/staging handles move at finalization. Independent metadata,
staging and cSHAKE scope guards clear on exit, including forgotten handles.
This does not establish complete register/spill erasure.

### Accelerated KMACXOF readers

The same execution module provides `KmacXof128Workspace` and
`KmacXof256Workspace`, with matching authority-bound `new`, `report`, byte/bit
scopes and caller-scratch scopes. Their absorbing handles finalize into borrowed
`KmacXof128Reader` / `KmacXof256Reader` handles using `right_encode(0)`.
Production finalizers reject weak keys even when setup used a conformance scope.

Readers expose incremental `squeeze_secret` and explicitly declassified
`squeeze_public`, consuming `squeeze_final_bits_secret` /
`squeeze_final_bits_public`, `cancel` and non-approved service status. There are
no message/output length or preflight queries. Secret output may outlive the
computation scope through its separate destination lifetime.

Each public read must fit the scope's staging (168 bytes by default); use
`with_scratch` or `with_bits_and_scratch` for larger transactional fragments.
Staging is reusable across successful reads. Insufficient staging, revocation
or another read failure clears and terminalizes the computation: a subsequent
secret read clears its supplied destination and fails, including empty reads.
Final-bit reads consume the reader, including on invalid shape. An outer scope
guard also covers forgotten readers and recoverable unwind. Existing inline-owner
APIs are unchanged, and complete register/spill qualification remains pending.

## Scoped KMACXOF

`KmacXof128Workspace` and `KmacXof256Workspace` reuse the fixed KMAC setup scope
without moving initialized storage. `finalize_xof` / `finalize_bits_xof` consume
the absorbing handle and append `right_encode(0)`, returning a reader that keeps
the original sponge and metadata exclusively borrowed. Production finalizers
still reject weak keys introduced through feature-gated conformance setup.

Incremental `squeeze_secret` returns typed output; `squeeze_public` requires
`KmacPublicDeclassification`. Both permit empty reads and crossing rate boundaries.
The consuming `squeeze_final_bits_secret` / `squeeze_final_bits_public` methods
take a destination slice and valid-tail width, so malformed secret destinations
can be cleared before returning an error. Public errors preserve destinations.
No accumulated-length/preflight query is exposed. An operation guard immediately
drops a failed reader and clears metadata on errors or recoverable unwind;
empty follow-up reads are also rejected. Scope exit independently covers forgotten
readers. These scopes are portable, not an accelerated dispatch change.

The six official XOF examples and the XOF half of the existing independent
256-case campaign exercise these scoped outputs. Another 128-case comparison
checks partial keys/customization/messages, all tail widths and mixed reads
across rate boundaries. Thirty-six new compile-fail examples enforce workspace,
state and reader traits, escape and overlap. Packaged tests reject nine new
compiled XOF regressions in debug/release, including trailer/key errors, revoked
reader reuse, omitted metadata/destination clearing and lost success transitions.
Compiler-copy/framing/register/spill qualification remains unfinished.

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
