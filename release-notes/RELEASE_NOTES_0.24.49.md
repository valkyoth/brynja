# Brynja v0.24.49

Release candidate: dedicated x86 SHA-512 execution, bounded opaque-kernel
register cleanup, scoped owners and the separate strict-only facade.
Both owner-supplied retests are recorded in the
[pentest ledger](../security/pentest/v0.24.49.md): no open Critical/High/Medium/Low
findings; F1 is closed at the opaque-kernel boundary, not as whole-call erasure.
Native Linux Intel/Arm, Apple M2 and Windows MSVC runtime collections passed.
Linux strict portable/accelerated sessions passed; Apple/Windows strict sessions
reject as designed, with support planned for v0.24.51/v0.24.50 respectively.
Dedicated x86 SHA512 has SDE evidence only, not native-silicon qualification.
Final local release verification and GitHub approval remain pending.
No crates are selected for publication. The incremental implementation notes
below are historical; their pending-retest/integration wording is superseded by
this status. Caller/platform residuals and informational instrumented-build
limitations remain in force.

- Add the separate `brynja-strict` facade over protected modern SHA-2,
  SHA-3/SHAKE/cSHAKE, KMAC, TupleHash, ParallelHash and batch sessions. Its
  dependencies remain protected with default features disabled; no raw CPU,
  ordinary, generic callback or legacy API is exported. Existing `brynja`
  defaults are unchanged. Unsupported targets/resources reject, and explicit
  compiled selection still needs a valid deployment guarantee. This is not
  certification; independent retest and native qualification remain pending.

- Complete the separate default-off strict profile across scalar and compiled
  SHA-2, SHA-3/SHAKE/cSHAKE, KMAC, TupleHash, isolated legacy SHA-1/MD5,
  modern SIMD batches and protected ParallelHash root/worker execution.
  Protected GNU/Linux resources are acquired before secret processing;
  unsupported targets reject instead of inheriting weaker portable guarantees.
  Eager `mlock2` requires Linux 4.4/glibc 2.27+. All started workers join before
  protected stacks, CVs, staging and outputs are cleared. Kernel failure remains
  terminal even if cancellation is concurrently requested. No release-gate or
  publication policy changed. The [consolidated contract](../docs/strict-hardening-profile.md)
  supersedes incremental pending-integration notes below; independent retest and
  final native qualification are still required, with no whole-process or
  arbitrary-interruption register-erasure claim.

- Add portable `brynja_legacy_md5::hardened_in_place` workspace/handle APIs,
  with consuming byte/bit finalization and cleanup after errors, forgotten
  handles and recoverable unwind. Failed updates close the scoped state; no
  public length/preflight oracle is exposed. MD5's checked u128 accounting
  and low-64-bit length padding remain unchanged. Scoped SIMD batching is
  implemented separately below; complete register/spill erasure is not claimed.

- Add `hardened_execution::in_place::Sha1Workspace` borrowing an existing
  portable/static/hosted hardened executor. Active state stays in borrowed
  storage; scope cleanup covers forgotten handles, and operation unwind clears
  secret output and quarantines authority. Length rejection clears and closes
  the computation without revoking a healthy executor. No route, CPU admission
  or release workflow changes; complete register/spill qualification is pending.

- Add `brynja_legacy_sha1::hardened_in_place` workspaces and borrowed handles.
  Consuming byte/bit finalization preserves public destinations on error or clears
  secret destinations, including recoverable unwind. Scope cleanup covers
  forgotten handles; failed updates terminate the handle without a length oracle.
  This portable profile is not new algorithm admission or complete register/spill
  erasure. The separate scoped execution profile is described above; existing
  by-value APIs are unchanged.

- Remove populated integer-encoding returns from portable and execution
  ParallelHash framing, and use scoped SHAKE storage in portable leaf hashing.
  Encodings clear on reuse/drop; leaf output remains a typed destination borrow.
  Add portable scoped fixed-output ParallelHash128/256 workspaces, byte/bit
  customization and final input, consuming public/secret output and independent
  cleanup on cancellation, forgotten handles and recoverable unwinding.
  Portable scoped XOF readers now retain the root borrow through incremental
  secret/public and consuming final-bit output, with immediate absorption-region
  clearing and terminal read errors. Scoped accelerated fixed-output workspaces
  now bind separate hardened root/leaf sessions and borrowed public staging,
  with checked revocation and no fallback. Accelerated XOF readers retain root
  authority after leaf completion, with terminal errors, mixed public/secret
  reads and consuming final-bit output. Portable scoped scheduled collectors
  now borrow root/counter storage for exact-plan fixed/XOF completion, consuming
  and clearing each ordered leaf result. Accelerated scheduled roots and separate
  leaf workspaces now preserve the same plan/order and cleanup contracts with
  explicit supplied sessions. Portable scoped thread handoff now keeps the root
  on the calling thread and joins bounded workers returning borrowed typed leaf
  outputs before the completion callback. A separate scoped execution adapter
  now constructs accelerated root/leaf authority locally on its executing thread
  and joins workers returning only completed output borrows. Typed multibuffer
  leaf jobs now return clearing exact-plan result loans for scoped collector
  merging. The std scoped multibuffer scheduler now uses bounded worker-local
  authority/workspaces, independent parent clearing slots and an ordered scoped
  root. It joins every started worker before returning and commits staged public
  output under the operation gate. Complete compiler-copy/register/spill
  qualification remains unfinished.

- Add checked borrowed secret-region copying for already-owned storage and use
  it in SHA-224/256 and SHA-512-family hardened batch state, block, digest-staging and final-output
  transfers, including explicit declassification. Full-slot preflight preserves
  transactional public output; consumed secret outputs retain clearing on Drop.
  Exact-length failures preserve storage; callers retain cleanup responsibility.
  This is partial caller-copy remediation, not whole-API residue qualification.
- Add a borrowed-byte mask helper with baseline x86/Arm opaque boundaries and
  safe portable models. SHA-2 hardened batches use it for bit-tail padding and
  general SHA-512/t output masks without materializing the byte in Rust. Exact
  byte bounds, working-register cleanup and mutation regressions have development
  evidence; caller copies/spills and final native qualification remain separate.
- Add scoped hardened MD5 SIMD batches in caller-owned eight-lane workspaces.
  Consuming public/secret output reuses the existing engine, exact work accounting
  and quarantine policy. Independent scope cleanup survives forgotten handles;
  ordinary request rejection preserves executor reuse. No complete compiler-copy,
  register/spill erasure or repair of MD5's collision weakness is claimed.
- Add scoped accelerated TupleHashXOF128/256 workspaces and readers. Supplied
  Keccak authority stays borrowed through incremental and partial-bit output;
  scope cleanup covers forgotten readers and recoverable unwinding. Errors are
  terminal and preserve public output or clear supplied secret destinations.
  No fallback, CPU admission or release-gate behavior changes.

- Extend scoped storage to all six named SHA-2 identities, with exact-IV reset,
  byte/bit input and typed secret output. Update failures clear and terminate
  the scoped state. General SHA-512/t now has a parameter-bound scoped workspace,
  typed secret output and all-parameter oracle coverage. Six named execution
  workspaces and a parameter-bound general-t execution workspace now retain
  the engine and CPU scratch in place with existing
  static/hosted authority. Other accelerated scoped APIs are described below;
  no whole-register/spill guarantee is claimed.
- Add `brynja_hash_sha3::hardened_in_place` for scoped SHA3-224/256/384/512,
  SHAKE128/256 and cSHAKE128/256 workspaces. Handles and readers borrow the active
  owner; finalization does not move that
  owner. Independent scope cleanup covers forgotten handles and recoverable
  unwind. Existing by-value APIs remain unchanged. See the
  [in-place contract](../docs/hardened-in-place.md); complete
  framing/register/spill erasure is not established by scoped ownership.
- Add scoped fixed-output SHA-3 and SHAKE/cSHAKE execution workspaces with explicit existing
  static/hosted sessions, in-workspace output staging and no owner moves through
  finalization. SHAKE/cSHAKE readers transfer the storage borrow and support mixed
  secret/public reads, byte/bit domains and consuming partial-bit output.
  Authority/revocation behavior is unchanged; complete residue qualification
  remains pending.
- Add an isolated first-party SHA512/AVX2/AVX intrinsic kernel and exact static/raw
  runtime identity, with real startup KAT and irreversible quarantine.
- Initialize KMAC key-length encoding through a borrow and finalize its partial
  suffix through a callback borrowing the original framing scratch. Both
  portable and accelerated KMAC use this internal boundary; public APIs and
  output bytes are unchanged. Add portable scoped fixed KMAC128/256 workspaces
  borrowing cSHAKE storage before key input, with typed secret output,
  constant-time verification, exact-length verification and independent cleanup
  for forgotten handles and recoverable unwind. Scoped KMACXOF128/256 readers
  add zero-trailer framing, mixed secret/public reads, consuming partial-bit
  output and immediate terminal cleanup. Accelerated fixed KMAC and KMACXOF scopes bind
  the existing Keccak authority and borrowed staging for transactional public
  tags and XOF fragments. The bounded KMAC and wider caller/worker author reviews
  are complete; they do not establish complete framing/compiler residue erasure.
- Add portable scoped fixed TupleHash128/256 workspaces and exact-length item
  writers. Sponge/metadata storage is borrowed before customization and item
  input; consuming secret/public finalizers transfer only references. Terminal
  errors and independent scope cleanup cover abandoned or forgotten writers,
  cancelled handles and recoverable unwind. Integer prefixes/trailers initialize
  borrowed storage. Portable scoped TupleHashXOF128/256 readers now retain that
  borrow through incremental public/secret and consuming final-bit output, with
  right_encode(0) framing. Scoped fixed/XOF accelerated TupleHash binds the supplied
  hardened Keccak session and borrowed transactional staging without fallback.
  Complete compiler-copy/register/spill qualification remains pending.
- Connect all ordinary SHA-512-family APIs, including every general-t identity;
  add distinct owner-backed hardened compression without ordinary scratch reuse.
- Preserve generic portable defaults, AVX2 batch routes and the hosted x86
  migration restriction. SHA-NI or AVX-512 alone never authorizes this kernel.
- Record Intel SDE development correctness separately from absent native CPU
  qualification. Keep Rust 1.90 support and no additional dependencies.
- Address pentest instruction-entry, checked-domain, quarantine-reporting and
  automated-coverage findings with private permits, fallible helpers, compiled
  fault probes, explicit ignored tests and a separate path-filtered SDE job.
  Register remnants remain outside the owned-memory clearing guarantee.

See the [API and acceptance status](../docs/x86-sha512-execution.md).
The [pentest handoff](../assurance/register-cleanup/pentest-handoff.md) reconciles
the implemented ports, compiler/ABI matrix and retained evidence without
conflating author checks with independent retest or native qualification.
The supplied retest closed F1 at the opaque-kernel boundary. The implementation
rollout is not a whole-call erasure proof.
Both compiler endpoints pass development instruction, owner-cleanup and SDE
checks; packaged consumers, five compiled kernel mutants, ten cleanup/identity
mutants and startup/route probes pass. Generic CPU Miri and emulated ASan/LSan
also pass; neither establishes native instruction qualification. Shared assurance
metadata, full workspace tests/doctests, Clippy, documentation and dependency
isolation checks pass. Owner retests and native runtime collection have since
completed; final evidence integration and release verification remain pending.
No release-gate or evidence-reuse policy
changes.
