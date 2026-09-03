<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://crates.io/crates/brynja">Crates.io</a>
  |
  <a href="https://docs.rs/brynja">Docs.rs</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md">Release Plan</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md">Threat Model</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <a href="https://github.com/valkyoth/brynja">
    <img src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja security-first Rust cryptography and secure protocols overview">
  </a>
</p>

# brynja-core

`brynja-core 0.9.0` carries the cumulative v0.18.1 bounded observational
security-event schema, v0.18 mandatory security-outcome authority contract,
v0.17 FIPS-aware provider architecture, v0.16
pending-operation lifecycle, v0.15 typed wall and monotonic
clock contract, v0.14 entropy and initialized
secure-random contract, v0.13.1 CPU-backend capability and dispatch contract,
and v0.13 provider capability and opaque-handle
contracts alongside the v0.12 constant-time foundation, v0.11
owned-memory zeroization implementation, v0.10 abstract secret-lifetime
contract, and transactional foundations from earlier milestones. Version
`0.9.0` was published at v0.20.0 after the cumulative pentest, remediation
retest, and hosted release gates recorded `PASS`/`PASS`
with zero open findings.

Every arithmetic operation is checked independently of build profile.
Sequence and epoch exhaustion cannot wrap or reuse zero. Budget checks return
the existing typed, limit-value-free exhaustion result without mutating the
budget. Every resource limit is supplied exactly once through a named builder
method; duplicate and incomplete assignments fail with a typed domain-specific
error. Numeric values and budget types intentionally implement neither `Debug`
nor `Display`; the fixed, valueless `NumericError` enum implements `Debug` for
safe diagnostics. `ReadCursor` borrows caller input, advances only after an
exact checked range is available, returns borrowed slices and array references,
and consumes itself when `finish` checks for trailing data. It is not clonable
or formattable, and its value-free errors reveal no input, offset, requested
length, or available length. `WriteCursor` exclusively borrows caller output
and preflights complete single-slice, multi-part, and repeated-byte operations
before changing any byte. Failure preserves the complete buffer and position;
exact completion consumes the cursor. `Workspace` safe-splits one exact-size
caller buffer into named secret, plaintext, transcript, certificate, and output
arenas. Sealed zero-sized domain markers prevent the five simultaneous handles
from being swapped. Complete monotonic allocations track used, remaining,
high-water, and successful non-empty allocation count; rejection preserves both
bytes and telemetry. Allocated bytes retain their caller contents and must be
initialized completely before any read. `SecretDomain` is only a storage
classification, and `CertificateDomain` is not private-key storage. Sensitive
use remains prohibited until the v0.11 proven destruction primitive exists.

`SecretInitialization` is an affine write-acknowledgment state: only exact
complete initialization can produce the non-clonable, non-formattable abstract
`SecretState`. Every partial-init exit, live drop, explicit obsolescence, or
replacement invokes configured local-memory, external-store, accelerator,
cache, and DMA duties. Every configured duty is attempted; any failed duty
produces a terminal failure. Explicit transitions return that failure. Because
`Drop` cannot return it, `SecretDestructor::handle_drop_failure` must make it
durable or initiate a platform fail-stop response before returning; returning
is itself a security assertion that silent continuation is impossible under
the operating contract. The state contains no secret bytes and exposes no
read operation. A destructor completion token is a security assertion by its
caller, not proof of erasure, and this crate intentionally supplies no
production local-memory destructor before v0.11.0.

v0.11 adds `SecretRegionInitialization` and `OwnedSecretRegion` around one
non-empty, exclusively borrowed caller allocation. Admission clears all prior
bytes; sequential writes are failure-atomic; only exact complete initialization
becomes readable; and incomplete finish, initialization Drop, explicit owner
clear, and owner Drop clear the entire allocation through a per-byte volatile
zero store plus compiler barrier. One private 23-line module contains the only
unsafe block. Repository policy rejects every other core unsafe site, while CI
checks MIR, LLVM IR, and assembly for Rust 1.90.0 through 1.98.1 and all nine
promised targets, then runs the secret-memory tests under pinned Miri and
AddressSanitizer. The guarantee stops at that Rust allocation: registers,
copies, caches, DMA-visible copies, dumps, suspend images, physical memory,
concurrent access, forgotten owners, and terminated processes remain outside
scope and need platform-specific duties. This is not integer encoding, TLS
framing, a protocol parser, a TLS state machine, cryptography, PKI, a provider,
or a production-ready transport.

v0.12 adds normalized one-byte `Choice` and `CtMask` values; constant-time
equality, conditional selection, and conditional swap for every unsigned word
width and compile-time-sized byte array; and an explicit compiler barrier.
Private representations prevent mask forging, ordinary equality and formatting
are unavailable, and `Choice::expose_public` is the single named
declassification boundary. Exhaustive byte-pair tests, word-boundary tests,
array mismatch-position tests, compile-fail examples, a hash-locked source
policy, and optimized LLVM/assembly witnesses cover Rust 1.90.0 through 1.98.1
and all nine promised targets. The emitted-code evidence is a bounded witness,
not a formal proof, statistical timing test, or microarchitectural guarantee.
Dynamic slices, secret-dependent lengths, signed values, and protocol-level
constant-time claims remain outside this foundation.

The initial v0.12 pentest found that LLVM selection became secret-dependent
branches on RV32. Every expanded mask now crosses the non-inlined optimization
barrier before XOR/AND selection, including array selection and swap. The
architecture-aware evidence gate inspects each function body, rejects
conditional branches outside proven public fixed-array backedges, rejects
direct RV32 `Choice`-register branches and memory addresses, and retains six
negative assembly fixtures. Retest then found numeric register aliases and
omitted pseudo/compressed branches. The gate now canonicalizes RISC-V argument
registers, covers all eighteen conditional forms, and retains ten focused
negative fixtures. Local remediation passes all compiler and target lanes; the
repository-owner retest of exact signed candidate
`7ce43fffdf81a349c7c44aae33b229d077d4512d` passed with zero open findings.
Signed tag v0.12.0 contains the remediated implementation and no crates.io
publication.

v0.13 adds nineteen exact provider operations covering cryptographic,
signature, KEM, AEAD, entropy, clock, certificate-chain, storage, and pending
boundaries. MAC generation and verification are separate authorities, and
verification cannot request computed-tag byte output. Named single-assignment
installation freezes the capability set, caller resource/work limits, and
nonempty secret-destruction duties. An opaque borrowed handle authorizes one
declared operation on one explicitly chosen provider; the prepared request
retains that exact identity and unsupported work fails without registry search
or fallback. Version-neutral request metadata accepts immutable inputs only,
checks aggregate input, output capacity, and provider-operation count before
any effect, and initializes a monotonic provider-owned work meter. Request
holders cannot manufacture success or failure receipts. Nine behavioral test
groups, six compile-fail examples, a hash-locked four-file source policy, and
thirteen broken fixtures enforce the boundary.

This is an authority and request-metadata contract only. It implements no
algorithm, provider effect, output commit, entropy health, clock semantics,
certificate path, storage backend, CPU dispatch, or FIPS approval.

v0.14 separates affine caller-provided `RawEntropy` from initialized
`SecureRandom` state. Requests bind exact purpose, security-strength capacity,
and byte length. The non-cloneable state wrapper requires an exact runtime
generation, mandates reseed after fork or a bounded successful-request
interval, and exposes output only after an engine completely initializes the
exact caller-owned region. Pre-existing bytes, partial writes, retryable
failures, length mismatches, underfill, rollback, and permanent failures all
clear the complete output. Terminal failures synchronously destroy and
quarantine the engine; explicit and `Drop` teardown preserve a mandatory
destruction-failure hook. Failed explicit teardown, failed `Drop`, rejected
initialization, and permanent quarantine all invoke that terminal hook; the
v0.14 assessment found and remediation closed the original explicit-path
omission; repository-owner retest passed with zero open findings.

This contract does not estimate entropy, implement a DRBG or algorithm, access
an operating-system RNG, use FFI, choose a provider, or grant FIPS status.
Callers remain responsible for honest source-strength assertions. The only
deterministic implementation is a deliberately non-cryptographic fixture in
permanently unpublished `brynja-test-support`; production graphs cannot reach
it.

v0.15 adds canonical checked nonnegative durations, signed Unix wall time,
inclusive wall-time validity ranges, opaque nonzero-generation monotonic
instants, and purpose-bound timer, freshness, ticket, and replay deadlines.
Wall and monotonic domains cannot be interchanged. Monotonic ticks are private
and redacted, elapsed and deadline arithmetic rejects generation or direction
confusion, temporary unavailability preserves state, and a source rollback
permanently fails its wrapper. Downstream capabilities provide raw time;
`brynja-core` reads no OS clock and performs no PKI, protocol timer, ticket,
replay, cryptographic, independent-verification, or FIPS operation. Scripted
sources exist only in permanently unpublished test support. Eight core tests,
two fixture tests, two compile-fail examples, reviewed hashes, and nine broken
policy fixtures enforce this boundary.

v0.16 adds an affine pending lifecycle over exact certificate-path,
external-signature, and accelerator-eligible provider requests. Admission
requires the same installed provider's poll and cancel capabilities plus
applicable external-store or accelerator destruction duties. Immutable checked
limits bound begin, resume, cancellation, retry, and backpressure. A downstream
`PendingProvider` either creates no state or exactly one opaque state; every
effect is bound to the exact opaque provider that authorized the request.
Provider-derived, effect-free nonzero costs are charged by the lifecycle before
it issues a non-forgeable work permit. The provider prepares only inert local
state, then the lifecycle owns that state before activation may create an
external resource. Identity is rechecked after guarded preparation and
immediately before activation. Activation, resume, cancellation, and destruction borrow
lifecycle-owned state so recoverable unwinding cannot move even partial state
beyond `Drop`. Completion, cancellation, provider failure, exhaustion, and `Drop`
synchronously destroy state with one non-cloneable destruction token that carries all frozen local,
external-store, accelerator, cache, and DMA duties. Completion and cancellation
remain unavailable until that token becomes a complete result, and failed
cleanup reached through `Drop` invokes the mandatory durable/fail-stop hook.

Sixteen deterministic and adversarial tests, four compile-fail examples,
reviewed hashes, and twenty-one broken fixtures enforce exact kinds and directions,
provider identity, provider-derived work charging, guarded activation,
begin/resume/cancel unwind-safe state ownership, missing capability and duty rejection, unchanged input,
bounded retries/backpressure, cancellation, failure, exhaustion, authoritative
destruction, and drop handling. This upstream contract implements no provider, path validator,
signature, external key store, accelerator, platform effect, cryptographic
algorithm, protocol engine, independent verification, or FIPS validation.

v0.17 adds an inert FIPS-aware provider architecture. Broad operation-category
sets classify every capability of one installed provider explicitly
non-approved. Transactional configuration rejects nonempty approved sets until
exact algorithm identities exist, plus overlap, omission, unsupported services,
duplicate fields, empty build digests, mismatched backend ownership, and
incomplete feature assumptions. SSP destruction duties are derived from the
installed provider and cannot be weakened independently. One nonzero operational-environment identity
binds one module-owned scalar or accelerated symbol class and its exact feature
bundle. The ordinary validated-module placeholder, opportunistic
`BackendPolicy`, runtime std detector, and std CPU adapter are excluded.

An explicitly trusted runner receives the exact mandatory integrity and
algorithm-known-answer plan. Before it passes, no service indicator is available.
Failure, reentry, interruption, unwind, impossible state, generation
exhaustion, or a later catastrophic event permanently fails the caller-owned
session. A non-cloneable, non-formattable, thread-bound informational service
indicator reports one broad operation category, disposition, provider, and
health generation, cannot authorize execution, and becomes stale after failure.
Six behavior groups, four compile-fail examples, exact source hashes, and
twenty-four broken policy fixtures enforce this architecture. It
implements no module, algorithm, provider effect, self-test algorithm, CPU
kernel, runtime detector, environment measurement, deterministic binary
reproduction, SSP movement or erasure, CMVP submission, certificate,
independent verification, or FIPS validation.

`FipsSelfTestRunner` is intentionally public only as a trusted architecture
seam. Application code can implement it, so its return value is not self-test
evidence and grants no execution or approved status. Before those capabilities
exist, v0.125.0 and v0.127.0 require an opaque module-owned attestation issued
only by the complete final-image integrity and pre-operational self-tests.

Permanent failure is currently scoped to one caller-owned
`FipsModuleSession`; sibling sessions over the same configuration are
independent. This is not currently exploitable because every service is
non-approved and no provider effect exists. Before executable or approved FIPS
services exist, v0.127.1 must replace this with one module-wide irreversible
failure latch that fresh sibling sessions cannot reset or bypass.

v0.18 adds sealed type-level domains and one caller-owned authoritative state
machine for every planned security decision class. Only one exact decision may
remain incomplete. Checked generations bind non-cloneable, thread-bound pending
values, completions, and receipts to their authority; exhaustive results
distinguish accepted, approved, non-approved, rejected, pending, canceled,
failed, and terminal work. Public resolutions cannot forge accepted or approved
authority. A future positive path must supply sealed exact-subject evidence;
the current external-key path alone can establish its exact token-bound
acceptance. Resolved non-terminal work remains `AwaitingCommit` until its affine
disposition-specific outcome is explicitly committed. Accepted, approved,
non-approved, rejected, canceled, and failed wrappers are opaque and
non-interchangeable; rejection/failure reasons are read-only, while the
authority retains and verifies the exact disposition at commit. Dropping
pending work or an uncommitted outcome permanently fails closed, mandatory self-test failure permanently
latches integrity failure, and explicit terminal transitions cannot report
non-terminal success.

External-key destruction begins only as a typed key-lifecycle decision and
issues one non-cloneable token for the external-store target. Only consuming a
correct authority- and generation-bound token can produce a successful result;
duplicate, cross-boundary, failed, or abandoned completion is terminal.
Fourteen behavior tests, seven compile-fail examples, six reviewed source
hashes, the 500-line ceiling, and twenty-nine broken fixtures enforce the
contract. Rejection and failure reasons must match their exact decision domain. It
implements no policy, authentication, protocol/profile selection, ticket,
resumption, PSK, early-data, replay, amplification, ECH, provider effect,
external key store, cryptography, protocol engine, event schema, independent
verification, or FIPS validation.

v0.18.1 adds opaque, copyable `SecurityEvent` values that can only be derived
from a typed pending/outcome value or a non-ready authoritative snapshot.
They duplicate the exact decision and disposition where authority retains
them, or the exact permanent terminal reason, without carrying authority
generations, secrets, handles, identities, plaintext, transcripts, PSK
identities, tickets, ECH inner names, arbitrary strings, byte payloads, or
stable cross-connection identifiers. Ready state produces no event. Terminal
events deliberately carry no invented decision identity because the v0.18
terminal snapshot does not retain one.

`SecurityEventRecord` begins explicitly untimestamped and permits one later
caller-provided wall or generation-bound monotonic timestamp. It reads no
clock and rejects timestamp replacement. `SecurityEventQueue<N>` embeds a
fixed caller-owned FIFO array, performs no allocation, callback, I/O, retry,
wait, provider call, alert, or protocol transition, and drops immediately when
full. Loss uses a visible saturating `u64` counter plus a saturation flag.
Events and queues cannot authorize, commit, complete, latch, or mutate the
v0.18 authority. Ten integration tests, two internal boundary tests, three
compile-fail examples, four reviewed source hashes, the 500-line ceiling, and
twenty-two broken fixtures enforce this separation. The schema implements no
audit sink, delivery, persistence, structured serialization, policy decision,
provider effect, protocol engine, cryptography, independent verification, or
FIPS validation.

The exceptional v0.18.0 assessment found four High and one Medium issue across
the initial review and first retest. The clean second repository-owner retest
of exact signed remediation commit
`635b229296be45b195d37d8111fd8ad8f8b1e571` records `PASS`/`PASS` with
zero open findings. This is pentest evidence, not independent cryptographic or
protocol verification.

v0.13.1 adds sealed scalar, x86, AArch64, RISC-V, and validated-module backend
identities; exact feature and provider-operation profiles; scalar-only,
opportunistic, required-accelerated, and validated-module policies; and
caller-owned no-atomics health state. Opaque feature and KAT evidence separate
candidate observation from activation. Each non-scalar candidate owns an
opaque measured-artifact and operational-environment identity. KAT pass and
failure evidence borrow the exact session and instance, preventing replay
between equal profiles or generations. Direct-KAT guards quarantine on
recursion, failure, panic, cancellation, or early return. Healthy authority is
thread-bound and revalidates runtime generation, health generation, backend
identity, and exact operation. Accelerated entry additionally consumes an
opaque platform-issued CPU lease and a sealed context that acquires a
migration-excluding guard while revalidating CPU or hart identity, migration
generation, complete usable features, and required OS or architectural state.
Logical authority is checked again after every platform callback, then one
sealed kernel executes directly while the guard remains live. No application
closure can enter between validation and instruction use. Only opportunistic
policy can return an explicit scalar-fallback reason; required and validated
policies fail closed.

Thirteen behavioral test groups, eleven compile-fail examples, a hash-locked
eight-file source policy, and twenty-three broken fixtures enforce this
boundary. There is still no CPU detection, public instance, lease, context,
guard, or kernel constructor, intrinsic, assembly, executable accelerated
kernel implementation, global cache, unsafe backend boundary, performance
claim, provider effect, or FIPS validation. Public profiles, features,
snapshots, approval values, and reports are observational and cannot construct
backend authority.

## Cryptography Verification Status

The provider and constant-time foundations and the earlier core domains have
not been independently reviewed. A component only moves from ❌ to ✅ when a named
independent reviewer signs off and linked review evidence is recorded. Project
tests, CI, Kani, Miri, fuzzing, and pentesting do not by themselves constitute
independent cryptographic or protocol verification.

| Component | Cryptographic or protocol scope | Independently verified |
| --- | --- | --- |
| `brynja-core` | Constant-time operations plus provider, CPU-backend, entropy, secure-random, clock, pending-operation, FIPS-aware state, and mandatory security-outcome contracts | ❌ Not verified |

Most application users will eventually depend on the modern facade:

```toml
[dependencies]
brynja = "0.20"
```

Version `0.9.0` was published at the Brynja v0.20.0 cumulative checkpoint after
the scheduled assessment and remediation retest passed with zero open
findings. Later development deltas remain unpublished until a checkpoint under the
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).
The exceptional repository-owner assessment of the exact v0.18.1
implementation candidate passed with zero findings; v0.18.1 remains in the
scheduled cumulative v0.20.0 review range.

The project-wide first-party Rust cryptography, dependency, `no_std`, 500-line
source-file, platform-portability, and modern/legacy isolation policies apply
here.
