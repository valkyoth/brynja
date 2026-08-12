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

`brynja-core 0.7.0` now carries the cumulative v0.14 entropy and initialized
secure-random contract, v0.13.1 CPU-backend capability and dispatch contract,
and v0.13 provider capability and opaque-handle
contracts alongside the v0.12 constant-time foundation, v0.11
owned-memory zeroization implementation, v0.10 abstract secret-lifetime
contract, and transactional foundations from earlier milestones. The package
version remains `0.7.0` until the v0.15.0 public checkpoint.

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
unsafe block. Repository policy rejects every other unsafe site, while CI
checks MIR, LLVM IR, and assembly for Rust 1.90.0 through 1.97.1 and all nine
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
policy, and optimized LLVM/assembly witnesses cover Rust 1.90.0 through 1.97.1
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
certificate path, storage backend, pending-operation lifecycle, CPU dispatch,
or FIPS approval.

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
omission, with repository-owner retest pending.

This contract does not estimate entropy, implement a DRBG or algorithm, access
an operating-system RNG, use FFI, choose a provider, or grant FIPS status.
Callers remain responsible for honest source-strength assertions. The only
deterministic implementation is a deliberately non-cryptographic fixture in
permanently unpublished `brynja-test-support`; production graphs cannot reach
it.

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
| `brynja-core` | Constant-time operations plus provider, CPU-backend, entropy, and secure-random state contracts | ❌ Not verified |

Most application users will eventually depend on the modern facade:

```toml
[dependencies]
brynja = "0.10"
```

The `0.7.0` package was published with Brynja v0.10.0 after its pentest,
remediation retest, and hosted checks passed. It remains at `0.7.0` during the
v0.14.0 development milestone and is not selected for publication
under the
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).

The project-wide first-party Rust cryptography, dependency, `no_std`, 500-line
source-file, platform-portability, and modern/legacy isolation policies apply
here.
