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

# brynja

Brynja is a security-first, first-party Rust, `no_std` cryptography and
secure-protocol ecosystem. Its first production goal is a serious
production-ready TLS and RFC 9580 OpenPGP implementation at `1.0.0`; its
primitive boundaries are designed so both protocol families and later
standalone cryptographic families reuse the exact same reviewed
implementations. Cryptography remains Brynja-owned Rust. Narrow encoding and
companion-adapter exceptions follow explicit admission and isolation policy.

> **Development status:** Brynja is pre-1.0, incomplete, and not ready to
> secure application traffic. Every version receives an immutable signed tag
> only after the complete automated gate and green GitHub and CodeQL. Scheduled
> pentesting and crates.io publication occur at the cumulative checkpoints
> described below; a tag without a matching committed pentest report was not a
> scheduled pentest checkpoint.

## Cryptography Verification Status

These tables track concrete public capabilities, not internal crate names or
reserved architecture. A capability is listed as implemented only after its
complete public API and required acceptance evidence for that named milestone pass.
The broader crate-level audit inventory remains available in the
[component verification status](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md).

✅ Implemented means a named capability is ready; ✅ Fully implemented means
every named member of that exact family is ready. Both require documented,
consumer-usable public APIs and the repository's required evidence. A green
implementation status does not mean independently verified. Independent status moves from ❌ to ✅ only
when a named independent reviewer signs off and linked evidence identifies the
reviewed implementation. The project's own tests, CI, Kani, Miri, sanitizers,
fuzzing, differential testing, and pentests do not by themselves constitute
independent cryptographic or protocol verification.

### Hash Functions

| Hash | Implemented | Independently verified |
| --- | --- | --- |
| SHA-2 (FIPS 180-4: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256) | ✅ Fully implemented | ❌ Not independently verified |

### Protocol And PKI Building Blocks

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| TLS and DTLS record-envelope parsing and encoding | ✅ Implemented | ❌ Not independently verified |
| Bounded DER framing and admitted canonical ASN.1 values | ✅ Implemented | ❌ Not independently verified |

### Security Foundations

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Fixed-width constant-time operations and secret-region lifecycle | ✅ Implemented | ❌ Not independently verified |
| Fixed-size secret ownership and explicit sanitization adapter | ✅ Implemented | ❌ Not independently verified |

### Official Validation

FIPS validation is a separate official claim from implementation and
independent source review.
Brynja has no FIPS 140-3 validation, certificate, validated module, approved
security policy, or certificate-bound operational-environment claim.

| Validation scope | Implemented | Officially validated |
| --- | --- | --- |
| FIPS 140-3 cryptographic module | ❌ Not implemented | ❌ Not FIPS validated |

## Project Direction

The roadmap through `1.0.0` implements complete modern TLS, DTLS, QUIC-TLS
integration, PKIX and RFC 9580 OpenPGP plus complete, separately selected named
legacy protocol packages before the final candidate. Standalone hashing does not
expand or delay that v1 protocol claim. SHA-2, SHA-3, SHAKE, and HMAC are
already required by TLS, PKI, ML-KEM, and OpenPGP, so their planned
implementation ownership lives in small reusable family crates instead of
private copies inside a protocol crate.

Every authenticated standardized capability attached to that scope must be
complete before `1.0.0`, including optional and deprecated algorithms, both
client and server roles, and every defined generation, import, export, send,
receive, sign, verify, encrypt and decrypt direction. Secure choices remain in
modern packages; obsolete or dangerous choices require conspicuously warned
`brynja-legacy-*` packages and explicit policy. Rejection is reserved for
malformed or forbidden input, reserved or unassigned values, unauthorised
private use, unsafe implicit fallback, unavailable lawful authority, or
non-production diagnostics. There is one implementation per algorithm: a
future legacy facade wraps or reexports an implementation that becomes obsolete
instead of copying it.

| Boundary | Responsibility |
| --- | --- |
| `brynja-hash-core` | Small fixed-output and XOF interfaces; no algorithm or protocol |
| `brynja-hash-sha2` / `brynja-hash-sha3` | Portable family implementations reused by standalone callers and Brynja protocols |
| `brynja-mac-hmac` | Keyed HMAC construction with MAC-specific types and verification |
| `brynja-crypto` | Provider contracts, algorithm policy and composition, AEADs, KDFs, RSA, ECC, and integration of exact primitive-family implementations |
| `brynja` | Modern secure-protocol facade; TLS and OpenPGP stay separately selectable and a future hash convenience surface remains default-off and curated |

`brynja-crypto` therefore remains essential. It is the protocol-facing
cryptographic substrate above the small leaf-family crates; those crates never
depend on TLS or pull the complete crypto graph. This direction prevents both
duplicate SHA implementations and a standalone hash user acquiring every
Brynja algorithm.

The final pre-1.0 phase adds `brynja-openpgp-core`,
`brynja-openpgp-armor`, and `brynja-openpgp`. Packet framing, certificates,
keys, signatures, encryption, compression, trust policy, and deprecated
compatibility remain separate review boundaries. The plan includes exact
modern RFC 9580 operations, isolated strong-v4 and v1-SEIPD compatibility,
exhaustive packet/subpacket dispositions, and downstream fixtures proving that
public Brynja APIs are sufficient to build an OpenPGP protocol client. UI,
storage, networking, key discovery, identity trust, and PGP/MIME remain
application-owned. OpenPGP is outside the FIPS validated-module plan. Base64 is the one encoding algorithm Brynja does not
plan to duplicate: v0.47.1 will audit the latest stable first-party
`base64-ng` family and admit only an exact-pinned, allocation-free `no_std`
edge suitable for PEM and OpenPGP armor.

After `1.0.0`, Brynja may expand into separately selectable modern, legacy,
utility, and research hashing families. Checksums and MACs remain distinct from
cryptographic hashes, legacy algorithms remain visibly isolated, and the main
facade will never gain an `all-hashes` feature. The versionless
[post-1.0 hashing plan](https://github.com/valkyoth/brynja/blob/main/docs/POST_1_0_HASH_PLAN.md)
contains the full candidate inventory, missing families, crate graph,
implementation order, and security gates. It is planning only: no listed
algorithm is implemented, admitted, independently verified, or FIPS validated
by appearing there.

The signed `0.22.2` development milestone added an isolated first-party RV64
Zknh compression candidate beside the x86_64 SHA and AArch64 SHA2 candidates
for the complete portable SHA-256 implemented at v0.22.0. The signed
`0.22.3` milestone closed that implementation chain with packaged downstream
public-API acceptance. Portable `brynja-hash-sha2` still owns the public
digest, streaming state, padding, checked length, finalization, and scalar
fallback. The optional zero-dependency `no_std` `brynja-crypto-cpu` crate owns
only static selection, direct KAT, caller-owned health/quarantine, and exact
one-block kernels. The separate opt-in `std` `brynja-crypto-cpu-std` crate owns
runtime feature detection and explicit opportunistic or required selection.

The signed `0.23.2` milestone completed the portable FIPS 180-4 SHA-2 family.
The signed `0.23.3` milestone extends the optional CPU boundary across all six
algorithm identities. SHA-224 reuses each exact SHA-256-family compression
kernel without changing its IV or output identity. New AArch64 SHA-512 and
RV64 Zknh SHA-512 kernels serve SHA-384, SHA-512, SHA-512/224, and SHA-512/256
through separately typed streaming and one-shot APIs. Differential tests cover
padding boundaries, irregular chunking, all six identities, forced routes,
KAT health, quarantine, and emitted instructions. x86_64 deliberately remains
scalar for the SHA-512 family: no path is admitted merely because AVX2 or
AVX-512 exists.

All five instruction kernels are implemented but deliberately unadmitted.
Private commit-bound correctness and emitted-code observations passed on local
AMD, observed-feature AWS Intel, Apple M2, and AWS Arm. The two Arm lanes ran
all six identities and emitted native SHA-512 instructions; x86_64 retained
its reviewed scalar-only SHA-512 decision. All observations remain non-authorizing.
Authenticated runner, CPU-migration, native performance, side-channel, and
final-admission evidence remains incomplete. A sanitized
preflight of the registered RISC-V lane found generic RV64 vector and
bit-manipulation support but no `Zknh`, `Zvknha`, or `Zvknhb`, so no native
candidate was executed. Ordinary builds therefore cannot execute any
candidate: opportunistic selection uses scalar and reports why, while required
acceleration fails closed. The RV64 path requires exact `zknh`, uses six
hash-bound register-only Rust inline-assembly statements across its 32-bit and
64-bit SHA-2 operations, and has no automatic std detection. Generic RV64, RVV, and QEMU
do not qualify it for admission. The candidates use no external C module,
external assembly source, build script, detector dependency, allocation, I/O, or global
registry, and make no register-erasure, independent-review, or FIPS 140-3
validation claim.

The current `0.23.4` milestone closes the complete SHA-2 chain with a
standalone downstream `no_std` consumer. It exercises all six algorithms
through both leaf and facade public APIs over independent empty, text, binary,
multi-block, million-byte, and file-like expectations in one-shot and
irregular streaming modes. The same consumer runs from safely extracted
offline Cargo archives with version-only dependencies. Adversarial fixtures
reject expectation, identity, output-width, export, documentation, backend-
accounting, feature, and package-content regressions. This establishes
consumer usability; it does not admit a CPU backend or add independent review,
FIPS validation, or secret-state erasure.

The voluntary repository-owner assessment of exact signed v0.23.4
implementation candidate `7864a8f3a8766d16fc9bb2ea89893351f29aa842`
reported no finding and required no remediation. Its permanent report records
`PASS`/`PASS` with zero open findings. This does not replace the scheduled
cumulative v0.20.0-to-v0.25.0 assessment or alter the zero-crate publication
selection.

RISC-V testing follows an exact-feature policy. The registered native host is
used for scalar portability and only those generic-vector or bit-manipulation
operations supported by every eligible hart; missing cryptographic extensions
remain explicitly QEMU/codegen-only. After v1.0.0, Brynja will publish a
reproducible, privacy-conscious capture kit and ask Rust and RISC-V community
members for additional real-hardware evidence. Community observations do not
by themselves admit a backend. See the
[post-1.0 RISC-V qualification plan](docs/POST_1_0_RISCV_QUALIFICATION_PLAN.md).

Native candidate runs use a repository-owned detached runner derived from the
same operational model as `base64-ng`: it pins one clean commit and tree,
clones that exact commit on SSH workers, survives disconnects, persists local
job state, retrieves completed bundles, and validates the lane, accelerated
test transcript, emitted instruction, and every checksum locally. These
candidate bundles remain explicitly non-authorizing; they do not replace the
later authenticated performance, side-channel, and admission records.
New source commits receive new sessions; prior orchestration databases are
archived rather than reused or relabelled.

The preceding v0.22.0 milestone introduced allocation-free `no_std` one-shot
and streaming SHA-256, checked FIPS message-length exhaustion, consuming
finalization, and an exact 32-byte digest type. `brynja-crypto` and `brynja`
reuse those implementations rather than carrying private copies. The complete FIPS 202 family,
isolated legacy SHA-1/MD5 compatibility, HMAC, and their public chain
acceptance remain explicitly numbered later scope before 1.0.

The exceptional assessment found no vulnerability and required no source
remediation. It retained one correctly disclosed future constraint: portable
SHA-256 working state, schedule, and buffered input are not explicitly
zeroized because v0.22.0 exposes only unkeyed hashing. Ordinary `Sha256` does
not guarantee erasure of remnants when its input contains secrets, and callers
cannot erase private working state themselves. Before HMAC or other key-derived
processing uses this path, the owning construction must add secret-owned
cleanup through Brynja's hardened volatile boundary and verify the emitted
stores across the supported compiler and target matrix. The
permanent report records `PASS`/`PASS` and zero open findings.

The signed and published `0.20.0` checkpoint introduced the underlying
borrowed, non-recursive DER framing reader. Its scheduled assessment found one
Low adjacent-byte semantic-boundary oracle; pre-access parent-boundary checks
closed it, repository-owner retest passed with zero findings, GitHub and
CodeQL became green, and all 15 selected packages were published.

The signed `0.19.0` development milestone adds `brynja-protocol`, a shared
allocation-free TLS and DTLS record-envelope boundary. An already selected
typed `WirePolicy` is required before parsing, so record bytes cannot choose a
protocol version, downgrade, or trigger fallback. Borrowed parsers and
transactional caller-buffer encoders cover TLS 1.2 and TLS 1.3 plaintext and
ciphertext envelopes, DTLS 1.2 plaintext/ciphertext envelopes, and DTLS 1.3
plaintext and unified ciphertext headers. They enforce profile-specific
constants and bounds, preserve permitted legacy-version and unknown
content-type bytes, reject malformed or truncated records, and reject RFC 6520
Heartbeat content and negotiation in every modern profile.

The framing boundary performs no allocation, I/O, cryptography, decryption,
authentication, DTLS sequence reconstruction, replay processing, version
selection, handshake transition, or alert decision. The TLS 1.2, TLS 1.3, and
DTLS engine packages consume the shared crate but remain unimplemented.
Because this was Brynja's first hostile protocol parser, v0.19.0 required an
exceptional pentest before its signed tag even though it selected no crates.io
publication and remains in the cumulative v0.15.0-to-v0.20.0 review range.
The initial assessment found one High cleartext-exposure flaw: TLS 1.3
plaintext admission inherited TLS 1.2 application-data allowance. TLS 1.3
application data is now categorically rejected during both parsing and caller
construction with a dedicated closed error. Focused regression and policy
fixtures pass. Repository-owner retest of exact signed remediation candidate
`238d4bac75eecce9dde63700c53f13e6f7a9aaed` passed with zero open findings,
and the permanent report records `PASS`/`PASS`; signed tag v0.19.0 contains the
reviewed remediation.

The signed `0.18.0` development milestone adds a protocol-neutral mandatory
security-outcome authority contract in `brynja-core`. Sealed type-level domains
cover self-tests, service approval, protocol and profile selection,
authentication, tickets, resumption, PSKs, early data, anti-replay,
amplification, exhaustion, providers, key lifecycle, ECH, policy, and terminal
transitions. One caller-owned allocation-free authority admits one incomplete
decision at a time and returns exhaustive accepted, approved, non-approved,
rejected, pending, canceled, failed, or terminal results. Public resolutions
cannot forge accepted or approved authority: positive outcomes remain
unreachable until a sealed, subject-bound execution path supplies exact
evidence. Resolved non-terminal work remains `AwaitingCommit` until its affine
disposition-specific outcome is explicitly committed. Accepted, approved,
non-approved, rejected, canceled, and failed values are opaque and
non-interchangeable; rejection/failure reasons are read-only, and the authority
verifies the exact retained disposition at commit. Abandoning pending work or
an uncommitted outcome permanently fails closed, mandatory self-test failure permanently
latches integrity failure, rejection and failure reasons remain confined to
their exact typed domains, and terminal transitions cannot report ordinary
success.

External-key destruction can report success only after consuming one
non-cloneable, thread-bound token for the exact external-store target. Duplicate,
cross-authority, cross-generation, failed, and abandoned completion fail closed.
Snapshots are informational and cannot authorize, complete, or alter work.
The v0.18 authority contract itself implements no decision policy,
authentication, protocol selection,
ticket, replay store, ECH, provider effect, external key store, cryptography,
protocol engine, event schema, independent verification, or FIPS validation.

The signed `0.17.0` development milestone freezes an inert FIPS-aware provider
architecture in `brynja-core`. Broad operation-category sets classify every
installed-provider capability explicitly non-approved. Any nonempty approved
set fails closed until exact algorithm, parameter, backend, and usage identities
span the provider request and result path. A module configuration binds nonzero
deterministic-build digests, one exact operational-environment identity, a module-owned scalar or
accelerated backend with its complete feature bundle, and explicit SSP flow;
complete-copy destruction duties come directly from the installed provider.
The ordinary validated-module
placeholder, opportunistic `BackendPolicy`, runtime std detection, and the std
CPU adapter cannot enter this boundary.

An explicitly trusted self-test runner receives the exact integrity and
algorithm-known-answer plan. Service indicators remain unavailable until it
succeeds;
failure, reentry, interruption, unwind, or a later catastrophic event latches
the caller-owned module session failed. Non-cloneable thread-bound service
indicators report one operation category, disposition, provider, and health
generation, and become stale after terminal failure. They cannot authorize or
execute provider work. This implements no cryptographic
module, algorithm, provider effect, self-test algorithm, CPU kernel, SSP
transport or erasure, deterministic binary reproduction, CMVP submission,
certificate, independent verification, or FIPS validation.

The public `FipsSelfTestRunner` trait is a trusted architecture seam, not
self-test evidence: application code can implement it, and its success grants
no provider execution or approved status. Before either becomes possible,
v0.125.0 and v0.127.0 require an opaque module-owned attestation that only the
complete final-image integrity and pre-operational self-tests can issue.

Permanent failure is currently caller-session-scoped. That has no executable
bypass today because every service is non-approved and no provider effect
exists. Before executable or approved FIPS services exist, v0.127.1 must make
the irreversible failure latch module-wide so a fresh sibling session cannot
reset or bypass it.

Version `0.15.0` added non-interchangeable typed wall and monotonic clocks
to `brynja-core`. Signed Unix wall values support checked arithmetic and
inclusive validity ranges for later PKI policy. Opaque monotonic instants bind
an explicit runtime/boot generation, redact raw ticks, reject cross-generation
arithmetic, and permanently fail their source wrapper after rollback.

Version `0.14.0` implemented the upstream entropy and initialized secure-random
contract in `brynja-core`. Caller-provided raw
entropy is affine, exact-purpose, exact-strength, exact-length secret input;
it is not an OS entropy source, a DRBG, or a validation claim. Initialized
secure-random state is non-cloneable, requires an exact runtime generation,
forces reseed after fork or its configured request interval, writes only into
transactional caller-owned secret memory, and permanently quarantines engine
underfill, rollback, or terminal failure. The wrapper supplies no algorithm,
platform RNG, FFI, FIPS status, or automatic fallback.

Intentionally non-production deterministic clock sources and a
non-cryptographic deterministic and fault-injecting random engine
lives only in permanently unpublished `brynja-test-support`. Machine policy
rejects making those fixtures publishable, moving them into a production graph,
adding OS randomness, OS clocks, or foreign code to the reviewed boundaries,
exposing monotonic ticks, weakening rollback latching, granting secret states
cloning or formatting, or changing reviewed source files without reopening
review.

Version `0.13.2` reserved `brynja-crypto-cpu` as a
zero-dependency `no_std` package and `brynja-crypto-cpu-std` as its separately
selected future host detector. Both remain independent of the main facade,
defaults, and protocol engines. Eight x86_64, AArch64, and RISC-V backend
module identities now carry
exact reserved paths, instruction and ABI preconditions, safe-wrapper
invariants, and a fail-closed amendment checklist. Both packages are inert:
there is no detector, intrinsic, assembly, executable backend, new low-level-
code allowance, performance claim, or FIPS validation.

Version `0.13.1` added a version-neutral CPU-backend
contract to `brynja-core`. Sealed scalar, x86, AArch64, RISC-V, and
validated-module identities bind exact feature and provider-operation profiles.
Opaque backend-instance identity binds a measured artifact and operational
environment, and KAT evidence borrows the exact session and instance rather
than matching reusable profile values. Caller-owned health state separates
detection evidence, direct startup KATs, per-operation dispatch authority,
permanent quarantine, runtime generations, and secret-free reporting.
Accelerated entry additionally requires an opaque platform-issued CPU lease and
a sealed context that acquires a migration-excluding guard while revalidating
logical CPU or hart identity, migration generation, the complete usable feature
predicate, and required OS or architectural state. Logical authority is checked
again after every platform callback, then a sealed kernel executes directly
while the guard remains live; application closures cannot enter this boundary.
Opportunistic policy reports scalar fallback; required-accelerated and
validated-module policies fail closed. This milestone adds no CPU detection,
public lease, context, guard, kernel, or instance constructor, intrinsic,
assembly, executable accelerated kernel implementation, unsafe backend
boundary, provider effect, performance claim, or FIPS validation.

Version `0.13.0` added provider capability and opaque-handle contracts to
`brynja-core`. Nineteen exact operations remain direction-specific,
including separate MAC generation and verification. Capabilities, caller
resource/work limits, and mandatory secret-destruction duties freeze through
transactional installation. Protocol code explicitly chooses one opaque
borrowed provider handle, receives authorization for one declared operation,
and prepares immutable version-neutral request metadata that retains that exact
provider identity. Unsupported operations fail without registry search or
fallback. Request holders cannot manufacture success or failure receipts, and
work can only be charged against the installed provider's monotonic meter. No
provider effect, algorithm, entropy source, clock, certificate-chain engine,
or storage backend is implemented by that authority layer.

Version `0.12.0` implemented Brynja's first constant-time foundation in
`brynja-core`: normalized one-byte `Choice` and `CtMask` values,
constant-time equality, conditional selection and swap for unsigned words and
compile-time-sized byte arrays, and an explicit compiler barrier. The source
policy, exhaustive byte tests, compile-fail API tests, and optimized LLVM and
assembly witnesses cover every supported Rust release and promised target.
This is implementation evidence, not a mathematical proof, timing measurement,
independent cryptographic review, or guarantee for an arbitrary downstream
composition. Version `0.11.2` implemented the
separately selected, protocol-neutral
`brynja-sanitization 0.1.0` adapter admitted at v0.11.1. It exact-pins
first-party `sanitization 2.0.3`, disables every upstream feature, activates no
transitive package, owns opaque fixed-size wrappers, and provides only explicit
copies to and from Brynja's caller-owned regions. It is absent from every
facade, engine, default feature, and FIPS module closure. Brynja's v0.11.0
affine owned-region primitive remains mandatory and authoritative. See the
[admission review](https://github.com/valkyoth/brynja/blob/main/docs/sanitization-admission-review.md)
for package hashes, unsafe inventory, target evidence, residual risks, and
re-review triggers. These foundations do **not** implement TLS framing, a
protocol state machine, or cryptography and must not be used to secure network
traffic.

An exceptional v0.11.1 repository-owner assessment found that the initial
review fixture accepted and discarded arbitrary source-error payloads. The
remediated boundary accepts only a payload-free Brynja-owned error, and the
retest of signed commit `cd1c881d2eb6c9aa925f1527a326330c1cf3b80a` passed
with zero open findings. The permanent
[v0.11.1 report](https://github.com/valkyoth/brynja/blob/main/security/pentest/v0.11.1.md)
records the finding, remediation, limits, and exact evidence; no affected code
ever entered the production graph.

The exceptional v0.11.2 repository-owner assessment of the production adapter
passed with no findings and zero open findings. Its permanent
[v0.11.2 report](https://github.com/valkyoth/brynja/blob/main/security/pentest/v0.11.2.md)
records the assessed implementation commit, scope, exact release evidence, and
residual risks. The v0.11.2 tag published no crate; the adapter was later
included in the completed v0.10.0-through-v0.15.0 cumulative assessment and
published at the v0.15.0 checkpoint.

The initial v0.12.0 pentest found a High RV32 timing flaw: LLVM selection was
lowered into branches controlled by `Choice`, while the assembly gate inspected
symbols but not function bodies. The source now barriers each expanded mask
before XOR/AND selection, and the gate rejects target-specific conditional
branches and direct RV32 secret-address operands in every concrete root.
Permanent negative fixtures cover RV32, x86_64, and AArch64 regressions. Local
remediation is green. Retest then found that a synthetic backward fixed-array
branch directly on the RV32 `Choice` register could bypass the loop classifier;
the validator and a sixth fixture closed that assurance gap. A second retest
found numeric register aliases plus omitted pseudo/compressed RISC-V branches;
the gate now canonicalizes argument registers, recognizes all eighteen
conditional forms, and retains ten focused negative fixtures. The exact signed
third candidate, `7ce43fffdf81a349c7c44aae33b229d077d4512d`, passed the
repository-owner retest with zero open findings. The permanent report records
PASS/PASS; signed tag v0.12.0 contains the remediated implementation and no
crates.io publication.

## Development Tags And Pentesting

The `brynja` facade version advances at every roadmap milestone, including
patch milestones, and each completed milestone receives the ordinary signed
`vX.Y.Z` tag after its signed commit passes the complete local gate and GitHub
and CodeQL are green. Development tags between public checkpoints are not
published to crates.io. Supporting crates keep independent versions and are
published only when their cumulative changes require it at a checkpoint.

Pentests look backwards over the complete change range between public
checkpoints. The v0.15.0 assessment covered all changes after signed public tag
v0.10.0 through v0.15.0. The v0.20.0 assessment covered all changes after
v0.15.0 through v0.20.0. The next scheduled assessment covers every change
after v0.20.0 through v0.25.0, and the same pattern continues every fifth
minor version. Each checkpoint report records
its previous public tag as `Baseline`
and names both ends of the reviewed range in `Scope`. Material security changes
can require an earlier exceptional pentest; that does not weaken the next
scheduled cumulative review.

Permanent outcomes are committed under
[`security/pentest/`](https://github.com/valkyoth/brynja/tree/main/security/pentest).
These reports make the assessed versions and ranges explicit; automated tests,
CI, CodeQL, fuzzing, Miri, or Kani are valuable evidence but are not themselves
an independent pentest.

The repository owner also performed an exceptional review of exact signed
v0.18.1 implementation commit `9ff9a459d8caae7e7f5c18b6576647487ba5b251`
and reported zero findings. That assessment is recorded permanently without
removing v0.18.1 from the broader v0.15.0-to-v0.20.0 cumulative review range.

The exceptional v0.19.0 review initially found one High TLS 1.3 cleartext-
exposure flaw. The repository-owner retest of exact signed remediation commit
`238d4bac75eecce9dde63700c53f13e6f7a9aaed` passed with zero open findings.
The permanent `PASS`/`PASS` report does not remove v0.19.0 from the cumulative
v0.15.0-to-v0.20.0 checkpoint assessment.

The scheduled v0.20.0 assessment found one Low semantic-boundary oracle in the
DER reader and no Critical, High, or Medium issue. An incomplete nested tag or
length could inspect an adjacent byte beyond its parent before rejection. The
reader now rejects the exact parent boundary before every header-byte access;
focused regressions and source policy pass. Repository-owner retest of exact
signed remediation commit `7fd31b4cc536cb2dce1a565fa3551365b086000f`
passed with zero open findings, and the permanent report records
`PASS`/`PASS`.

The exceptional v0.21.0 assessment found no issue in the canonical ASN.1 value
delta and required no source remediation. Its permanent `PASS`/`PASS` report
retains the essential boundary: canonical sequence framing is not
schema-specific validation, and X.509, cryptography, independent review, and
FIPS validation remain absent. The v0.21.0 delta remains included in the
scheduled v0.20.0-to-v0.25.0 assessment.

The exceptional v0.22.0 assessment found no vulnerability in the portable
SHA-256 delta and required no source remediation. Its permanent `PASS`/`PASS`
report records zero open findings and preserves the future secret-state
cleanup requirement before HMAC or other keyed processing. The v0.22.0 delta
remains included in the scheduled v0.20.0-to-v0.25.0 assessment.

The exceptional v0.22.1 assessment and final retest found no open
vulnerability in the SHA-256 acceleration delta. Exact signed commit
`7d6dc573d8aaf049085d4bc4007642ee3b9ed82f` records `PASS`/`PASS`.
Its private four-lane candidate observations do not admit either v0.22.1 backend or
replace authenticated native, CPU-migration, performance, side-channel,
independent-review, or FIPS evidence. The v0.22.1 delta remains included in
the scheduled v0.20.0-to-v0.25.0 assessment.

The v0.22.2 RV64 `Zknh` candidate is implemented but unadmitted. Rust 1.90.0
and 1.97.1 emitted all four required scalar SHA-256 instructions and the QEMU
differential corpus passed, but those results are supplemental and create no
native RISC-V support claim. The registered native lane was also inventoried
and rejected before execution because every hart lacks scalar and vector SHA
extensions. Its exceptional assessment found no Critical, High, or Medium
issue, required no source remediation, and records `PASS`/`PASS` with zero open
findings. Signed tag v0.22.2 contains that exact report candidate.

The v0.22.3 acceptance fixture depends only on the ordinary
`brynja-hash-sha2` and `brynja-crypto` manifests. One documented command checks
empty, text, binary, multi-block file-like, and million-byte messages through
one-shot and irregular streaming APIs, rebuilds and runs the fixture from
Cargo package contents, and verifies public checked-length exhaustion. It
reports zero admitted acceleration routes and explicitly skips all three
unadmitted candidates. Corrupted digests, missing public exports, backend
overclaims, exhaustion bypasses, candidate-feature injection, and altered
package contents fail deterministic negative fixtures.

The voluntary v0.22.3 repository-owner assessment and retest through exact
signed implementation and CI-correction commit
`399c9e7c5092d755dfbc22a3adf5500f85a8877e` found no vulnerability, required
no cryptographic source remediation, and records `PASS`/`PASS` with zero open
findings. This remains an internal tag with zero crates.io publication; its
complete delta is still covered again by the scheduled v0.20.0-to-v0.25.0
cumulative assessment.

The exceptional v0.23.0 repository-owner assessment and retest of exact signed
SHA-224 implementation candidate
`8877bda1e697db98e77637d82bdc0d0d6ecad237` found no vulnerability, required
no remediation, and records `PASS`/`PASS` with zero open findings. It remains
an internal tag with zero crates.io publication and remains covered again by
the scheduled v0.20.0-to-v0.25.0 cumulative assessment.

The exceptional v0.23.1 repository-owner assessment of exact signed
SHA-384/SHA-512 implementation candidate
`22c1dcdc7594a34bc14b53b42d1d56f7aa66047b` found no vulnerability, required
no remediation, and records `PASS`/`PASS` with zero open findings. It remains
an internal tag with zero crates.io publication and remains covered again by
the scheduled v0.20.0-to-v0.25.0 cumulative assessment.

## Install

Brynja is not ready for application use and does not implement TLS. The latest
signed and crates.io checkpoint is `0.20.0`. The current internal `0.23.4`
complete SHA-2 public-usability milestone selects no crates.io publication. The published
dependency is:

```toml
[dependencies]
brynja = "0.20"
```

Every tag advances the `brynja` facade manifest to the tag version. Only
scheduled or exceptional public checkpoint tags publish it to crates.io.
Supporting crates keep independent versions and are published only when their
cumulative package or exact-pin changes require it; unchanged support crates
are not republished. The guarded publisher validates and packages the exact
selected set in dependency order and publishes the facade last.

## Design Boundaries

- **Golden rule:** every Brynja cryptographic primitive, construction, key
  operation, protocol cryptographic operation, CPU backend, and FIPS module
  service is implemented from first-party Rust source. Brynja never wraps,
  links, vendors, calls, or delegates those duties to C, C++, Objective-C,
  OpenSSL, BoringSSL, AWS-LC, a system cryptographic library, or another
  foreign/native cryptographic module.
- Portable scalar primitives belong to the smallest reusable semantic family:
  SHA-2 in `brynja-hash-sha2`, SHA-3/SHAKE in `brynja-hash-sha3`, and HMAC in
  `brynja-mac-hmac`. `brynja-crypto` consumes those exact symbols and retains
  provider, composition, policy, AEAD, KDF, RSA, ECC, and other unsplit
  cryptographic responsibilities; it never reimplements a family privately.
- The modern `brynja` facade can never enable SSL or other legacy
  protocols through its features.
- Legacy implementations live in explicitly named packages and use
  separate APIs, state, configuration, negotiation, caches, and ticket keys.
- Every legacy engine uses a `brynja-legacy-*` package name so its
  presence is obvious in manifests, lockfiles, SBOMs, and policy reports.
- `brynja-tls` is an evergreen facade and one-pass router over independently
  versioned modern TLS engines; a new TLS generation does not redefine an
  existing engine package or automatically make its predecessor legacy.
- Unreviewed runtime and build dependencies are forbidden in the core
  workspace. The only planned core encoding exception is an exact-pinned,
  default-feature-disabled `base64-ng` edge confined to bounded Base64, PEM,
  and OpenPGP armor after its v0.47.1 admission review; it never implements
  cryptography or enters `brynja-fips-module`. Future
  separately selected `brynja-rustls` and `brynja-tokio` companion adapters may
  depend only on the exact pure-Rust ecosystem API they implement, in separate
  lockfiles and graphs that can never enter or be enabled by `brynja`.
- Version `0.11.2` implements one separately selected
  `brynja-sanitization` adapter over admitted exact `sanitization 2.0.3`. It
  uses an exact pin with default features disabled,
  never activates `zeroize`, and is not a dependency or feature of a facade,
  protocol engine, legacy engine, or FIPS module.
- Every production crate is `no_std` by default. Platform services enter
  through explicit caller-provided interfaces.
- v0.9 arena domain names classify raw caller storage only. v0.10 adds the
  abstract destruction-duty contract. v0.11 adds a separate exclusive borrowed
  region owner with exact initialization and volatile complete-region clearing;
  a raw `SecretDomain` arena is not automatically that owner and
  `CertificateDomain` is not private-key storage.
- FIPS 140-3 support is planned through separate `brynja-fips-module` and
  `brynja-fips` packages, not a boolean Cargo feature. Only an exact issued,
  certificate-bound module and tested operational environment may carry a
  validation claim; the current project is not FIPS validated.
- Source files are limited to 500 lines and milestones are split before they
  become too large to review safely.
- Assurance runners are first-party, deterministic, bounded, and shell-free.
  Inputs use descriptor-bound, no-follow, limit-plus-one reads and differential
  corpora and generated mutation cases stream one at a time. Windows uses a
  suspended-start kill-on-close Job Object. A POSIX process group is only
  cooperative cleanup: hostile execution fails closed unless the launcher
  declares enforced cgroup, PID-namespace, container/VM, or fork-and-setsid
  denial. That declaration is a launcher contract, not sandbox evidence.
  External campaign launchers must provide and record OS containment. Kani uses
  its separately documented Rust 1.90.0 verifier pairing while release code
  stays on latest stable Rust; policy-only status is never a proof claim.
- A feature being compiled is never evidence that a protocol is implemented,
  secure, interoperable, audited, or production-ready.
- The v0.12 constant-time API is intentionally limited to unsigned fixed-width
  words and compile-time-sized byte arrays. It has one explicitly named public
  declassification operation; dynamic slices, secret-dependent lengths,
  protocol-level timing claims, and platform microarchitectural guarantees are
  outside this foundation.
- The v0.13 provider boundary freezes capabilities, limits, destruction duties,
  opaque handles, and request metadata only. It has no provider registry or
  fallback, mutable effect buffer, algorithm/key identifier, platform effect,
  request-side completion or FIPS approval claim. Pending lifecycle is owned
  separately by the v0.16 upstream contract, still without an effect. MAC
  generation and verification are distinct, verification cannot request byte
  output, requests retain exact provider identity, and actual work must be
  charged by a later trusted effect boundary.
- The locked RFC closure and its roadmap mapping are recorded in the
  [RFC coverage audit](https://github.com/valkyoth/brynja/blob/main/docs/RFC_COVERAGE_AUDIT.md);
  the generated
  [protocol-surface coverage](https://github.com/valkyoth/brynja/blob/main/standards/protocol-surface-coverage.md)
  classifies every pinned IANA record and explicit non-registry decision;
  the generated
  [requirement coverage](https://github.com/valkyoth/brynja/blob/main/requirements/coverage.md)
  proves complete lifecycle and bidirectional mapping across the foundation,
  cryptography, encoding, PKIX, TLS, DTLS, QUIC-TLS, optional, HPKE, ECH,
  entropy, legacy, operational, and residual domains before implementation.

## Workspace

| Package | Role | Current status |
| --- | --- | --- |
| `brynja` | Modern production facade | Exposes cumulative foundations, record/DER/ASN.1 building blocks, and all six packaged-consumer-accepted portable FIPS 180-4 SHA-2 algorithms through v0.23.4; no TLS engine or provider effect |
| `brynja-core` | Bounded wire, buffer, error, state, provider, entropy, time, and mandatory security-outcome domains | Prior domains plus pending/FIPS-aware authority and mandatory security-outcome contracts implemented |
| `brynja-hash-core` | Fixed-output hash interfaces without algorithms | v0.1.0 implemented; allocation-free `no_std` support boundary |
| `brynja-hash-sha2` | Reusable SHA-2 family ownership | v0.1.0 contains all six complete portable FIPS 180-4 algorithms, opt-in forced APIs for every CPU candidate, and complete packaged downstream family acceptance at v0.23.4 |
| Future `brynja-hash-sha3` | Complete FIPS 202 SHA-3 and SHAKE family ownership | Planned from v0.24.0 through v0.24.2 |
| Future `brynja-mac-hmac` | Complete generic HMAC over admitted fixed-output hashes | Planned from v0.25.0 through v0.25.2 |
| `brynja-crypto` | Provider contracts, cryptographic composition, policy, AEADs, KDFs, RSA, ECC, and exact family integration | Reexports all six portable FIPS 180-4 SHA-2 algorithms; other planned cryptography and provider effects remain absent |
| `brynja-crypto-cpu` | Optional zero-dependency no_std ISA-kernel boundary | Published metadata v0.1.1; three SHA-256-family and two SHA-512-family candidates implemented; x86 SHA-512 is scalar-only; zero admitted backends |
| `brynja-crypto-cpu-std` | Directly selected host detector adapter | Published metadata v0.1.1; complete-family reporting with scalar fallback, RISC-V auto-detection disabled; absent from facade and FIPS graphs |
| `brynja-pki` | Bounded DER framing and admitted canonical ASN.1 values now; schema decoding, X.509, path validation, and revocation later | DER reader and canonical primitive/container foundations implemented; package remains published at 0.2.0 until the next checkpoint |
| `brynja-protocol` | Shared TLS 1.2/1.3 and DTLS 1.2/1.3 record envelopes | v0.1.0 implemented and published at v0.20.0; v0.19.0 exceptional pentest and retest passed |
| `brynja-tls` | Evergreen modern TLS facade and one-pass version router | Foundation only |
| `brynja-tls13` | Version-specific TLS 1.3 stream engine | Foundation only |
| `brynja-tls13-handshake` | Record-independent TLS 1.3 handshake shared with QUIC | Foundation only |
| `brynja-tls12` | Version-specific explicitly hardened TLS 1.2 engine | Foundation only |
| `brynja-quic-tls` | QUIC/TLS handshake integration | Foundation only |
| `brynja-dtls` | Modern DTLS engines | Foundation only |
| Future `brynja-openpgp-core` | RFC 9580 packet, registry, resource, certificate, and key models | Planned from v0.163.0 |
| Future `brynja-openpgp-armor` | Allocation-free ASCII Armor over the admitted Base64 boundary | Planned from v0.165.0 |
| Future `brynja-openpgp` | Modern RFC 9580 Sans-I/O facade and operation engines | Planned through v0.180.0 |
| Future `brynja-openpgp-legacy` | Complete deprecated-algorithm and historical-key compatibility with no modern facade edge | Required before 1.0 and separately isolated |
| Future `brynja-legacy-sha1` | Complete streaming and fixed-message SHA-1 with legacy warnings | Planned at v0.24.3 and accepted at v0.24.5; OpenPGP consumers receive separate reviews at v0.169.2, v0.169.3, v0.169.5, and v0.171.2 |
| Future `brynja-legacy-md5` | Complete streaming and fixed-message MD5 with legacy warnings | Planned at v0.24.4 and accepted at v0.24.5 solely before isolated HMAC-MD5 compatibility |
| `brynja-platform` | Explicit entropy, time, storage, and I/O integration | Foundation only |
| `brynja-sanitization` | Optional protocol-neutral first-party sanitization adapter | v0.1.1 published over exact `sanitization 2.0.3`; absent from facade and FIPS graphs |
| `brynja-legacy` | Opt-in legacy facade; no default features | Boundary only |
| `brynja-legacy-*` engines | Complete TLS 1.2/1.1/1.0, DTLS 1.2/1.0, SSL, WTLS, PCT, and SNP compatibility with independent package policy | Boundaries exist; complete v0.180.1-v0.180.24 implementation chains are required before 1.0 |
| `brynja-test-support` | RFC 9850 key-log encoder plus deterministic random and clock fixtures | Implemented, unpublished, production-unreachable; never a randomness or production time source |
| Other repository-only crates | Tests, interop, tasks, and proof harnesses | Unpublished |

See the [legacy protocol plan](https://github.com/valkyoth/brynja/blob/main/docs/LEGACY_PROTOCOL_PLAN.md)
for the complete pre-1.0 implementation, warning, containment, audit, and
pentest line required for every named obsolete protocol.

## Platform Policy

The protocol and cryptographic cores must remain portable `no_std` Rust.
Day-one CI is designed to compile the workspace for Linux, Windows, FreeBSD,
macOS, Android, and iOS, and to run host tests on Linux, Windows, and macOS.
Aesynx is a planned portability target: no API may assume a current operating
system, allocator, socket type, filesystem, clock, or platform RNG.

See [Platform Support](https://github.com/valkyoth/brynja/blob/main/docs/platform-support.md).

## Trust Dashboard

| Area | Policy |
| --- | --- |
| License | `MIT OR Apache-2.0` |
| MSRV | Rust `1.90.0` |
| Pinned stable toolchain | Rust `1.97.1` |
| Kani verifier pairing | `cargo-kani 0.67.0` on Rust `1.90.0`; separate evidence only |
| Default target | `no_std` |
| Cryptographic implementation | First-party Rust only; foreign/native cryptographic modules and wrappers are forbidden |
| External crates | Rejected unless a numbered admission freezes an exact minimal graph; planned `base64-ng` use is encoding-only and future rustls/Tokio API dependencies remain isolated |
| First-party companion crates | Exact `sanitization 2.0.3` is reachable only through the optional adapter; future `base64-ng` admission requires default features off, no allocation for protocol use, and no cryptographic or FIPS edge |
| Unsafe Rust | Six exact source-hash-bound modules admit the v0.11 volatile clearer plus SHA-256 attestation, x86 SHA, AArch64 SHA2, RV64 Zknh inline assembly, and std detector boundaries; every other site is mechanically forbidden |
| Default networking | None |
| Legacy protocols in `brynja` | Impossible by package boundary |
| FIPS 140-3 status | Planned Level 1 software-module path; not validated |
| Production readiness | Not before an exact independently reviewed TLS and OpenPGP `1.0.0-rc.N` candidate |

## Rust Version Support

The MSRV is Rust `1.90.0`. Development and full release evidence are pinned
to Rust `1.97.1`, the current stable patch release checked on 2026-08-14.
The release preflight queries upstream again and fails closed if the pin or
tooling is stale.

Kani does not set the crate compiler baseline. Its compiler-sensitive proof
path is separately pinned to `cargo-kani 0.67.0` with Rust `1.90.0`, following
the documented `base64-ng` model. v0.10.0 admits no Kani proof harness, so the
successful policy check is not formal-verification evidence.

| Rust toolchain | Required evidence |
| --- | --- |
| `1.90.0` | Workspace all-feature compatibility check |
| `1.91.0` | Workspace all-feature compatibility check |
| `1.92.0` | Workspace all-feature compatibility check |
| `1.93.0` | Workspace all-feature compatibility check |
| `1.94.0` | Workspace all-feature compatibility check |
| `1.95.0` | Workspace all-feature compatibility check |
| `1.96.0` | Workspace all-feature compatibility check |
| `1.96.1` | Workspace all-feature compatibility check |
| `1.97.0` | Workspace all-feature compatibility check |
| `1.97.1` | Full format, lint, test, platform, policy, docs, package, and security gate |

The v0.12 constant-time emitted-code witness additionally runs on every listed
stable compiler for the x86_64 Linux host and on all nine promised targets with
Rust 1.97.1. This matrix is compiler evidence for the bounded witness, not a
timing or independent-verification claim.

Patch releases are listed separately when they are stable releases that the
project promises to support. The authoritative matrix is
[CRATE_VERSION_MATRIX.md](https://github.com/valkyoth/brynja/blob/main/docs/CRATE_VERSION_MATRIX.md).

## Checks

```bash
scripts/checks.sh
scripts/check-rust-version-matrix.sh
scripts/release_crates.py --check
scripts/release_crates.py --package-check
python3 scripts/check-verification-status.py
python3 scripts/test-verification-status.py
python3 scripts/check-assurance.py
python3 scripts/test-assurance.py
scripts/check-bare-metal.sh
scripts/check-kani.sh
python3 scripts/check-unsafe-policy.py
python3 scripts/check-first-party-rust-crypto.py
python3 scripts/test-first-party-rust-crypto.py
python3 scripts/check-constant-time.py
python3 scripts/test-constant-time.py
scripts/check-constant-time-codegen.sh 1.97.1 x86_64-unknown-linux-gnu
python3 scripts/test-constant-time-codegen.py
python3 scripts/check-constant-time-evidence.py
python3 scripts/test-constant-time-evidence.py
python3 scripts/check-provider-contract.py
python3 scripts/test-provider-contract.py
python3 scripts/check-entropy-contract.py
python3 scripts/test-entropy-contract.py
python3 scripts/check-clock-contract.py
python3 scripts/test-clock-contract.py
python3 scripts/check-pending-contract.py
python3 scripts/test-pending-contract.py
python3 scripts/check-fips-architecture.py
python3 scripts/test-fips-architecture.py
python3 scripts/check-security-outcome.py
python3 scripts/test-security-outcome.py
python3 scripts/check-security-event.py
python3 scripts/test-security-event.py
python3 scripts/check-backend-contract.py
python3 scripts/test-backend-contract.py
python3 scripts/check-cpu-evidence.py
python3 scripts/test-cpu-evidence.py
scripts/check-cpu-admission-fixture.sh
python3 scripts/check-zeroization-evidence.py
scripts/check-zeroization-codegen.sh 1.97.1 x86_64-unknown-linux-gnu
scripts/check-sanitization-adapter-codegen.sh 1.97.1 x86_64-unknown-linux-gnu
scripts/check-zeroization-miri.sh
scripts/check-zeroization-sanitizer.sh
scripts/check-github-release-controls.py
python3 scripts/check-standards-ledger.py
python3 scripts/check-protocol-surfaces.py
python3 scripts/check-requirements.py
python3 scripts/check-asn1-values.py
python3 scripts/test-asn1-values.py
python3 scripts/check-sha256.py
python3 scripts/test-sha256.py
scripts/check-sha256-cpu-codegen.sh
cargo deny check
cargo audit
scripts/tag_gate.sh v0.23.4
```

The networked `scripts/check_latest_tools.sh` check is mandatory before a
signed tag. `scripts/tag_gate.sh vX.Y.Z` runs the complete automated tag gate
and applies the stage-specific final check: ordinary development milestones
require no scheduled pentest, exceptional development milestones require their
PASS report without publication, and public checkpoints require their
cumulative PASS report. GitHub CodeQL uses Default setup; this repository
intentionally does not add an advanced CodeQL workflow.

After an exact green public-checkpoint candidate is pentested and tagged, the
interactive crates.io publisher is, for example:

```bash
scripts/release_crates.py --version 0.20.0
```

It reruns the complete release gate, publishes changed dependencies in order,
waits for crates.io indexing between dependent packages, and publishes
`brynja` last. Publication accepts signed annotated tag subjects using the
proper project capitalization, `Brynja vX.Y.Z`, and retains compatibility with
the historical lowercase `brynja vX.Y.Z` form.

Every milestone waits for green GitHub and CodeQL before the user authorizes
its signed tag. At scheduled or exceptional public checkpoints, the
implementation and cumulative versioned PASS report are committed together.
Any later CI-driven fix must update that report in the same commit before the
candidate can be tagged and published.

## Documentation

- [Initial idea and final architecture decision](https://github.com/valkyoth/brynja/blob/main/docs/initial-idea.md)
- [Implementation plan](https://github.com/valkyoth/brynja/blob/main/docs/IMPLEMENTATION_PLAN.md)
- [Release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md)
- [Version plan](https://github.com/valkyoth/brynja/blob/main/docs/VERSION_PLAN.md)
- [Threat model](https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md)
- [First-party Rust cryptography golden rule](https://github.com/valkyoth/brynja/blob/main/docs/first-party-rust-cryptography.md)
- [Component verification status](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md)
- [Standards source policy](https://github.com/valkyoth/brynja/blob/main/docs/rfc-source-policy.md)
- [Machine-readable standards evidence](https://github.com/valkyoth/brynja/blob/main/standards/README.md)
- [Normative requirement evidence](https://github.com/valkyoth/brynja/blob/main/requirements/README.md)
- [Permanent evidence index](https://github.com/valkyoth/brynja/blob/main/docs/evidence-index.md)
- [Assurance harness policy](https://github.com/valkyoth/brynja/blob/main/assurance/README.md)
- [Kani verifier policy](https://github.com/valkyoth/brynja/blob/main/docs/KANI.md)
