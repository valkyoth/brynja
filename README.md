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

These tables track concrete public capabilities and the named implementation
families in Brynja's active pre-1.0 roadmap. A capability is listed as
implemented only after its complete public API and required acceptance evidence
for that named milestone pass; a planned row is not yet usable.
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

### Modern Hash Functions

SHA-2 covers SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256;
SHA-3/SHAKE covers SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256.

| Hash family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| SHA-2 | ✅ Fully implemented | `brynja-hash-sha2` | ❌ Not independently verified |
| SHA-3/SHAKE | ✅ Fully implemented | `brynja-hash-sha3` | ❌ Not independently verified |
| TupleHash/TupleHashXOF | ✅ Fully implemented | `brynja-hash-tuple` | ❌ Not independently verified |
| ParallelHash/ParallelHashXOF | ✅ Fully implemented | `brynja-hash-parallel` | ❌ Not independently verified |
| SP 800-185 family | ✅ Fully implemented | `brynja-hash-sha3`, `brynja-mac-kmac`, `brynja-hash-tuple`, `brynja-hash-parallel` | ❌ Not independently verified |

SP 800-185 portable acceptance passed at v0.24.16; final acceptance passed at v0.24.17.
All fourteen ordinary/hardened identities and parallel execution
routes have passing or explicit unadmitted dispositions. CPU candidates remain
unadmitted; implementation completion is not independent review or FIPS validation.

### Modern Message Authentication

The complete KMAC/KMACXOF family here comprises KMAC128, KMAC256,
KMACXOF128, and KMACXOF256.

| Construction family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| KMAC/KMACXOF | ✅ Fully implemented | `brynja-mac-kmac` | ❌ Not independently verified |

### Legacy Hash Functions

Legacy hashes remain outside the modern `brynja` facade and require an explicit
legacy crate dependency even after implementation.

| Hash family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| SHA-1 | 🗓 Planned — v0.24.18–v0.24.23 | `brynja-legacy-sha1` | ❌ Not independently verified |
| MD5 | 🗓 Planned — v0.24.19–v0.24.23 | `brynja-legacy-md5` | ❌ Not independently verified |

### Protocol And PKI Building Blocks

| Capability | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| TLS and DTLS record-envelope parsing and encoding | ✅ Implemented | `brynja-protocol` | ❌ Not independently verified |
| Bounded DER framing and admitted canonical ASN.1 values | ✅ Implemented | `brynja-pki` | ❌ Not independently verified |

### Security Foundations

| Capability | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| Fixed-width constant-time operations and secret-region lifecycle | ✅ Implemented | `brynja-core` | ❌ Not independently verified |
| Fixed-size secret ownership and explicit sanitization adapter | ✅ Implemented | `brynja-core`, `brynja-sanitization` | ❌ Not independently verified |

### Official Validation

FIPS validation is a separate official claim from implementation and
independent source review.
Brynja has no FIPS 140-3 validation, certificate, validated module, approved
security policy, or certificate-bound operational-environment claim.

| Validation scope | Implementation status | Owning crate | Official validation |
| --- | --- | --- | --- |
| FIPS 140-3 cryptographic module | ❌ Not implemented | Future `brynja-fips-module`, `brynja-fips` | ❌ Not FIPS validated |

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

A later pre-1.0 phase adds `brynja-openpgp-core`,
`brynja-openpgp-armor`, and `brynja-openpgp`. Packet framing, certificates,
keys, signatures, encryption, compression, trust policy, and deprecated
compatibility remain separate review boundaries. The plan includes exact
modern RFC 9580 operations, isolated strong-v4 and v1-SEIPD compatibility,
exhaustive packet/subpacket dispositions, and downstream fixtures proving that
public Brynja APIs are sufficient to build an OpenPGP protocol client. UI,
storage, networking, key discovery, identity trust, and PGP/MIME remain
application-owned. OpenPGP is outside the FIPS validated-module plan. Base64 is the one encoding algorithm Brynja does not
plan to duplicate: v0.88.1 will audit the latest stable first-party
`base64-ng` family and admit only an exact-pinned, allocation-free `no_std`
edge suitable for PEM and OpenPGP armor.

Before `1.0.0`, the roadmap also includes separately selectable modern, legacy,
utility and research hashing families, MACs, checksums, password hashing,
field/ZK hashes and perceptual profiles. The
[unified release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md#unified-catalogue-scope-and-api-contracts)
assigns complete APIs, internal cleanup, real-use tests and final evidence gates;
the [scope register](docs/CATALOGUE_SCOPE_REGISTER.json) maps every catalogue
entry to its versions and existing or new owner. Small family crates keep the
dependency graph selective: the main facade never gains an `all-hashes` feature.
This is planned scope, not an implementation, security, independent-review or
FIPS claim. Unavailable RISC-V native/community qualification remains post-1.0.

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

The signed `0.23.4` milestone closes the complete SHA-2 chain with a
standalone downstream `no_std` consumer. It exercises all six algorithms
through both leaf and facade public APIs over independent empty, text, binary,
multi-block, million-byte, and file-like expectations in one-shot and
irregular streaming modes. The same consumer runs from safely extracted
offline Cargo archives with version-only dependencies. Adversarial fixtures
reject expectation, identity, output-width, export, documentation, backend-
accounting, feature, and package-content regressions. This establishes
consumer usability; it does not admit a CPU backend or add independent review,
FIPS validation, or secret-state erasure.

The signed `0.24.0` milestone starts the FIPS 202 family in
the new `brynja-hash-sha3` leaf crate. Complete portable SHA3-224 and
SHA3-256 use one private safe-Rust Keccak-f[1600] permutation and distinct
144-byte and 136-byte rates. Official examples, million-byte inputs, exact
padding boundaries, irregular streaming partitions, checked counter
exhaustion, two bounded Kani harnesses, and 328-message differential tests
pass. Raw Keccak, SHA3-384, SHA3-512, SHAKE, and acceleration remain absent;
the family therefore stays visibly In progress.

The exceptional v0.24.0 assessment found one High assurance supply-chain
issue: generated Cargo artifacts, including executables, were tracked beneath
the SHA-3 differential fixture. All 241 artifacts were removed, nested Cargo
targets are ignored and rejected by policy, and differential execution now
uses a fresh locked non-incremental target. Independent retest of exact
remediation candidate `208cde2b24e9aef314e2a59e530a5fd0f659151d`
passed with zero open findings. This is pentest evidence, not independent
cryptographic verification or FIPS validation.

Signed `0.24.1` completed portable SHA3-384 and SHA3-512 over that same private
permutation and sponge owner. Signed `0.24.2`
adds complete SHAKE128 and SHAKE256 with distinct consuming absorb and
incremental squeeze states, exact 168-byte and 136-byte rates, the FIPS 202
SHAKE domain suffix, zero-length and arbitrary caller-bounded output, checked
input/output counters, official examples, rate and multi-squeeze boundaries,
and all-six-function differential coverage. Portable-family package acceptance,
acceleration, secret-state erasure, independent review, and FIPS validation
remain later gates, so the SHA-3/SHAKE family remains **In progress**.

The exceptional v0.24.2 assessment and first retest supplied two Medium denial-
of-service findings in the repository-only differential adapter. The adapter
now enforces its declared 343-byte output, 8 MiB stdin, and 1,968-case ceilings,
uses fallible decode and rendering allocations, and gives every child run a
240-second timeout. Production SHAKE code is unchanged. Independent second
retest of exact candidate `c7af70e19def950f3a9004c18e5c869ef844c644`
passed with zero open findings; the milestone is signed and selects zero
crates.io packages.

Signed `0.24.3` freezes a standalone downstream
`no_std` consumer over all six FIPS 202 identities. It checks leaf and facade
one-shot, irregular streaming, zero-output, exact-rate, multi-rate, 257-byte
real-file and 343-byte multi-squeeze paths against official or independently
generated expectations. The same consumer runs offline from a safely
extracted exact sixteen-package archive closure with version-only dependencies.
Executable negative fixtures reject corrupted outputs, missing semantics,
hidden features, invalid absorb/squeeze phases, private permutation access,
and incomplete packages. No production algorithm or backend changes; the
byte-oriented consumer is accepted, but the family remains **In progress**
through v0.24.11 while the newly explicit arbitrary-bit and hardened secret-
bearing API profiles, backend evidence, and combined package-external
acceptance are completed.

The voluntary v0.24.3 assessment found one Low assurance-control gap in that
repository-only fixture: its declared forbidden Clippy lints were not executed.
The warning is corrected, local and hosted warnings-denied runs are mandatory,
and policy mutations reject removal of either binding. Independent retest of
exact candidate `c7bd354e5bcf9a816c366cf24d0d88347771afc5` passed with zero
open findings. The permanent
[v0.24.3 report](https://github.com/valkyoth/brynja/blob/main/security/pentest/v0.24.3.md)
records `PASS`/`PASS`; it does not add independent cryptographic review, FIPS
validation, backend admission, or crates.io publication.

Signed internal `0.24.4` adds two isolated first-party
Keccak-f[1600] acceleration paths: x86_64 AVX2 and AArch64 SHA3 instructions.
Direct KATs, permanent session quarantine, a 1,024-state permutation
differential, all-six-identity fixed-output/XOF comparisons, compiler-endpoint
instruction checks, and supplemental AArch64 QEMU execution pass. Both paths
remain unadmitted; ordinary consumers continue to use portable SHA-3/SHAKE.
RISC-V is explicitly scalar-only because the pinned ratified authorities
contain no qualifying Keccak instruction route. The exceptional assessment of
exact implementation candidate `2f755e821e31da9a5524320986c3eb9400f3cfad`
passed with zero open findings; the permanent
[v0.24.4 report](https://github.com/valkyoth/brynja/blob/main/security/pentest/v0.24.4.md)
records `PASS`/`PASS`. Native Intel, Apple M2, and AWS Arm observations,
performance, migration, side-channel, independent-review, secret-erasure, and
FIPS-validation claims remain pending or absent, so both backends stay
unadmitted.

Signed internal `0.24.5` adds a fail-closed standards lifecycle
monitor without changing production Rust or cryptographic behavior. Its
machine-readable register separates official upstream state from Brynja's
current, compatibility, legacy-only, disabled, and rejected decisions across
all 130 locked RFC, NIST, ITU-T, RISC-V, and IANA authorities. Weekly, manual,
and pre-tag observations are bounded and read-only: changed bytes, publication
status, planning notices, replacements, errata, registry metadata, rollback,
parser drift, redirect, timeout, or outage create a review-required artifact
and cannot update code or policy. The first strict 2026-08-31 run detected RFC
9846 editorial erratum 9157; human review retained it as unverified and
track-not-applied, refreshed its exact evidence, and the final complete
observation passed with zero new or unresolved drift. The v0.24.11 release gate
later detected reported technical RFC 9846 erratum 9161; human review likewise
kept its presentation-syntax clarification unverified and track-not-applied,
and the refreshed September 3 observation passed with zero unresolved drift.

The voluntary v0.24.5 assessment found three Medium assurance defects.
The remediated monitor rejects malformed HTTP-200 errata pages unless they
contain records or exactly one official empty marker; archives every
content-identified observation before review and requires exact authority,
affected-object, real roadmap, repository-evidence, and committed passing
exceptional-pentest bindings for security changes; and creates tag artifacts
exclusively inside private unpredictable directories without following
pre-existing paths. Its first retest closed the malformed-response and symlink
findings but identified one residual Medium append-only-history bypass. The
monitor now requires complete Git history and compares every reachable
schema-2 archive version; real Git fixtures cover shallow history, a deletion
hidden by a later unrelated commit, and unavailable historical blobs. The
final independent retest of exact signed candidate
`116afe2390b61561c0d4414aa2a2dafbc3658a80` passed; the permanent report records
`PASS`/`PASS` with zero open findings.

Signed internal `0.24.6` makes complete cryptographic API
profiles and private secret-state cleanup machine-checkable before later
algorithms can claim completion. All 129 semantic capabilities receive 22 API
dimensions and an exact milestone owner; eight current and 75 planned secret
owners are present, while zero capability owners are registered. Current
owners must pass adjacent compiler-checked type, private-field, and sanitizer
contracts plus exact optimized-MIR cleanup-call checks under both supported
compiler endpoints;
future registered owners must match a separate canonical compiler contract;
three exact-coverage maps derive their unique owner test, nonempty caller
headers, and nonempty declared-sanitizer MIR target, while registrations cannot
supply their own expected cleanup expression; planned owners cannot
masquerade as executable symbols. Every operation has
its own public, secret, or no-output classification, failure behavior, and
authentication timing. A standalone
zero-dependency `no_std` contract rejects downstream hardened-marker forgery,
ordinary-state substitution, output-classification drift, retained partial
secret output, and missed Drop or recoverable-unwind cleanup. The voluntary
pentest and nine retests found thirteen Medium assurance-control gaps in the
original, lexical-remediation, future-registration, empty-value, identifier-
prefix, namespace, callable-identity, and MIR place/data-flow evidence paths;
all remediations pass locally, and the independent tenth retest reported zero
open findings. The permanent report records `PASS`/`PASS`; the signed tag was
created after hosted GitHub and CodeQL passed. The generated
[API-profile and secret-state register](https://github.com/valkyoth/brynja/blob/main/docs/cryptographic-api-profile-register.md)
is a closure gate, not a new cryptographic implementation or verification
claim; SHA-2 and SHA-3/SHAKE remain **In progress** until their later bit-input,
hardened-state, backend, and combined acceptance milestones pass.

Signed internal `0.24.8` adds distinct hardened streaming states for
all six SHA-2 identities over the same FIPS 180-4 compression algorithms and
canonical byte/bit domains. Hardened owners keep every source-declared
chaining state, partial input, schedule, block copy, padding block, length,
phase, and staged output in registered byte regions that pass compiler-
resistant destruction evidence. Public digest release consumes an explicit
declassification token; secret digest release transfers a typed caller-owned
region that clears on `Drop`, error, and recoverable unwind. Downstream code
cannot forge the sealed hardened capability, clone or format a hardened state,
reset it into an ordinary state, or select an unproved accelerated backend.

Ordinary SHA-2 remains available for public/unkeyed data without an erasure
claim. Hardened cleanup covers Brynja-owned, source-declared memory; it cannot
promise erasure of compiler-created copies, registers, caches, dumps,
`mem::forget`, abort, forced termination, suspend images, or physical memory.
SHA-2 therefore remains **In progress** until the combined v0.24.11 acceptance
pass, and this milestone does not claim independent review, FIPS validation,
backend admission, or crates.io publication.

Two supplied security assessments of exact v0.24.8 implementation candidate
`9bb19a27d5ce957a2cf4474e88e445dce7950da3` reported no Critical, High, or
Medium finding. The
[permanent exceptional report](https://github.com/valkyoth/brynja/blob/main/security/pentest/v0.24.8.md)
records `PASS`/`PASS`, zero open findings, and no remediation. This does not
replace independent cryptographic review, FIPS validation, or the scheduled
v0.20.0-to-v0.25.0 cumulative assessment.

The signed internal `0.24.9` milestone completes the FIPS 202 arbitrary-bit domain
for all four SHA-3 digests and both SHAKE XOFs. A distinct
`Fips202BitString` makes FIPS 202's least-significant-bit-first partial-byte
representation explicit instead of reusing SHA-2's incompatible convention;
`Fips202Output` also permits every SHAKE output bit length with canonical
zeroed high tail bits. One-shot, incremental final-tail and consuming
final-bit squeeze APIs are available through both the leaf crate and facade.

Seventy-six curated records imported from checksum-pinned official NIST CAVP
archives, all six official five-bit examples, 440 independent bounded oracle
cases, Kani bounds, Miri, AddressSanitizer, package-external `no_std`
acceptance and malformed-input tests cover this boundary. Ordinary state still
makes no secret-remanence claim.

The
[permanent exceptional report](https://github.com/valkyoth/brynja/blob/main/security/pentest/v0.24.9.md)
records `PASS`/`PASS`, zero open findings, and no Critical, High, or Medium
finding for exact implementation candidate
`3f6669f670472cea4f2a162e545db456ee368530`. No remediation was required. The
assessment does not replace independent cryptographic review, FIPS validation,
or the scheduled cumulative v0.20.0-to-v0.25.0 assessment.

Subsequent v0.24.1 pentest review found one Medium assurance-control gap: the
committed CI scripts did not enforce the release note's SHA3-384/SHA3-512 Miri
and AddressSanitizer claim. Both paths are now enforced and fail closed under
the SHA-3 policy; local remediation verification passes with zero open
findings. Independent retest of exact remediation candidate
`31ce5c95fdf4ea5eb6f1bb942de9f06c3f11f6d2` was reported green, and the
permanent report records `PASS`/`PASS`. This does not create an independent
cryptographic review, FIPS validation, accelerated-backend admission, or
crates.io publication.

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
v0.173.0 and v0.175.1 require an opaque module-owned attestation that only the
complete final-image integrity and pre-operational self-tests can issue.

Permanent failure is currently caller-session-scoped. That has no executable
bypass today because every service is non-approved and no provider effect
exists. Before executable or approved FIPS services exist, v0.175.0 must make
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
first-party `sanitization 2.0.4`, disables every upstream feature, activates no
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
and 1.98.1 emitted all four required scalar SHA-256 instructions and the QEMU
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

The internal `0.24.10` release candidate adds distinct sealed hardened states
for all four SHA-3 digests and both SHAKE XOFs. A byte-backed private owner
accounts for eleven sponge, input/output, lifecycle, staging and
permutation-scratch regions and clears them through the compiler-resistant core
boundary on completion, failure, cancellation, recoverable unwind and Drop.
Public output requires an explicit declassification token; secret output
transfers affine ownership of the complete caller destination and clears it on
Drop.

Hardened-versus-ordinary differential tests cover all identities, rates, bit
tails and multi-squeeze boundaries. Package-external `no_std`, strict source
policy, Miri, AddressSanitizer, 18 cumulative Kani properties, and Rust
1.90.0/1.98.1 MIR/LLVM/assembly cleanup checks are mandatory. Accelerated
hardened execution remains prohibited. SHA-3/SHAKE remains **In progress**
until v0.24.11 combined acceptance, and this candidate does not claim
independent review, FIPS validation, backend admission, or publication.

Its initial exceptional assessment reported one High secret-derived
byte-array remanence finding. Exact remediation candidate
`b3232116a66f908524d859aa40d1b1ab8e31f913` replaces those arrays with bounded
scalar conversion and registered owner staging, adds every-width cleanup and
compiler-artifact regression gates, and passed repository-owner retest with
zero open findings. The
[permanent exceptional report](https://github.com/valkyoth/brynja/blob/main/security/pentest/v0.24.10.md)
records `PASS`/`PASS`; independent cryptographic review and FIPS validation
remain absent.

The internal `0.24.11` candidate freezes and runs the SHA-2 and SHA-3/SHAKE
package-external ordinary, arbitrary-bit, hardened public/secret, and XOF
profiles together. It records all seven optional CPU candidates explicitly as
unadmitted, preserves portable fallback, and binds the detailed differential,
proof, sanitization, compiler-artifact, unavailable, quarantine, error,
cancellation, unwind, and Drop evidence to the final source. Both exact
families are now **Fully implemented**; neither is independently verified or
FIPS 140-3 validated.

The voluntary assessment found no Critical, High, or Medium security
vulnerability. Its one non-security status inconsistency is corrected and the
retest passed; the permanent
[v0.24.11 report](https://github.com/valkyoth/brynja/blob/main/security/pentest/v0.24.11.md)
records `PASS`/`PASS` with zero open findings.

Signed `0.24.12` adds the complete allocation-free SP 800-185
encoding foundation and complete cSHAKE128/cSHAKE256 byte and arbitrary-bit
APIs. Ordinary one-shot, streaming, fixed-output and incremental-XOF paths
coexist with hardened secret-bearing owners and explicit public/typed-secret
output classification. All official NIST cSHAKE examples, exact SHAKE
equivalence for empty N/S, a 480-case independent arbitrary-bit oracle, bounded
malformed-input rejection, package-external `no_std` consumers, sanitizer,
focused Miri and twenty cumulative Kani bounds are bound into policy. The
wider SP 800-185 family remained **In progress** at v0.24.12 pending KMAC,
TupleHash, ParallelHash and combined acceptance; cSHAKE is not independently
verified or FIPS 140-3 validated. Its initial exceptional assessment found one
Medium hardened metadata-remanence gap; the remediation moves both metadata
values into the registered clearing owner, covers all thirteen regions in
compiler evidence, and the exact-candidate retest passed. The permanent
[v0.24.12 report](https://github.com/valkyoth/brynja/blob/main/security/pentest/v0.24.12.md)
records `PASS`/`PASS` with zero open findings.

Signed `0.24.13` adds complete KMAC128, KMAC256, KMACXOF128,
and KMACXOF256 over the exact hardened cSHAKE owner. Strength-enforcing
constructors form the default surface; exact conformance constructors require
the explicit `conformance-testing` leaf-crate feature and cannot appear through
ordinary default-build autocomplete. Fixed tags are
opaque and use constant-time verification; XOF output is typed secret unless
explicitly declassified. Official examples, a separately composed arbitrary-
bit oracle, package-external `no_std` use, twenty-two cumulative Kani bounds,
Miri, AddressSanitizer, timing checks, and Rust 1.90.0/1.98.1 cleanup evidence
are bound to the implementation. The pentest remediation additionally removes
inline `Option::take` state extraction and binds in-place source-allocation
clearing into compiler evidence; a follow-up terminal lifecycle prevents
reuse after extraction or explicit wiping. The exact final remediation retest
passed, and the permanent
[v0.24.13 report](https://github.com/valkyoth/brynja/blob/main/security/pentest/v0.24.13.md)
records `PASS`/`PASS` with zero open findings. KMAC is fully implemented but neither
independently verified nor FIPS 140-3 validated; the wider SP 800-185 family
remains in progress until TupleHash, ParallelHash, and final acceptance pass.

Signed `0.24.14` adds complete TupleHash128, TupleHash256,
TupleHashXOF128, and TupleHashXOF256 in the allocation-free `no_std`
`brynja-hash-tuple` leaf. Whole and exact-length streamed tuple items preserve
item identity, order, empty values, and canonical arbitrary-bit tails; fixed
and incremental XOF output, customization, ordinary and hardened owners, typed
secret output, checked bounds, abandoned-item failure, official examples, an
independent differential oracle, package-external use, proofs, Miri,
AddressSanitizer, and Rust 1.90.0/1.98.1 cleanup evidence are bound to the
implementation. TupleHash is fully implemented but is neither independently
verified nor FIPS 140-3 validated. ParallelHash and combined SP 800-185 final
acceptance remain pending. Its initial exceptional assessment found two High,
two Medium, and two Low ownership, lifecycle, metadata, and assurance gaps;
the fixes now bind in-place cSHAKE phase changes, lifetime-bound readers,
fixed-output borrowing, exact source erasure, forgotten-writer failure,
clearing length metadata, direct partial-byte ownership, closed backend
strength, the production Kani path, and package-external no-copy compiler
evidence. A later retest's remaining High owner-copy and Medium gate-coverage
findings are remediated. The next retest confirmed the High fix and found two
Medium issues: the tuple count survived successful borrowed finalization, and
the LLVM/assembly copy matcher retained false-negative paths. The candidate now
clears all source-owned metadata before returning output or a borrowing reader,
tests fixed and XOF completion across ordinary and hardened owners, self-tests
the corrected LLVM matcher, and rejects every memcpy in isolated external
finalization functions. Independent retest of the exact TupleHash candidate
found no Critical, High, or Medium issue. The permanent
[v0.24.14 report](https://github.com/valkyoth/brynja/blob/main/security/pentest/v0.24.14.md)
records `PASS`/`PASS` with zero open findings after the focused retest of the
later exact `sanitization 2.0.4` dependency delta also found no Critical,
High, or Medium issue.

Signed `0.24.15` adds complete ParallelHash128,
ParallelHash256, ParallelHashXOF128, and ParallelHashXOF256 in the
allocation-free `no_std` `brynja-hash-parallel` leaf. The caller-selected
workspace length is the exact positive `B`; empty, partial, multi-leaf,
customized, fixed, XOF, streaming, and canonical arbitrary-bit inputs use the
same hardened cSHAKE owner. Indexed caller-scheduled leaf jobs retain typed
secret result ownership and an ordered collector rejects missing, duplicated,
reordered, or differently shaped results. The separate zero-third-party-dependency
`brynja-hash-parallel-std` host adapter adds explicit worker and leaf-work
limits, a fail-closed single-operation permit per executor, worker-sized
reusable storage, pre-allocation cancellation, fallible OS thread creation,
panic containment, deterministic joining, and no default, bare-metal, facade,
or FIPS edge. Callers must share one executor for one aggregate budget rather
than create an executor per request. All twelve official NIST examples
pass. ParallelHash is implemented but neither independently verified nor FIPS
140-3 validated; combined family acceptance remains at v0.24.16-v0.24.17.

Signed `0.24.16` freezes one package-external `no_std`
consumer contract across all fourteen cSHAKE, KMAC/KMACXOF,
TupleHash/TupleHashXOF, and ParallelHash/ParallelHashXOF identities. It checks
one exact official output per identity plus ordinary, hardened, streaming,
incremental-XOF, arbitrary-bit, zero-length, misuse, real-data, exact tuple
item, and caller-scheduled leaf paths. The same fixture is required across Rust
1.90.0–1.98.1 and every declared bare-metal target. Portable acceptance has
passed at that milestone. The unchanged contract now also passes final backend
and native-parallel disposition at v0.24.17; SP 800-185 is **Fully implemented**.

## Install

Brynja is not ready to secure application traffic and does not implement TLS.
The latest signed and crates.io checkpoint is `0.20.0`. Signed internal
milestones continue through `0.24.16`; the current internal `0.24.17`
SP 800-185 execution-acceptance candidate selects no crates.io publication.
It reruns the frozen portable contract and compares sequential, caller-scheduled
and threaded ParallelHash. The owner-supplied pentest passed with no findings;
same-commit AMD, Intel, AWS ARM and Apple M2 observations and every required
local release-check stage passed. SP 800-185 is **Fully implemented**; green
GitHub/CodeQL and explicit tag authorization are still required. No production
cryptography or backend admission changes. See the
[final acceptance procedure](https://github.com/valkyoth/brynja/blob/main/docs/sp800185-final-acceptance.md).
The published
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
  and OpenPGP armor after its v0.88.1 admission review; it never implements
  cryptography or enters `brynja-fips-module`. Future
  separately selected `brynja-rustls` and `brynja-tokio` companion adapters may
  depend only on the exact pure-Rust ecosystem API they implement, in separate
  lockfiles and graphs that can never enter or be enabled by `brynja`.
- Version `0.11.2` implements one separately selected
  `brynja-sanitization` adapter over admitted exact `sanitization 2.0.4`. It
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
- The generated
  [authority lifecycle register](https://github.com/valkyoth/brynja/blob/main/standards/authority-lifecycle.json)
  binds official landing pages, immutable content, RFC status and errata,
  registries, architecture specifications, reviewed impact, and affected
  requirements without allowing observations to reclassify Brynja.

## Workspace

| Package | Role | Current status |
| --- | --- | --- |
| `brynja` | Modern production facade | Internal v0.24.17 adds SP 800-185 execution acceptance around the same complete named hash/MAC APIs; native review is pending, CPU candidates remain unadmitted, and no TLS engine or provider effect exists |
| `brynja-core` | Bounded wire, buffer, error, state, provider, entropy, time, and mandatory security-outcome domains | Prior domains plus pending/FIPS-aware authority and mandatory security-outcome contracts implemented |
| `brynja-hash-core` | Fixed-output and extendable-output hash interfaces without algorithms | v0.1.0 implemented; allocation-free `no_std` support boundary |
| `brynja-hash-sha2` | Reusable SHA-2 family ownership | v0.1.0 contains all six fully implemented FIPS 180-4 ordinary and hardened byte and canonical arbitrary-bit APIs plus forced ordinary CPU-candidate APIs; all five candidates remain unadmitted |
| `brynja-hash-sha3` | Reusable SHA-3, SHAKE, cSHAKE, and SP 800-185 encoding foundations | v0.1.0 contains all six fully implemented FIPS 202 functions plus complete SP 800-185 encodings and cSHAKE128/cSHAKE256 ordinary and hardened byte/arbitrary-bit APIs; both CPU candidates remain unadmitted, and the wider SP 800-185 family passed final acceptance at v0.24.17 |
| `brynja-mac-kmac` | Complete KMAC128/256 and KMACXOF128/256 with secret-state cleanup and typed verification | v0.1.0 implemented internally at v0.24.13; unpublished until a public checkpoint, independently unverified, and not FIPS validated |
| `brynja-hash-tuple` | Complete TupleHash128/256 and TupleHashXOF128/256 with structural item boundaries and hardened ownership | v0.1.0 implemented internally at v0.24.14; unpublished until a public checkpoint, independently unverified, and not FIPS validated |
| `brynja-hash-parallel` | Complete allocation-free ParallelHash128/256 and ParallelHashXOF128/256 with hardened and ordered scheduling APIs | v0.1.0 implemented internally at v0.24.15; unpublished until a public checkpoint, independently unverified, and not FIPS validated |
| `brynja-hash-parallel-std` | Optional worker/leaf-budgeted native-thread ParallelHash executor with one operation at a time per executor and fallible thread creation | v0.1.0 implemented internally at v0.24.15; excluded from defaults, bare metal, facades, and FIPS boundaries |
| Future `brynja-mac-hmac` | Complete generic HMAC over admitted fixed-output hashes | Planned from v0.25.0 through v0.25.2 |
| `brynja-crypto` | Provider contracts, cryptographic composition, policy, AEADs, KDFs, RSA, ECC, and exact family integration | Reexports all six SHA-2 algorithms, all six FIPS 202 functions, complete cSHAKE, SP 800-185 encodings, all four KMAC/KMACXOF, TupleHash/TupleHashXOF, and ParallelHash/ParallelHashXOF constructions; other planned cryptography and provider effects remain absent |
| `brynja-crypto-cpu` | Optional zero-dependency no_std ISA-kernel boundary | Published metadata v0.1.1; five SHA-2 plus x86_64 AVX2 and AArch64 SHA3 Keccak candidates implemented; x86 SHA-512 and RISC-V Keccak are scalar-only; zero admitted backends |
| `brynja-crypto-cpu-std` | Directly selected host detector adapter | Published metadata v0.1.1; complete-family reporting with scalar fallback, RISC-V auto-detection disabled; absent from facade and FIPS graphs |
| `brynja-pki` | Bounded DER framing and admitted canonical ASN.1 values now; schema decoding, X.509, path validation, and revocation later | DER reader and canonical primitive/container foundations implemented; package remains published at 0.2.0 until the next checkpoint |
| `brynja-protocol` | Shared TLS 1.2/1.3 and DTLS 1.2/1.3 record envelopes | v0.1.0 implemented and published at v0.20.0; v0.19.0 exceptional pentest and retest passed |
| `brynja-tls` | Evergreen modern TLS facade and one-pass version router | Foundation only |
| `brynja-tls13` | Version-specific TLS 1.3 stream engine | Foundation only |
| `brynja-tls13-handshake` | Record-independent TLS 1.3 handshake shared with QUIC | Foundation only |
| `brynja-tls12` | Version-specific explicitly hardened TLS 1.2 engine | Foundation only |
| `brynja-quic-tls` | QUIC/TLS handshake integration | Foundation only |
| `brynja-dtls` | Modern DTLS engines | Foundation only |
| Future `brynja-openpgp-core` | RFC 9580 packet, registry, resource, certificate, and key models | Planned from v0.211.0 |
| Future `brynja-openpgp-armor` | Allocation-free ASCII Armor over the admitted Base64 boundary | Planned from v0.213.0 |
| Future `brynja-openpgp` | Modern RFC 9580 Sans-I/O facade and operation engines | Planned through v0.239.0 |
| Future `brynja-openpgp-legacy` | Complete deprecated-algorithm and historical-key compatibility with no modern facade edge | Required before 1.0 and separately isolated |
| Future `brynja-legacy-sha1` | Complete streaming and fixed-message SHA-1 with legacy warnings | Portable implementation at v0.24.18, frozen acceptance at v0.24.20, SHA-instruction acceleration at v0.24.21, and final cross-backend closure at v0.24.23; OpenPGP consumers receive separate reviews at v0.225.1, v0.225.2, v0.226.0, and v0.230.2 |
| Future `brynja-legacy-md5` | Complete streaming and fixed-message MD5 with legacy warnings | Portable implementation at v0.24.19, frozen acceptance at v0.24.20, multi-buffer SIMD at v0.24.22, and final cross-backend closure at v0.24.23 solely before isolated HMAC-MD5 compatibility |
| `brynja-platform` | Explicit entropy, time, storage, and I/O integration | Foundation only |
| Future `brynja-platform-security` | Optional `no_std` protected-region contract and typed enforcement evidence | Planned at v0.174.1; never performs hidden OS effects |
| Future `brynja-platform-security-std` | Optional Linux, Android, Windows, macOS, iOS, and BSD protected-memory providers | Planned at v0.174.2-v0.174.5; outside every default graph |
| `brynja-sanitization` | Optional protocol-neutral first-party sanitization adapter | v0.1.1 published; current source exact-pins `sanitization 2.0.4`; absent from facade and FIPS graphs |
| `brynja-legacy` | Opt-in legacy facade; no default features | Boundary only |
| `brynja-legacy-*` engines | Complete TLS 1.2/1.1/1.0, DTLS 1.2/1.0, SSL, WTLS, PCT, and SNP compatibility with independent package policy | Boundaries exist; complete v0.240.0-v0.249.0 implementation chains are required before 1.0 |
| `brynja-test-support` | RFC 9850 key-log encoder plus deterministic random and clock fixtures | Implemented, unpublished, production-unreachable; never a randomness or production time source |
| Other repository-only crates | Tests, interop, tasks, and proof harnesses | Unpublished |

See the [unified legacy release line](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md#complete-named-legacy-package-release-line)
for the complete pre-1.0 implementation, warning, containment, audit, and
pentest line required for every named obsolete protocol.

## Platform Policy

The protocol and cryptographic cores must remain portable `no_std` Rust.
Day-one CI is designed to compile the workspace for Linux, Windows, FreeBSD,
macOS, Android, and iOS, and to run host tests on Linux, Windows, and macOS.
Aesynx is a planned portability target: no API may assume a current operating
system, allocator, socket type, filesystem, clock, or platform RNG.

The future v0.174.1-v0.174.5 high-assurance layer is explicitly opt-in. It can
require protected pages and verify supported process controls, but it cannot
guarantee erasure of registers, caches, caller-owned copies, dumps, swap,
hibernation, DMA-visible memory, forced termination, or physical media unless
the responsible platform or operator supplies authoritative evidence. Missing
mandatory controls fail closed rather than silently falling back.

See [Platform Support](https://github.com/valkyoth/brynja/blob/main/docs/platform-support.md).

## Trust Dashboard

| Area | Policy |
| --- | --- |
| License | `MIT OR Apache-2.0` |
| MSRV | Rust `1.90.0` |
| Pinned stable toolchain | Rust `1.98.1` |
| Kani verifier pairing | `cargo-kani 0.67.0` on Rust `1.90.0`; separate evidence only |
| Default target | `no_std` |
| Cryptographic implementation | First-party Rust only; foreign/native cryptographic modules and wrappers are forbidden |
| External crates | Rejected unless a numbered admission freezes an exact minimal graph; planned `base64-ng` use is encoding-only and future rustls/Tokio API dependencies remain isolated |
| First-party companion crates | Exact `sanitization 2.0.4` is reachable only through the optional adapter; future `base64-ng` admission requires default features off, no allocation for protocol use, and no cryptographic or FIPS edge |
| Unsafe Rust | Nine exact source-hash-bound modules admit the v0.11 volatile clearer plus SHA-256/Keccak attestations, x86 SHA/AVX2 Keccak, AArch64 SHA2/SHA-512/SHA3 Keccak, RV64 Zknh inline assembly, and std detector boundaries; every other site is mechanically forbidden |
| Default networking | None |
| Legacy protocols in `brynja` | Impossible by package boundary |
| FIPS 140-3 status | Planned Level 1 software-module path; not validated |
| Production readiness | Not before an exact independently reviewed TLS and OpenPGP `1.0.0-rc.N` candidate |

## Rust Version Support

The MSRV is Rust `1.90.0`. Development and full release evidence are pinned
to Rust `1.98.1`, the current stable release checked on 2026-09-03.
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
| `1.97.1` | Workspace all-feature compatibility check |
| `1.98.0` | Workspace all-feature compatibility check |
| `1.98.1` | Full format, lint, test, platform, policy, docs, package, and security gate |

The v0.12 constant-time emitted-code witness additionally runs on every listed
stable compiler for the x86_64 Linux host and on all nine promised targets with
Rust 1.98.1. This matrix is compiler evidence for the bounded witness, not a
timing or independent-verification claim.

Patch releases are listed separately when they are stable releases that the
project promises to support. The authoritative matrix is
[CRATE_VERSION_MATRIX.md](https://github.com/valkyoth/brynja/blob/main/docs/CRATE_VERSION_MATRIX.md).

## Checks

```bash
scripts/checks.sh
scripts/ci/check-rust-version-matrix.sh
scripts/release/release_crates.py --check
scripts/release/release_crates.py --package-check
python3 scripts/repository/check-verification-status.py
python3 scripts/repository/test-verification-status.py
python3 scripts/assurance/check-assurance.py
python3 scripts/assurance/test-assurance.py
scripts/assurance/check-bare-metal.sh
scripts/assurance/check-kani.sh
python3 scripts/repository/check-unsafe-policy.py
python3 scripts/repository/check-first-party-rust-crypto.py
python3 scripts/repository/test-first-party-rust-crypto.py
python3 scripts/constant-time/check-constant-time.py
python3 scripts/constant-time/test-constant-time.py
scripts/constant-time/check-constant-time-codegen.sh 1.98.1 x86_64-unknown-linux-gnu
python3 scripts/constant-time/test-constant-time-codegen.py
python3 scripts/constant-time/check-constant-time-evidence.py
python3 scripts/constant-time/test-constant-time-evidence.py
python3 scripts/foundations/check-provider-contract.py
python3 scripts/foundations/test-provider-contract.py
python3 scripts/foundations/check-entropy-contract.py
python3 scripts/foundations/test-entropy-contract.py
python3 scripts/foundations/check-clock-contract.py
python3 scripts/foundations/test-clock-contract.py
python3 scripts/foundations/check-pending-contract.py
python3 scripts/foundations/test-pending-contract.py
python3 scripts/foundations/check-fips-architecture.py
python3 scripts/foundations/test-fips-architecture.py
python3 scripts/foundations/check-security-outcome.py
python3 scripts/foundations/test-security-outcome.py
python3 scripts/foundations/check-security-event.py
python3 scripts/foundations/test-security-event.py
python3 scripts/cpu/check-backend-contract.py
python3 scripts/cpu/test-backend-contract.py
python3 scripts/cpu/check-cpu-evidence.py
python3 scripts/cpu/test-cpu-evidence.py
scripts/cpu/check-cpu-admission-fixture.sh
python3 scripts/zeroization/check-zeroization-evidence.py
scripts/zeroization/check-zeroization-codegen.sh 1.98.1 x86_64-unknown-linux-gnu
scripts/sanitization/check-sanitization-adapter-codegen.sh 1.98.1 x86_64-unknown-linux-gnu
scripts/zeroization/check-zeroization-miri.sh
scripts/zeroization/check-zeroization-sanitizer.sh
scripts/release/check-github-release-controls.py
python3 scripts/standards/check-standards-ledger.py
python3 scripts/standards/check-authority-lifecycle.py
python3 scripts/standards/test-authority-lifecycle.py
python3 scripts/standards/check-protocol-surfaces.py
python3 scripts/standards/check-requirements.py
python3 scripts/pki/check-asn1-values.py
python3 scripts/pki/test-asn1-values.py
python3 scripts/sha2/check-sha256.py
python3 scripts/sha2/test-sha256.py
scripts/sha2/check-sha256-cpu-codegen.sh
cargo deny check
cargo audit
scripts/tag_gate.sh v0.24.0
```

The networked `scripts/ci/check_latest_tools.sh` check is mandatory before a
signed tag. `scripts/tag_gate.sh vX.Y.Z` runs the complete automated tag gate
and applies the stage-specific final check: ordinary development milestones
require no scheduled pentest, exceptional development milestones require their
PASS report without publication, and public checkpoints require their
cumulative PASS report. Every tag runs local Miri smoke coverage for all
registered groups plus complete coverage for changed groups and their
downstream closure; public crates.io checkpoints and shared assurance changes
force every group. Full AddressSanitizer and Kani also execute locally in that
pre-tag gate. Ordinary GitHub CI checks their pinned scripts, declared coverage,
scope selection, mutation resistance, and emitted-code evidence but does not
rerun the long dynamic suites, whose runtime exceeds the bounded hosted-CI
window. GitHub CodeQL uses Default setup; this repository intentionally does
not add an advanced CodeQL workflow.

After an exact green public-checkpoint candidate is pentested and tagged, the
interactive crates.io publisher is, for example:

```bash
scripts/release/release_crates.py --version 0.20.0
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
