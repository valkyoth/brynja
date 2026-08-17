# Current Status

Status: v0.20.0 signed and published; v0.21.0 through v0.24.0 signed; v0.24.1 pentest passed and awaiting green CI

Brynja has implemented only shared alert/failure and bounded numeric/resource
value domains plus protocol-neutral borrowed read and transactional
caller-buffer write cursors, an exact caller-owned workspace partition, an
abstract secret-lifetime contract, and a byte-backed exclusive borrowed secret
region with complete-region volatile clearing, plus fixed-width constant-time
choice, mask, equality, selection, swap, and compiler-barrier operations, and
provider capability, installation, opaque-handle, authorization, and bounded
request-metadata contracts, plus inert CPU-backend profiles, exact feature and
operation bundles, explicit selection policy, caller-owned KAT/health state,
permanent quarantine, thread-bound dispatch authority, a fail-closed
native CPU evidence and performance-admission harness, isolated x86_64 SHA,
AArch64 SHA2, and RV64 Zknh compression candidates, a direct startup KAT, caller-owned health
and quarantine, static `no_std` selection, and separate opt-in `std` runtime
detection with explicit scalar fallback or fail-closed required mode, and affine raw-entropy
plus initialized secure-random contracts, canonical checked durations, signed
Unix wall time, inclusive validity ranges, opaque generation-bound monotonic
instants, purpose-bound deadlines, explicit unavailability, and permanent
rollback failure, plus affine bounded pending certificate, external-signature,
and accelerator request state whose completion and cancellation require an
authoritative single-consumption destruction transition, plus fail-closed
FIPS-aware non-approved operation classification, module-owned
environment/build assumptions, provider-derived SSP destruction duties,
trusted self-test entry, permanent-failure state, and generation-bound service
indicators, plus sealed mandatory security-decision domains, exhaustive typed
outcomes, one caller-owned authority state machine, and token-gated external-key
destruction completion, plus opaque bounded observational security events,
explicit caller timestamp enrichment, a caller-owned fixed FIFO, and visible
saturating event-loss accounting. It currently admits zero backends and implements no FIPS module.
It now has all six complete portable FIPS 180-4 SHA-2 algorithms, complete
portable FIPS 202 SHA3-224, SHA3-256, SHA3-384, and SHA3-512, plus bounded DER tag-length-value framing
and admitted canonical ASN.1 primitive/container foundations, but still has no
schema-driven ASN.1 decoder, TLS handshake parser, TLS state machine, other
cryptographic algorithm beyond those ten named hash identities, X.509, QUIC-TLS, DTLS
engine, platform provider, or legacy protocol implementation and must not be
used to secure network traffic. Brynja is not FIPS 140-3 validated, and no
package, feature, build, profile, or configuration may imply otherwise.

The v0.22.1 candidate also provides a persistent detached native-run manager.
It can launch the exact clean candidate locally or over SSH, records the source
commit and tree before execution, continues after the operator disconnects,
polls without relabeling results, downloads completed bundles, and validates
their exact lane, accelerated execution transcript, generated instruction,
file inventory, and checksums. Apple M2 bundles can be produced locally and
imported through the same validator without granting remote access. These are
non-authorizing candidate observations only; the trusted-runner signature,
performance, statistical side-channel, and final backend-admission contracts
remain deliberately unsatisfied.

The repository owner collected and locally validated exact-commit candidate
observations on local AMD x86_64, observed-feature AWS Intel x86_64, Apple M2
macOS AArch64, and AWS AArch64. The exceptional assessment and retest of exact
signed commit `7d6dc573d8aaf049085d4bc4007642ee3b9ed82f` passed with zero
open findings. The final Apple-only tooling correction recognizes Mach-O
`sha256h.4s` without accepting `sha256h2` as a false match and changes no Rust
kernel, public API, dependency, or admission state. Both kernels remain
unadmitted because candidate observations are not authenticated performance,
side-channel, CPU-migration, independent-review, or FIPS evidence.

Signed v0.22.2 added a third isolated candidate using
the exact ratified RV64 `Zknh` scalar-cryptography bundle through four
source-hash-bound first-party Rust inline-assembly statements. Rust 1.90.0 and
1.97.1 emit `sha256sig0`, `sha256sig1`, `sha256sum0`, and `sha256sum1`; the
complete accelerated differential corpus passes under explicit QEMU RISC-V
execution. Generic RV64 and base-vector support do not qualify, the reserved
`Zvknha`/`Zvknhb` route remains absent, and the std adapter does not detect or
activate RISC-V. A sanitized preflight found that the registered native lane
has Rust 1.97.1 and generic vector/bit-manipulation support but lacks `Zknh`,
`Zvknha`, and `Zvknhb` on every hart, so it cannot execute this candidate. No
qualifying native RISC-V correctness, performance, side-channel, or migration
evidence exists, so the candidate is unadmitted and ordinary execution remains
scalar. The new inline-assembly boundary triggered
an exceptional v0.22.2 pentest; it reported zero Critical, High, or Medium
findings, required no source remediation, and records `PASS`/`PASS` with zero
open findings. No crate was selected for publication, and signed tag v0.22.2
contains the green committed report candidate.

Signed v0.22.3 added a standalone downstream
`no_std` consumer exercises only the documented public `brynja-hash-sha2` and
`brynja-crypto` APIs against empty, text, binary, file-like, multi-block, and
million-byte authoritative inputs through one-shot and irregular streaming
paths. It validates the scalar path, explicitly skips all three unadmitted CPU
backends, checks deterministic public message-length exhaustion, and repeats
the same run against safely extracted packaged crate contents with version-only
dependencies. The exact four-crate packaging workspace uses an empty Cargo home
and offline mode, excluding unrelated packages and cached registry state.
Executable negative fixtures reject digest corruption, missing
exports, backend misreporting, exhaustion bypass, an unadmitted feature, and
altered package contents. This acceptance makes portable SHA-256 publicly
usable; it does not admit an accelerated backend, add an algorithm, establish
independent verification or FIPS validation, or select a crate for publication.
The voluntary repository-owner assessment and retest through exact signed
candidate `399c9e7c5092d755dfbc22a3adf5500f85a8877e` passed with zero open
findings and required no cryptographic source remediation. The permanent report
is committed with the signed tag, and the complete delta remains in the
scheduled v0.25.0 assessment.

Signed v0.23.0 added complete
portable SHA-224 with its distinct FIPS 180-4 initial value, exact 28-byte
output, allocation-free `no_std` one-shot and streaming APIs, checked
message-length domain, transactional updates, and consuming finalization. NIST
CAVP short and Monte Carlo cases, FIPS long and million-byte examples, every
critical padding boundary, exhaustive two-part splits, fixed chunk widths,
four shared SHA-224/SHA-256 Kani bounds, Miri, and AddressSanitizer cover the
implementation. Its exceptional repository-owner assessment and retest of
exact signed candidate `8877bda1e697db98e77637d82bdc0d0d6ecad237` passed
with `PASS`/`PASS`, zero open findings, and no remediation. Ordinary SHA-224
state makes no secret-remanence cleanup claim; SHA-224 acceleration,
independent cryptographic review, and FIPS 140-3 validation remain absent. The
milestone selected zero crates.io packages, passed GitHub and CodeQL, and is
signed. It remains in the scheduled v0.20.0-to-v0.25.0 cumulative assessment.

Signed internal v0.23.1 added one private allocation-free
`no_std` 80-round `u64` compression owner and one private 128-byte buffered
state implement complete portable SHA-384 and SHA-512 through separately typed
one-shot, streaming, error, and 48-byte/64-byte digest APIs. Distinct exact
FIPS 180-4 IVs, the 111/112-byte padding boundary, a checked 128-bit bit-length
field, transactional exhaustion, NIST CAVP short and Monte Carlo vectors, FIPS
long and million-byte cases, independent padding oracles, every two-part split,
fixed chunk widths, six cumulative Kani bounds, Miri, and AddressSanitizer are
covered. SHA-384 is explicitly distinguished from truncated SHA-512. Ordinary
unkeyed state makes no secret-remanence cleanup claim. Acceleration,
independent review, and FIPS 140-3 validation remain absent. The repository-owner
assessment of exact candidate
`22c1dcdc7594a34bc14b53b42d1d56f7aa66047b` found no vulnerability, required
no remediation, and records `PASS`/`PASS` with zero open findings. Hosted
GitHub and CodeQL passed, and the signed tag selects zero crates.io packages.

Signed internal v0.23.2 added distinct `Sha512_224` and
`Sha512_256` types complete the portable FIPS 180-4 SHA-2 family with exact
28-byte and 32-byte outputs, checked 128-bit length domains, transactional
streaming, consuming finalization, one-shot functions, common traits, and
facade reexports. A private exact SHA-512/t derivation implements the mandated
XOR mask and ASCII identities and proves that both outputs equal the normative
IV constants used by public constructors. NIST CAVP short, 1,816-bit long, and
Monte Carlo vectors, million-byte cases, every critical padding boundary,
every two-part split and fixed chunk width, exhaustion checks, and negative
ordinary-SHA-512 truncation tests pass. The new algorithm identities select
zero crates.io packages. The repository-owner assessment of exact candidate
`0129013eaae7ee3f1cd2ca5cf9671b8ea5834165` found no vulnerability, required
no remediation, and records `PASS`/`PASS` with zero open findings. The
hosted GitHub and CodeQL passed, and the signed tag selected zero crates.io
packages. Ordinary-state erasure, independent review, and FIPS 140-3
validation remain absent.

Signed internal `0.23.3` extends the optional CPU boundary. SHA-224 reuses all three exact
SHA-256-family candidate kernels through its separate IV, output, and public
state identity. New static, caller-owned, KAT-gated AArch64 SHA-512 and RV64
Zknh SHA-512 sessions serve SHA-384, SHA-512, SHA-512/224, and SHA-512/256.
Forced scalar equivalence passes across all six identities, padding boundaries
and irregular chunking under AArch64 and RISC-V QEMU, and compiler-endpoint
assembly contains the required SHA-512 instructions. The std adapter reports
unadmitted AArch64 capability and retains scalar fallback. x86_64 SHA-512 is
an explicit scalar-only decision; AVX2 and AVX-512 do not imply admission.
All five candidates remain unadmitted. Exact-commit native correctness and
emitted-code observations pass on local AMD, observed-feature AWS Intel,
Apple M2, and AWS Arm; the registered RISC-V host remains non-qualifying and
QEMU-only. Authenticated provenance, performance, migration and side-channel
evidence remains pending. The exceptional assessment records `PASS`/`PASS`
with zero open findings. The milestone selects zero crates.io packages and
makes no independent-review, register-erasure, or FIPS-validation claim.

Signed internal `0.23.4` added a standalone downstream
`no_std` consumer uses only public leaf and facade APIs to exercise all six
SHA-2 identities. Thirty one-shot and thirty-six irregular-streaming results
cover empty, text, binary, multi-block, million-byte, and file-like inputs
against independent expected digests. The same consumer runs from a safely
extracted exact 15-package offline archive closure with version-only
dependencies and an empty Cargo home. Negative fixtures reject per-algorithm
digest corruption, missing APIs or documentation, wrong identity or output
width, incomplete candidate accounting, forbidden evidence features, and
missing package source. This closes public usability without changing
cryptographic code, admitting a CPU backend, or adding independent-review,
FIPS-validation, or secret-remanence claims.

The repository-owner voluntary assessment of exact signed v0.23.4
implementation candidate `7864a8f3a8766d16fc9bb2ea89893351f29aa842`
reported no finding and required no remediation. The permanent report records
`PASS`/`PASS` with zero open findings. This does not admit an accelerated
backend, establish independent cryptographic review or FIPS validation, or
replace the scheduled cumulative v0.20.0-to-v0.25.0 assessment. The complete
local release check and hosted GitHub/CodeQL passed before the signed tag.

The facade now advances to internal `0.24.0`. New unpublished
`brynja-hash-sha3 0.1.0` owns one private safe-Rust Keccak-f[1600]
permutation and fixed-output sponge. Distinct `Sha3_224` and `Sha3_256`
states expose allocation-free `no_std` one-shot and streaming APIs with exact
144-byte and 136-byte rates, the FIPS 202 SHA-3 suffix and padding, checked
`u128` message lengths, transactional updates, and consuming finalization.
Official zero-bit and 1,600-bit examples, standard text and million-byte
values, exact padding boundaries, every bounded two-part partition, and raw-
Keccak domain-separation negatives pass. An isolated repository-only adapter
matches Python `hashlib` over 328 deterministic messages, 17 mutation fixtures
bind the source and package boundary, and two Kani harnesses cover length
admission and every byte-to-lane mapping. SHA3-384, SHA3-512, SHAKE, complete-
family public acceptance, acceleration, secret-state erasure, independent
review, and FIPS validation remain absent. The family is therefore **In
progress**, v0.24.0 selects zero crates.io packages, and the new primitive
requires an exceptional pentest before the signed tag.

The facade now advances to internal `0.24.1`. Complete portable `Sha3_384` and
`Sha3_512` states reuse the same private safe-Rust Keccak-f[1600] sponge owner
with exact 104-byte and 72-byte rates and 48-byte and 64-byte outputs. Their
official zero-bit and 1,600-bit examples, text and million-byte cases, exact
padding boundaries, irregular streaming partitions, raw-Keccak negatives, and
typed public APIs pass. The isolated 328-message differential corpus now checks
all four fixed-output algorithms, and 25 mutation fixtures bind the expanded
source, output-width, rate, vector and package boundary. SHAKE, complete-family
package acceptance, acceleration, secret-state erasure, independent review and
FIPS validation remain absent, so the family stays **In progress** and v0.24.1
selects zero crates.io packages.

Signed releases v0.1.0 through v0.15.0 established the workspace, hardened
release and isolation controls, made standards authority executable, and
classified protocol surfaces and the normative matrix foundation, and added
the assurance harness and first value, cursor, workspace, and abstract secret
lifetime domains. The v0.10.0 checkpoint published `brynja-core 0.7.0`, eight
dependency-only modern support patches at `0.1.6`, and `brynja 0.10.0`.
Signed v0.11.0 introduced the first isolated unsafe secret-destruction
boundary and completed its exceptional pentest with zero open findings.
v0.11.1 admitted the optional sanitization adapter and v0.11.2 implemented it;
both exceptional assessments are permanently recorded with zero open findings.
The v0.12.0 exceptional assessment and retest passed after closing one High
RV32 branch-timing flaw and two Medium assurance-scanner gaps; signed v0.12.0
published no crate. The facade then advanced to `0.13.0` for upstream provider
capability and opaque-handle contracts while all crates.io publication
selections remained empty. Its voluntary assessment found three High
authorization/provider-binding flaws and one Medium work-accounting flaw. The
four source remediations are complete, and the repository-owner retest of exact
signed candidate `b45185e5aefdd48b9dc1859fee7a9000be9b6168` passed with zero
open findings. Signed tag v0.13.0 contains the remediated contract and selected
no crates.io publication. Signed v0.13.1 contains the remediated CPU-backend
capability and dispatch contract and also selected no crates.io publication.
Signed v0.13.2 reserves two inert future CPU-kernel and host-detection package
boundaries. Signed v0.13.3 provides machine-readable evidence, lane,
raw-artifact, benchmark, and admission contracts while admitting no backend.
Signed v0.14.0 contains exact-purpose raw entropy and initialized secure-random
state, while its deterministic fault provider remains unpublished test support.
The `0.15.0` checkpoint published `brynja-core 0.8.0`, the modern dependency
patches, the initial CPU-boundary and sanitization packages, and the facade
after the scheduled v0.10.0-through-v0.15.0 pentest of
exact signed candidate `1aa4ad938438f0f2dc996b74b6364f1026c05e0f` passed
with zero findings and hosted checks became green. Signed v0.16.0 contains the
remediated pending-operation lifecycle and selects no crates.io publication.
Signed v0.17.0 contains the remediated FIPS-aware architecture and selects no
publication. The v0.18.0 exceptional assessment found four High and one Medium
issue across its initial review and first retest. The clean second retest of
exact signed remediation commit
`635b229296be45b195d37d8111fd8ad8f8b1e571` records `PASS`/`PASS` with
zero open findings. Signed tag v0.18.0 contains that remediation. The facade now
advanced to `0.18.1`; supporting versions remained unchanged and no crate was
selected for publication. The repository-owner assessment of exact signed
v0.18.1 implementation commit
`9ff9a459d8caae7e7f5c18b6576647487ba5b251` passed with zero findings and
required no remediation; its permanent report is
`security/pentest/v0.18.1.md`. Signed tag v0.18.1 contains that candidate.

The facade now advances to `0.19.0`. New unpublished
`brynja-protocol 0.1.0` implements shared allocation-free TLS 1.2, TLS 1.3,
DTLS 1.2, and DTLS 1.3 record-envelope parsing and transactional encoding
behind externally selected typed policies. It rejects RFC 6520 Heartbeat in
all modern profiles and cannot negotiate versions, decrypt, authenticate,
reconstruct DTLS sequence numbers, process replay, perform I/O, or transition
a handshake. The TLS and DTLS engine packages consume the shared boundary but
remain unimplemented. No package is selected for publication. As the first
hostile protocol parser, v0.19.0 requires an exceptional pentest before tag and
also remains in the scheduled v0.15.0-to-v0.20.0 cumulative assessment.
The initial assessment found one High TLS 1.3 cleartext-exposure flaw: the
plaintext admission path inherited TLS 1.2 application-data allowance. TLS
1.3 application data is now categorically rejected during both parsing and
construction with a dedicated closed error, while TLS 1.2 retains its required
plaintext behavior. Focused regression and policy fixtures pass; the exact
signed remediation candidate
`238d4bac75eecce9dde63700c53f13e6f7a9aaed` passed repository-owner retest
with zero open findings. The permanent `security/pentest/v0.19.0.md` report
records `PASS`/`PASS`; signed tag v0.19.0 contains that remediation.

Signed v0.20.0 and published `brynja-pki 0.2.0` implement a borrowed,
allocation-free, non-recursive DER reader with immutable input, depth, node,
child, identifier, length, value, and work ceilings plus a caller-selected
fixed stack. Canonical identifier and definite minimal length checks,
parent-boundary enforcement, failure-atomic reader position, and exact borrowed
slices are implemented. ASN.1 primitive semantics, SET ordering, X.509,
cryptography, signature verification, and FIPS validation remain absent.

The scheduled cumulative assessment found no Critical, High, or Medium issue
and one Low DER semantic-boundary oracle: an incomplete nested identifier or
length could inspect one adjacent byte beyond its parent before later
rejection. Every header-byte access is now parent-boundary-aware, declared
content uses the same boundary decision, and focused tag/length regressions and
source policy pass. Repository-owner retest of exact signed remediation
candidate `7fd31b4cc536cb2dce1a565fa3551365b086000f` passed with zero
open findings, and the permanent report records `PASS`/`PASS`.

The scheduled public checkpoint passed hosted checks and published all 15
selected packages, including initial `brynja-protocol 0.1.0`, changed
`brynja-pki 0.2.0`, and the `brynja 0.20.0` facade.

The facade now advances to internal `0.21.0` while every support package keeps
its published version. `brynja-pki` adds borrowed canonical BOOLEAN, INTEGER,
BIT STRING, OCTET STRING, OBJECT IDENTIFIER, admitted character strings,
UTCTime, GeneralizedTime, SEQUENCE, SET, and SET OF foundations. Exact DER
value canonicality, checked integer/OID bounds, real calendar rules, direct SET
tag order, and padded-octet SET OF order are enforced without allocation,
unsafe code, recursion, or copying. Schema-driven decoding, DEFAULT omission,
escape-bearing ISO 2022 strings, AlgorithmIdentifier, X.509, signatures,
cryptography, independent verification, and FIPS validation remain absent.

Nine behavior groups include exhaustive Boolean, bit-padding, and two-octet OID
corpora; six compile-fail examples, ten locked source hashes, and forty broken
fixtures protect the boundary. `BRY-REQ-ENC-0002` is implemented at revision 3
and binds the new `format.asn1.values` surface. The exceptional assessment of
exact signed implementation candidate
`6e3ca63305fd3923ca723c9d7f559a9b12843002` reported no findings and required
no source remediation. Its permanent report records `PASS`/`PASS`, zero open
findings, and the warning that canonical sequence framing is not
schema-specific validation. The tag awaits green GitHub and CodeQL. It selects
zero crates.io publication and remains inside the future
v0.20.0-to-v0.25.0 cumulative assessment.

Every roadmap version now completes the full automated tag gate and waits for
green GitHub and CodeQL before its signed tag. Scheduled pentests and crates.io
publication occur at each fifth-minor public checkpoint. The v0.15.0 pentest
reviewed all changes after v0.10.0 through v0.15.0; the v0.20.0 pentest
reviewed all changes after v0.15.0 through v0.20.0. Intermediate patch and minor
tags remain inside that cumulative change range.

Version 0.3.0 provides the exact source foundation:

- 104 locked RFCs and eighteen local NIST/ITU/RISC-V authorities map to lifecycle, domain,
  and roadmap ownership;
- RFC status and update/obsolescence relationships are closed or explicitly
  excluded;
- eight exact IANA XML snapshots preserve registry state;
- all 290 official errata have fail-closed reviewed dispositions; and
- ordinary checks reproduce the ledger offline while the release gate rejects
  live official-source drift.

Version 0.3.1 adds explicit protocol-surface decisions:

- 129 semantic decisions cover current and compatibility TLS, DTLS, QUIC-TLS,
  PKIX, OCSP, CT, HPKE, ECH, cryptographic algorithms, certificate and key
  formats, legacy protocols, and operational facilities;
- all 192 nested registries and all 4,106 individual records across the eight
  pinned IANA collections receive a deterministic disposition;
- every one of the 4,450 current generated surfaces records normative sources, owning
  milestone, planned code target, planned test target, and rationale;
- required exclusions explicitly cover Heartbeat, status_request_v2,
  production SSLKEYLOGFILE, TLS 1.3 post-handshake authentication,
  certificate-with-external-PSK, legacy PKCS1 client signatures, ML-KEM PKIX
  credentials and unsigned X.509 certificates; the original HPKE non-base-mode
  exclusion is now superseded by separately planned v0.139.2-v0.139.5
  PSK/Auth/AuthPSK implementation and acceptance milestones;
- QUIC version-specific cryptography and certificate compression remain
  explicit bounded future work, while unknown extensions are safely ignored
  only where protocol rules permit; and
- 25 positive and broken-fixture tests reject source-ledger drift, registry
  omissions, duplicate or unknown decisions, invalid owners or targets,
  overlapping rules, unmatched overrides, stale output, and premature
  implementation claims.

Version 0.3.2 added the normative-requirement foundation:

- 12 stable pilot requirements bind exact source-ledger and surface-register
  hashes, source sections and anchors, status, errata, strength, applicability,
  decisions, owners, residual risk, targets, tests, and evidence;
- all eight lifecycle states are represented: planned, implemented, tested,
  evidenced, rejected, caller-owned, legacy, and blocked;
- deterministic schema, matrix, coverage, and bidirectional source, decision,
  owner, target, test, and evidence indexes are reproduced byte for byte;
- implementation, test, and evidence claims require existing file anchors,
  while protocol requirements are forbidden from making premature
  implementation claims; and
- 51 positive and broken-fixture tests reject source or registry drift,
  malformed or duplicate identifiers, invalid sections, obsolete-as-current
  authority, illegal transitions, missing ownership and targets, premature
  evidence, weakened SHOULD decisions, symlink target escapes, released-ID
  removal, stale revisions, unrelated decision links, protocol use of global
  mappings, released-scope changes, lifecycle/disposition conflict, and stale
  generated output.

Version 0.3.3 completes the cryptography, encoding, and PKIX population pass:

- 35 new domain requirements bring the matrix to 47 stable records;
- all 56 exact authorities in the symmetric, SHA-3-derived, RISC-V acceleration, public-key, key-container, PKIX,
  OCSP, and CT domains are cited with current, compatibility, evidence, or
  exclusion roles;
- all 3,325 current cryptography, PKIX, PKI, OCSP, and CT surfaces map to a requirement
  or one of two explicit v0.3.5 ML-KEM deferrals;
- every uppercase normative RFC section is hash-bound with occurrence counts,
  and every domain rule records assurance invariants, a work bound, positive
  and negative target tests, an evidence gap, and residual risk;
- FIPS 202 and the in-force ITU-T X.690 (2021) plus Erratum 1 are pinned as
  local-only authorities, while SHA-3/SHAKE, GHASH, and ChaCha20 receive
  explicit semantic decisions; and
- fifteen domain fixtures fail on authority, binding, coverage, lifecycle,
  ownership, test-polarity, invariant, work-bound, or reproducibility defects.

Version 0.3.4 completes the TLS, DTLS, and QUIC-TLS population pass:

- 64 semantic surfaces give every planned transport implementation milestone
  one stable owner, code target, test target, source set, and rationale;
- 71 new requirements bring the matrix to 117 stable records and cover all 40
  admitted transport authorities, 550 normative RFC sections, and 485
  selected transport surfaces;
- all 914 domain and transport normative RFC sections carry reviewed
  decisions: 909 exact mappings and five explicit dispositions with unique
  extraction anchors and section hashes;
- source roles distinguish current, compatibility, evidence, exclusion, and
  caller-owned authority, including explicit Heartbeat, legacy signature,
  post-handshake-authentication, certificate-with-external-PSK, and QUIC
  transport boundaries;
- TLS, TLS 1.2, TLS 1.3, QUIC, and DTLS state and ownership mappings are
  version-separated and include work bounds, positive and negative tests,
  unresolved evidence, and residual risk;
- RFC 9850 key logging and four optional TLS facility groups remain explicit
  v0.3.5 deferrals, while status_request_v2 remains bound to the completed
  v0.3.3 OCSP review; and
- eight transport and nine section-binding fixtures reject missing owners,
  binding drift, role swaps, duplicate identities, omitted authorities,
  unmapped or non-normative sections, source/requirement mismatch, incomplete
  semantic revisions, unreviewed exclusions, and nondeterministic output.

Version 0.3.5 completes the optional, legacy, operational, and residual pass:

- 51 residual requirements bring the matrix to 169 stable records;
- final FIPS 203, SP 800-227, SP 800-90B, and SP 800-90C are added as
  local-only checksum-pinned authorities;
- 33 residual authorities and 182 normative RFC sections are reviewed through
  165 exact mappings and 17 explicit dispositions;
- all 787 surfaces left by the foundation, domain, and transport bundles are
  assigned, producing complete coverage of all 4,450 surfaces;
- the generated closure maps all 130 locked sources, all 510 ordered pre-1.0
  roadmap rows, all 4,450 surfaces, and all 169 requirements in both directions;
- local redistribution boundaries, all eight mutable registries, five mutable
  NIST publication pages, source-free plan rows, and dependent refresh owners
  are explicit; and
- twenty-two residual fixtures reject draft claims, missing or duplicate
  groups, unlinked or boundary-mixed surfaces, non-representative source,
  target, owner or disposition drift, blanket section coverage, orphaned
  sources or plans, stale mutable guidance, source-rights gaps, missing
  exclusions, actionable source-blocked legacy requirements, and weakened
  hybrid-resolution, legacy-blocker, or FIPS-blocker records;
- domain, transport, and residual section decisions are globally reconciled,
  with delegated sections accepted only when another bundle records an exact
  owner;
- the DTLS RRC state, extension, ContentType 27, and message registry are fixed
  at v0.111.1, while stream TLS must reject RRC admission;
- RFC 6066 is split among exact TLS 1.2, TLS 1.3, SNI, status, alert,
  terminology, bounded peer ClientHello ignore, and configuration-rejection
  decisions instead of being mapped wholesale to OCSP; and
- RFC 7568 section 3 is authority only for the SSLv3 prohibition boundary.

Version 0.4.0 establishes assurance infrastructure without protocol code:

- bounded first-party mutation covers empty, original, truncation, deletion,
  bit-flip, and zero/`0xff` insertion cases in deterministic replay order;
- differential adapters consume bounded public test bytes over raw standard
  input and return canonical JSON, with fail-closed crash, timeout, output,
  class, encoding, and mismatch handling;
- seed and corpus files use descriptor-bound, no-follow, limit-plus-one reads,
  corpus enumeration is case-bounded, and differential and generated mutation
  execution hold only one case at a time;
- process execution never invokes a shell; Windows uses suspended-start
  kill-on-close Job Objects, while POSIX process-group cleanup is explicitly
  cooperative and hostile execution fails closed without a declared external
  cgroup, PID-namespace, container/VM, or fork-and-setsid-denial boundary;
  campaign launchers retain an explicit duty to supply and evidence OS network,
  filesystem, process, and device isolation;
- CI and the local release gate compile the complete all-feature workspace for
  `thumbv7em-none-eabi`, `riscv32imac-unknown-none-elf`, and
  `x86_64-unknown-none`;
- exact source pins cover Kani 0.67.0, AFL++ 5.02c, honggfuzz 2.6, and the
  separately pinned Miri/sanitizer nightly without adding a Cargo dependency;
- stable Rust 1.97.1 remains the release compiler while Kani 0.67.0 uses the
  documented compatible Rust 1.90.0 verifier pairing; no Kani proof harness is
  admitted or claimed at this milestone; and
- deterministic assurance evidence binds policy, runners, CI, and every Cargo
  manifest, with 43 positive and broken fixtures, including detached-descendant
  limitation, native-host CI, Windows startup constant, bounded input,
  streaming corpus, and exact local/remote probe timeout checks.

Version 0.5.0 implements the first shared protocol value domains:

- all 256 TLS AlertDescription bytes classify as assigned, reserved, or
  unassigned without lossy coercion;
- assigned alerts carry a concrete TLS 1.2, TLS 1.3, DTLS 1.2, or DTLS 1.3
  identity and fail closed on version-specific misuse;
- orderly close and explicit cancellation are distinct from alert failures;
- local, provider, and resource-exhaustion failures carry only closed enums,
  with no strings, byte payloads, provider-native codes, or numeric limits;
- failure envelopes implement neither `Debug` nor `Display`, and compile-fail
  tests prevent accidental formatting or secret-payload constructors; and
- `BRY-REQ-TLS-0005` and the alert registry surface now point to actual code
  and tests through immutable `implemented` and `tested` revisions.

Version 0.6.0 adds bounded numeric and resource foundations:

- `BoundedU64<MAX>` and `BoundedUsize<MAX>` use private fields, fallible
  construction, and checked addition, subtraction, and multiplication;
- `Count<MAX>` and `Length<MAX>` remain different Rust types, while `u64` to
  `usize` conversion fails closed when the target pointer width is too small;
- protocol-neutral `SequenceNumber<MAX>` and `Epoch<MAX>` advance without
  wraparound and return typed exhaustion at their inclusive maxima;
- `ResourceBudget` names seven resource dimensions through a fail-closed
  builder that requires exactly one assignment per limit and returns typed
  duplicate or incomplete-domain errors, while `WorkBudget` carries an
  explicit `u64` work-unit limit;
- budget checks do not mutate either operand and return the existing typed
  `ResourceExhaustion` without embedding numeric limits;
- small-domain arithmetic and advance matrices are exhaustively checked, with
  additional boundary, representation, zero-budget, and compile-fail tests;
- the reviewed 2026-07-31 IANA DNS snapshot adds three registries and
  seventeen entries, all explicitly caller-owned by v0.140.0, bringing the
  then-current register to 4,444 surfaces without admitting provisional draft
  text or advancing a protocol implementation claim;
- the reviewed 2026-08-09 refresh adds only one caller-owned provisional
  `snifq/1` ALPN record and three DNS reference updates, bringing the current
  register to 4,445 surfaces without admitting draft or RFC implementation
  authority;
- the reviewed 2026-08-11 DNS refresh adds only the caller-owned `_x402` TXT
  underscored service name referencing provisional
  `draft-hawkins-x402-dns-discovery-01`, bringing the current register to 4,446
  surfaces without admitting draft authority or runtime code;
- the later reviewed 2026-08-11 TLS ExtensionType refresh adds C509 Certificate
  type value 4 and moves the unassigned range start to 5, bringing the current
  register to 4,450 surfaces while retaining the provisional C509 draft as
  non-authoritative future work and admitting no runtime code; and
- no protocol surface or normative protocol requirement advances because
  these types are source-free shared foundations; later wire widths,
  direction-specific state, parsers, and engines remain future work.

Version 0.7.0 adds borrowed input consumption:

- `ReadCursor<'input>` stores only a caller-owned immutable byte-slice borrow
  and a private position, performs no allocation, and exposes no mutable input;
- dynamic, typed `Length<MAX>`, and fixed-array reads compute their end offset
  with checked arithmetic and use bounds-checked slice access without indexing;
- success advances by exactly the requested length, while overflow,
  truncation, and fixed-array conversion failure leave position and remaining
  input unchanged;
- explicit consuming `finish()` rejects every trailing suffix, while an
  exhaustive composite fixture rejects truncation at every byte boundary;
- the cursor is non-`Clone`, non-`Copy`, non-formattable, and `must_use`, and
  compile-fail tests bind those API constraints and the caller-input lifetime;
- `ReadError` carries only `Truncated`, `LengthOverflow`, or `TrailingData`,
  with no bytes, offsets, requested/available lengths, strings, or allocation;
  and
- no protocol surface or normative protocol requirement advances because this
  is a source-free cursor foundation; integer decoding, framing, parsers,
  writes, arenas, secret ownership, and state machines remain future work.

Version 0.8.0 adds transactional caller-buffer output construction:

- `WriteCursor<'output>` exclusively borrows caller-owned mutable bytes and
  stores only that slice plus a private position without allocation;
- every single-slice, multi-part, and repeated-byte operation preflights its
  complete destination before changing the first byte;
- multi-part writes check aggregate-length arithmetic and capacity first, then
  preserve source order as one mutation transaction;
- capacity and end-offset failures preserve every output byte and the cursor
  position, while success changes only the exact destination and advances
  exactly once;
- immutable prefix inspection and consuming exact-capacity completion expose
  no mutable alias while the cursor remains active;
- the cursor is non-`Clone`, non-`Copy`, non-formattable, and `must_use`, and
  compile-fail tests enforce its exclusive output lifetime;
- `WriteError` contains only `InsufficientCapacity`, `LengthOverflow`, or
  `TrailingCapacity`, with no bytes, offsets, lengths, strings, or allocation;
  and
- no protocol surface or normative protocol requirement advances because this
  is a source-free buffer foundation; integer encoding, framing, patching,
  arenas, overlap policy, secrets, and protocol state remain future work.

Version 0.9.0 adds exact caller-owned workspace partitioning:

- `WorkspaceLayoutBuilder` requires explicit single assignments for secret,
  plaintext, transcript, certificate, and output capacities and rejects every
  duplicate, omission, and aggregate-length overflow;
- `Workspace` accepts exactly one caller-owned mutable slice whose length must
  equal the layout total, then safe-splits every byte once into five named
  domains without admitting independent potentially overlapping buffers;
- empty arenas may share boundary addresses but contain no bytes, while named
  simultaneous borrows permit the non-empty domains to be used together under
  Rust's exclusive-aliasing rules and sealed zero-sized domain markers prevent
  secret, plaintext, transcript, certificate, and output handles from being
  swapped;
- each private `Arena` admits only monotonic complete-range allocation and
  exposes capacity, used, remaining, high-water, and successful non-empty
  allocation-count telemetry;
- overflow and capacity failure preserve all storage and accounting, empty
  allocations do not change accounting, and successful allocations retain
  caller bytes for mandatory initialization by the caller;
- exhaustive small-layout and every-position/request tests cover domain
  identity, pointer identity, isolation, overflow, exhaustion, zero lengths,
  sentinel preservation, value-free errors, and compile-fail lifetime and
  formatting constraints; and
- no protocol surface or normative protocol requirement advances because this
  is a source-free storage foundation; release, reuse, zeroization, secret
  ownership and destruction, framing, and protocol state remain future work.

Version 0.10.0 adds the abstract secret-lifetime contract and isolated test
key logging:

- private affine initialization can transition to an abstract secret state
  only after exact complete write acknowledgments;
- cancellation, exhaustion, provider failure, initialization failure,
  replacement, obsolescence, and drop invoke configured local-memory,
  external-store, accelerator, cache, and DMA destruction duties;
- all configured duties are attempted, completion tokens are consumed once,
  and any failed duty produces a terminal failure without secret values;
- v0.10.0 supplied no secret bytes, reads, backing storage, or production
  local-memory destructor, making the v0.11.0 zeroization primitive its
  mandatory next step;
- RFC 9850 key-log lines are encoded transactionally only in the permanently
  unpublished `brynja-test-support` crate; production dependency and feature
  graphs are mechanically prohibited from reaching it;
- exact initialization boundaries, every early exit, replacement/drop,
  every destruction target, line labels/endings, short buffers, isolation, and
  compile-fail clone/format constraints are tested; and
- the post-v0.10 five-minor public-checkpoint cadence and every intervening
  tagged development milestone are mechanically classified by the release-plan
  validator.

Version 0.11.0 adds the owned-memory zeroization primitive:

- `SecretRegionInitialization` exclusively borrows one non-empty caller region,
  clears every prior byte at admission, accepts only sequential failure-atomic
  writes, and cannot expose the region before exact complete initialization;
- `OwnedSecretRegion` is affine, non-clonable, non-formattable, read-only to its
  caller, and clears the complete allocation on explicit clear or `Drop`;
- incomplete finish, failed initialization, and initialization `Drop` clear the
  complete allocation before the caller can regain access;
- one private module contains the only approved unsafe block, derives each raw
  pointer from a live exclusive byte reference, performs one volatile zero
  store, retains no pointer, and ends with a compiler barrier;
- policy fixtures reject any second unsafe allowance, block, item, assembly, or
  FFI site, and source files remain below the review-size limit;
- MIR, LLVM IR, and assembly checks pass for Rust 1.90.0 through 1.97.1 on the
  host and Rust 1.97.1 across all nine promised OS and bare-metal targets;
- pinned Miri and AddressSanitizer pass all owned-memory tests; and
- the guarantee is explicitly limited to the exclusively borrowed Rust
  allocation, excluding registers, copies, caches, DMA-visible copies, dumps,
  suspend images, physical-memory remanence, concurrent access, forgotten
  owners, abort, and process or power termination.

Version 0.11.1 completes the sanitization adapter admission review:

- the latest stable first-party release is pinned as `sanitization 2.0.3`,
  source commit `ffcb211cd931c6966b2e767ce5edffa4b47c4f07`, package SHA-256
  `75e43f2762b31232062e8ba7bfbdfcbd33c80c43bf7a306a7e195c3c4f734e0f`,
  Rust 1.90, and MIT OR Apache-2.0;
- an isolated exact-pin candidate with default features disabled resolves only
  `sanitization`, with no `zeroize`, derive, serde, subtle, or other runtime
  dependency, and compiles across all ten supported Rust versions, nine
  promised targets, and the explicitly weaker WASM compatibility target;
- the selected-feature inherited unsafe inventory, upstream pentest, advisory
  result, emitted-code evidence, target tiers, and residual limits are recorded
  in both machine-readable and reviewer-facing evidence;
- one protocol-neutral future `brynja-sanitization` adapter is admitted for
  conditional v0.11.2 implementation; a legacy-specific split, facade or
  engine feature, default activation, implicit conversion, and ownership
  ambiguity are rejected; and
- `brynja-core` remains the mandatory authoritative protocol destruction path,
  while the optional adapter stays outside every FIPS validated-module closure
  and cannot satisfy or imply a validation claim.
- an exceptional repository-owner assessment found the initial review fixture
  could discard arbitrary secret-bearing source errors without clearing their
  payload; signed remediation `cd1c881d2eb6c9aa925f1527a326330c1cf3b80a`
  replaced that boundary with a zero-sized `SourceFailure`, and the retest
  passed with zero open findings; and
- the milestone remains an internal tag with zero crates selected for
  publication, while its permanent PASS report is committed under
  `security/pentest/v0.11.1.md`.

Version 0.11.2 implements the admitted optional adapter:

- `brynja-sanitization 0.1.0` is a separately publishable `no_std` package
  with exact `sanitization 2.0.3`, default features disabled, and no resolved
  transitive package;
- `SanitizedSecret<N>` owns upstream fixed storage behind a non-copyable,
  non-converting wrapper with redacted `Debug`, closure-scoped inspection,
  payload-free source failure, transactional replacement, explicit clear, and
  named exact-length copies to and from `brynja-core` regions;
- the same type serves modern and legacy downstream callers. No facade,
  protocol engine, legacy engine, platform crate, default feature, all-feature
  aggregate, or FIPS validated-module closure can activate the adapter;
- workspace, lockfile, release, package, and SBOM policy admit only the exact
  reviewed external package and reject pin, source, default-feature, feature,
  transitive-package, `zeroize`, owner, and reachability drift; and
- behavior, failure-position, replacement, capacity, cancellation/unwind,
  differential, compile-fail, Rust 1.90.0-1.97.1, promised-target, Miri, and
  MIR/LLVM/assembly evidence cover the adapter boundary.

Version 0.12.0 implements the constant-time foundation:

- private one-byte `Choice` and `CtMask` values normalize decisions and prevent
  callers from forging masks; ordinary equality and formatting are unavailable,
  while `Choice::expose_public` is the single named declassification boundary;
- `ConstantTimeEq`, `ConditionalSelect`, and `ConditionalSwap` cover all
  unsigned word widths and compile-time-sized byte arrays without allocation,
  operating-system services, third-party dependencies, or new unsafe code;
- exhaustive byte-pair, word-boundary, selection, swap, array-length and
  mismatch-position tests are joined by compile-fail API examples;
- hash-locked source policy rejects branch, dynamic-slice, fallible-surface,
  representation, inventory, barrier, and source-byte drift with fourteen broken
  fixtures; and
- optimized LLVM and assembly witnesses cover Rust 1.90.0 through 1.97.1 and
  nine promised targets through a machine-checked matrix and five broken
  evidence fixtures. These bounded witnesses are not formal proof, timing
  measurement, independent review, or a microarchitectural guarantee.

The initial assessment demonstrated that the source mask formula became LLVM
`select`, then secret-dependent RV32 branches, while the old assembly checker
validated symbols but not their bodies. Remediation barriers each expanded
mask before XOR/AND selection, always inlines word selection into the witness,
and inspects concrete function bodies with target-specific branch rules. The
follow-up remediation canonicalizes RISC-V register aliases, recognizes all
eighteen conditional forms, and retains ten focused negative fixtures. The
repository-owner retest of exact signed candidate
`7ce43fffdf81a349c7c44aae33b229d077d4512d` passed; the permanent report records
`PASS`/`PASS` with zero open findings.

Dynamic slices, secret-dependent lengths, signed values, arbitrary downstream
composition, and protocol-level timing remain outside v0.12.0. Signed tag
v0.12.0 selects no crates.io publication.

Version 0.13.0 implements provider capability and opaque-handle contracts:

- nineteen independent operations cover hash, separate MAC
  generation/verification, KDF, key agreement, signature, KEM, AEAD, entropy,
  wall/monotonic clocks, certificate chains, storage, and pending boundaries
  without implementing those effects;
- named transactional installation freezes a nonempty exact capability set,
  caller resource/work limits, and mandatory nonempty destruction duties;
- one non-cloneable and non-formattable opaque borrowed handle authorizes one
  exact operation on one explicitly chosen provider, without registry search,
  direction broadening, or fallback, and each prepared request retains that
  exact provider identity;
- immutable version-neutral request metadata checks aggregate input, output
  capacity, and provider-operation count before any effect; verification cannot
  request byte output, request holders cannot construct provider results, and a
  monotonic provider-owned meter replaces caller-declared work; and
- nine behavioral test groups, six compile-fail examples, a reviewed
  SHA-256-locked four-file policy, and thirteen broken fixtures enforce the
  claim.

The boundary has no algorithm or key identifiers, mutable output, provider
completion, entropy health, clock units, certificate-path semantics, storage
backend, pending lifecycle, platform effect, CPU dispatch, or FIPS approval.
The repository-owner remediation retest passed with zero open findings. Signed
v0.13.0 selects no crates.io publication.

Version 0.13.1 implements the CPU-backend capability and dispatch contract:

- sealed scalar, x86, AArch64, RISC-V, and validated-module identities bind
  exact feature and provider-operation profiles without authorizing execution;
- opaque backend-instance identity binds the measured artifact and operational
  environment, while KAT pass/failure evidence borrows the exact session and
  instance so equal profiles and generations cannot redirect it;
- caller-owned no-atomics health state, monotonic health/runtime generations,
  direct initialization, permanent quarantine, and thread-bound active
  authority separate observation from use;
- exact-operation dispatch revalidates identity, health, runtime, operation,
  and observational service approval, while accelerated entry also requires
  an opaque platform-issued CPU lease and a sealed context that acquires a
  migration-excluding guard while revalidating CPU or hart identity, migration
  generation, complete usable features, and required OS or architectural state;
  logical authority is checked again after every platform callback, then one
  sealed kernel executes directly while the guard remains live; and
- scalar-only, opportunistic, required-accelerated, and validated-module
  policies make fallback explicit and make required modes fail closed.

Thirteen behavior groups, eleven compile-fail examples, a SHA-256-locked
eight-file source policy, and twenty-three broken fixtures enforce the
boundary. It contains no CPU probe, public instance, lease, context, guard, or
kernel constructor, intrinsic, assembly, executable accelerated kernel
implementation, unsafe backend boundary, global cache, provider effect,
performance claim, or FIPS validation. Its exceptional assessment and first
retest found three High backend-authority flaws; all were remediated, and the
repository-owner retest of exact signed final candidate
`738d21227d9681299d7464d9df360cf49cac8cca` passed with zero open findings.
Signed v0.13.1 contains the exact remediated candidate and selects no crates.io
publication.

Version 0.13.2 reserves the CPU-acceleration package and low-level boundary:

- `brynja-crypto-cpu 0.1.0` is an optional, zero-dependency `no_std` package
  reserved for separately admitted first-party Rust ISA kernels;
- `brynja-crypto-cpu-std 0.1.0` is a separately selected inert host-adapter
  boundary that currently remains `no_std` and performs no CPU detection;
- the ordinary facade, protocol engines, defaults, bare-metal graphs, and
  validated-module/FIPS boundaries remain independent of both packages;
- a SHA-256-bound machine register reserves eight exact backend identities,
  modules, instruction bundles, architectures, ABI preconditions, and future
  admission duties while admitting zero active kernels and zero new low-level
  allowances; and
- positive validation plus twenty-six broken fixtures reject graph smuggling,
  dependency or feature drift, premature backend activation, unregistered
  source, low-level tokens, build scripts, false claims, and files above the
  500-line review limit.

This milestone implements no primitive, intrinsic, assembly, runtime feature
detection, executable dispatch, performance claim, independent verification,
FIPS approval, or new unsafe site. Both new packages remain unpublished and the
development release selects zero crates.io publication.

The repository-owner assessment found one High fail-open inert-source
admission flaw and one Medium policy-integrity flaw. Both are locally
remediated: source hashes and the complete reviewed policy now have independent
validator anchors, actual declarations are line-anchored, and exact semantic
comparisons cover every backend ABI, amendment duty, forbidden mechanism,
safe-wrapper invariant, and FIPS field. The permanent report records zero open
findings. Repository-owner retest of exact signed remediation candidate
`2fa60d05d8c4472426cdb979243f53e2e959c231` passed with zero open findings;
the permanent report now records `PASS`/`PASS`.

Version 0.13.3 implements the native CPU evidence and performance-admission
harness:

- a hash-bound machine schema records source, runner, measured binary, CPU, microcode or
  firmware, exact observed features and operating state, OS, compiler, flags,
  target, clock, frequency policy, workload, schedule, and raw artifact hashes;
- five native AMD, AWS Intel, Apple M2, AWS AArch64, and RISC-V lanes plus
  three QEMU supplemental lanes are explicit, with Intel currently unavailable,
  the RISC-V lane capability-inventoried but SHA-ineligible, and no lane carrying
  admission evidence;
- thirteen harness contracts cover forced and required modes, unsupported
  features, KAT and quarantine faults, scalar differential and concurrency,
  emitted code, code size, cold start, latency, throughput, and statistical
  side channels;
- freshness, sample count, logical-CPU identity, noise, balanced order,
  speedup, size, and cold-start limits fail closed; and
- a dependency-free `no_std`, no-atomics fixture exercises positive mock,
  mismatch, unsupported, fallback, required, KAT, quarantine, and independent-
  session behavior on host and OS-less targets.

The deterministic ledger records zero admitted backends and zero native
results. The assessment of implementation candidate
`9d2f6f48770bb832b1b36e2ec3e647a8a362159c` found two High flaws: self-asserted
and submitter-hashed results could authorize a candidate, and arbitrary
operating-state strings were not checked against the reviewed backend ABI.
Repository-owner retest of exact signed first remediation candidate
`7de753a57e942c28dac8406d8f93d62c4767de3a` confirmed both High findings
resolved and found one new Low uncontrolled oversized-JSON-integer exception.
Repository-owner retest of exact signed second remediation candidate
`1f08ca0fd9be6bf1995a22a9ca806addc17641e0` confirmed that parser issue
resolved with zero open findings; the permanent report records `PASS`/`PASS`.
Fifty-four adversarial evidence fixtures now reject unauthenticated candidate/native
claims, machine-readable artifact semantic drift, disabled or meaningless
ABI/vector state, oversized/non-finite/float JSON, stale provenance, missing
features, mixed CPUs, non-finite/noisy/biased
measurements, QEMU promotion, raw-file drift, and false eligibility. No trust
root or signature verifier is admitted, so recorded runner metadata and hashes
cannot authenticate evidence or authorize a backend.
No primitive, ISA kernel, detector, benchmark result, side-channel result,
unsafe allowance, performance claim, independent verification, or FIPS
approval is added. v0.13.3 selects no crate for crates.io publication.

Version 0.14.0 implements the entropy and initialized secure-random contract.
Raw caller bytes are affine secret input bound to exact instantiation or
reseed purpose, declared strength capacity, and byte count; the contract does
not estimate source entropy. Initialized state is non-cloneable, binds an
exact runtime generation, forces reseed after fork and a bounded number of
successful requests, initializes exact caller output transactionally, and
destroys/quarantines state after terminal failure. Partial writes, mismatch,
underfill, rollback, and all errors clear the complete output. A deterministic
fault engine exists only in permanently unpublished `brynja-test-support` and
is mechanically production-unreachable. This milestone adds no DRBG,
algorithm, OS entropy source, FFI, source-health result, FIPS status, or
independent verification and selects no crate for crates.io publication.
The voluntary assessment found one Medium omission where failed explicit
teardown did not invoke the terminal destruction-failure handler. The handler
now covers explicit teardown, `Drop`, rejected initialization, and permanent
quarantine; failed explicit and `Drop` teardown must each invoke it exactly
once. Repository-owner retest of exact signed remediation candidate
`854c301de56ba432bd0544e2acc525b34a7b28c8` passed with zero open findings.

Version 0.15.0 implements typed wall and monotonic clock contracts. Signed Unix
time is canonical and checked; monotonic instants are private, redacted, bound
to one nonzero runtime generation, and permanently fail after rollback.
Purpose-bound deadlines cannot cross timer, freshness, ticket, or replay
domains. The package reads no OS clock and performs no PKI, timer, ticket,
replay, or cryptographic effect. The cumulative assessment of every change
after v0.10.0 passed with zero findings and the selected package set was
published.

Version 0.16.0 implements the pending-operation lifecycle. Certificate-path,
external-signature, and accelerator requests require exact operation, poll,
cancel, and applicable destruction capabilities. Checked limits bound every
effect call and backpressure response. The effect must match the exact
authorizing provider. Provider-derived nonzero costs are charged before a
non-forgeable work permit is issued, and activation/resume/cancel/destruction
borrow state owned by the lifecycle so recoverable unwinding still reaches
`Drop` cleanup.
Effect-free preparation creates inert local state, the lifecycle takes
ownership, and provider identity is rechecked after preparation immediately
before borrowed activation may create an external resource.
Completion, cancellation, provider
failure, exhaustion, or `Drop` destroys it through mandatory destruction
authority. Completion and cancellation are unavailable
until cleanup reports complete; failed `Drop` cleanup reaches the mandatory
durable/fail-stop handler. This is an upstream contract only and implements no
provider, key store, accelerator, certificate validator, signature,
cryptographic algorithm, protocol engine, independent verification, or FIPS
validation. v0.16.0 selects no crates.io publication.

Version 0.18.0 implements a protocol-neutral mandatory security-outcome
authority contract. Sealed type-level domains cover self-tests, service
approval, protocol/profile selection, authentication, tickets, resumption,
PSKs, early data, anti-replay, amplification, exhaustion, provider results,
key lifecycle, ECH, policy, and terminal transitions. One allocation-free
caller-owned authority permits one incomplete typed decision and returns only
exhaustive accepted, approved, non-approved, rejected, pending, canceled,
failed, or terminal outcomes. Public resolutions cannot create accepted or
approved authority; future positive paths require sealed exact-subject
evidence, while external-key completion alone has an internal exact-token
acceptance path. Resolved non-terminal outcomes hold the authority in
`AwaitingCommit` until their affine completion is explicitly committed.
Each disposition is carried by an opaque, non-interchangeable result type;
rejection/failure reasons are read-only, and commit verifies the exact
disposition retained in authority state. Abandoned pending decisions and
uncommitted outcomes permanently fail closed, and mandatory self-test failure permanently latches integrity failure. Checked
generations bind affine pending values, completions, and receipts; rejection
and failure reasons cannot cross their typed domains, and terminal transitions
cannot claim ordinary success.

External-key destruction succeeds only through one consumed non-cloneable,
thread-bound token bound to the exact authority, generation, and external-store
target. Duplicate token requests, cross-authority substitution, provider
failure, and explicit abandonment fail closed. Informational snapshots cannot
authorize or complete work. Fourteen behavior tests, seven compile-fail
examples, six reviewed-source hashes, and twenty-nine broken fixtures enforce
the boundary.
No decision logic, policy implementation, authentication, protocol engine,
provider effect, external key store, audit event, cryptography, independent
verification, or FIPS validation is implemented. v0.18.0 selects no crates.io
publication.

Version 0.18.1 adds only a bounded observational duplicate of that authority.
Opaque events are derived from exact pending/outcome values or non-ready
snapshots; they expose closed decision, disposition, and terminal categories
but no authority generation, secret, handle, peer identity, plaintext,
transcript, PSK identity, ticket, ECH inner name, arbitrary string, byte
payload, or stable cross-connection identifier. Terminal events do not invent
a decision identity that the v0.18 snapshot does not retain. Records are
explicitly untimestamped until a caller supplies one wall or monotonic
observation, and timestamps cannot be replaced. The fixed-capacity
caller-owned FIFO performs no callback, I/O, retry, wait, provider call, alert,
or state transition; full and zero-capacity queues drop immediately and expose
exact-until-saturated loss accounting. Missing, ignored, delayed, duplicated,
or dropped events cannot authorize, commit, complete, latch, alter, or obscure
any mandatory outcome. The milestone adds no sink, delivery guarantee,
persistence, serialization, protocol engine, cryptographic operation,
independent review, or FIPS result and selects no crates.io publication.

Version 0.17.0 implements an inert FIPS-aware provider architecture. Broad
operation-category sets classify every capability of one installed provider
explicitly non-approved. Transactional configuration rejects every nonempty
approved set until exact algorithm, parameter, backend, and usage identities
exist, plus overlap, omission, unsupported services, duplicate fields, empty
build digests, the ordinary validated-module placeholder, and scalar or
accelerated backend/feature mismatch. SSP destruction duties derive directly
from the installed provider. Deterministic source, toolchain, flags, and
dependency digests remain expectations rather than a validated binary identity.

An explicitly trusted runner receives the mandatory integrity and algorithm
known-answer plan. Service indicators remain unavailable before success; failure,
reentry, interruption, unwind, generation exhaustion, or a later catastrophic
event permanently fails the caller-owned session. Non-cloneable thread-bound
service indicators report one operation category, disposition, provider, and
generation, cannot authorize execution, and become stale after failure.
Ordinary `BackendPolicy`, opportunistic
dispatch, std runtime detection, and the std CPU adapter cannot enter this
boundary. The milestone adds no module, algorithm, provider effect, self-test
algorithm, CPU kernel, environment measurement, deterministic binary
reproduction, SSP effect, independent verification, CMVP submission,
certificate, or FIPS validation. An exceptional assessment found and locally
remediated two High design issues. Repository-owner retest of exact signed
candidate `bc83f44a9c8fdb710d03429b1669ee6c4449b054` passed with zero open
findings. A final full-delta review through exact signed candidate
`3f889a2c07ae513235fd8cb9056faa983f2135e9` substantiated no open Critical,
High, or Medium vulnerability and confirmed both remediations. Permanent
failure remains caller-session-scoped and is currently
non-exploitable because no service is approved or executable; v0.127.1 now
explicitly requires a module-wide irreversible latch that sibling sessions
cannot bypass before that changes. The application-implementable self-test
runner likewise grants no execution or approved status; v0.125.0/v0.127.0
require an opaque module-owned attestation issued only by complete final-image
tests before either can become reachable. v0.17.0 selects no crates.io
publication.

The package was held from crates.io until the v0.15.0 public checkpoint.
Because this is the first production adapter around external unsafe
secret-storage code, v0.11.2 received an exceptional assessment; it passed
with zero findings and zero open findings. Its signed development tag was
created after green GitHub and CodeQL, and the adapter was subsequently covered
by the completed v0.10.0-through-v0.15.0 cumulative assessment and published.

The repository-owner v0.10.0 assessment found one Medium failure-observability
gap: target failure reached through either Drop implementation was discarded
because Drop cannot return `DestructionOutcome`. `SecretDestructor` now
requires a platform-specific `handle_drop_failure`; both Drop paths deliver the
closed failure there after attempting every configured target. New tests cover
failed partial-initialization and live-state drops, exact handler cause, kind,
and target, single notification, and complete target attempts. The assessment's
informational self-attestation observation remains the explicit v0.11 emitted-
code/hardware-evidence blocker. The repository owner retested signed remediation
candidate `1818f36` and reported it green with zero open findings.

The repository-owner v0.9.0 assessment of signed candidate
`fb3307a17a578daa7bd2e9f0adca4537b5e91ff8` confirmed that caller bytes remain
after arena drop and are returned unchanged by allocation. The report correctly
classified both behaviors as deliberate documented deferrals rather than a
safe-Rust memory-safety defect. A plain safe fill or `black_box` cannot support
a zeroization claim, while the suggested volatile store requires the explicit
unsafe-policy and emitted-code review already owned by v0.11.0.

The dispositions now make `SecretDomain` a storage classification rather than
a secret owner, prohibit private keys in `CertificateDomain`, prohibit
sensitive consumption before v0.10 typed complete-initialization states and the
v0.11 proven destruction primitive, and require early-return initialization
tests for every future consumer. Both findings are closed for this source-free
release with no code claiming erasure; the repository-owner retest passed.

Everything beyond those foundation domains remains governance and planning
evidence, not protocol implementation. Final Standards Track RFC 10024 and
the matching IANA assignments now resolve the source gate for exactly three
planned ECDHE-ML-KEM groups. Their implementation remains owned by v0.120.0,
and draft or private identifiers remain forbidden. Non-RFC legacy requirements
carry machine-checked blocked lifecycles and exact blocker targets until source
provenance and rights are authenticated. FIPS validation
milestones remain blocked on a dated rights-reviewed mutable guidance baseline.

`brynja-sanitization` now uses exact `sanitization 2.0.3` only under the frozen
adapter boundary. Any source, package, feature, dependency, unsafe, advisory,
target, guarantee, ownership, engine, facade, or FIPS-boundary drift forces
re-review and fail-closed withholding or removal.

The v0.3.2 repository-owner pentest cycle reported no remaining vulnerability
and one optional defense-in-depth improvement. Target validation now resolves
paths and rejects symlinks that escape the repository root. The subsequent
retest found two medium release-assurance defects: lifecycle transitions and
revisions were not bound to immutable history, and decision links could be
structurally valid but semantically unrelated. Both are remediated locally with
immutable parent-matrix comparison, append-only identifiers, exact revision
rules, explicit mapping scopes, source/disposition/owner consistency, and 16
dedicated history and semantic-link tests. A later retest found one remaining
medium bypass: protocol rows could select reviewed-global and avoid
exact-source checks. Reviewed-global is now governance-only, released scope is
immutable, and the two affected RFC-wide protocol pilot rows now use exact
IANA sources at revision three. Ordinary CI now accepts only the exact current,
committed `RETEST REQUIRED`/`PENDING` remediation state so hosted checks can
run truthfully before retest, while all release and tag paths require
`PASS`/`PASS`. The final repository-owner retest passed with zero open
findings.

The repository owner pentested the signed v0.3.3 implementation candidate and
reported a green result with no findings. Its permanent report records `PASS`,
zero open findings, and `PASS` retest status.

The repository owner pentested signed v0.3.4 candidate
`42869b4b85087bac647c11a08064189878346112` and reported two Medium
governance-integrity findings. Both were remediated in signed commit
`091c6c29dbf4613646564f3d13b9e40ecc5d40ed`: every linked surface now has an
independent authority and owner check or an exact structured exception, and
every normative RFC section now has an exact requirement binding or reviewed
disposition. The repository-owner retest was green with zero open findings.
The permanent v0.3.4 report is `PASS`/`PASS`, and signed tag `v0.3.4` is
published. Four v0.3.5 assessment rounds reported ten Medium
governance-integrity findings, all of which were remediated. The repository
owner retested signed commit
`0d1203bd1c2640e40edb31d7ff18bf20833140a2` and reported it green with no
remaining finding. The permanent v0.3.5 report records `PASS`/`PASS` with zero
open findings, and signed tag `v0.3.5` is published.

The v0.4.0 assessment cycle reported one Medium governance-integrity finding,
one accepted Low architectural risk, one Low tooling-availability finding,
and four Medium resource, containment, and Windows-availability findings.
Bounded subprocess probes, descriptor-bound input allocation, streaming
corpora, cooperative POSIX limitation disclosure, fail-closed hostile POSIX
containment contracts, Windows Job Object startup, native-host CI, and
independent-review/FIPS disclosures address the complete assessment. The
repository owner retested signed commit
`62ad878cf2e536fec43cab99d42c6943cab905d5` and reported it green with no
remaining finding. The permanent v0.4.0 report records `PASS`/`PASS` with zero
open findings, and signed tag `v0.4.0` is published. The repository owner
pentested signed v0.5.0 implementation candidate
`20305afe423d8a6142abe15bd0357546b3f8d41c` and reported it green with no
findings. Its permanent report records `PASS`/`PASS` with zero open findings.
The hosted checks passed after one documented assurance-test timing correction,
and signed tag `v0.5.0` is published. The v0.6.0 assessment found one Medium
positional-budget-construction footgun and one Low diagnostic-ergonomics gap.
Named fail-closed budget construction, a workspace-wide overlong-argument
lint, safe `NumericError` debugging, and regression tests remediate both
findings. A follow-up assessment found that repeated named setters still used
last-write-wins behavior. Every setter is now single-assignment and returns a
typed `Duplicate(domain)` error; `build()` returns typed `Incomplete(domain)`
errors. Exhaustive tests cover duplicate and missing assignment for all seven
domains. The repository owner retested signed candidate
`89d4d7a930c89e2b6788554941389ca0d83cf999` and reported it green with no
remaining finding. The permanent report records `PASS`/`PASS` and zero open
findings. Signed tag `v0.6.0` and the intended ten-crate publication are
complete. The v0.7.0 assessment of signed implementation candidate
`784bfce7ae3c68f6ad9fee0e69058bee3c2a678a` found no exploitable cursor
defect and one Low defense-in-depth observation about an implicit internal
position invariant. Debug-build assertions now make that invariant explicit.
The assessment also retained the fail-closed fixed-array conversion branch and
required parser-level adversarial fuzzing when the first concrete framed
parser is implemented. Hosted macOS CI exposed and the remediation corrected
a timing-racy detached-descendant assurance fixture. The repository owner
retested signed remediation candidate
`13adb4b4d5d5eca97b40381fc41533ba5723e69b` and reported it green with no
remaining finding. The permanent report records `PASS`/`PASS` and zero open
findings. The signed `v0.7.0` tag is complete. The v0.8.0 assessment of signed
implementation candidate `ebabb656697a5a98ac01a79b801c012daa31ca24` found no
exploitable cursor defect. It recorded the intentional no-zeroization boundary as
informational and one Low defense-in-depth observation about silently
unreachable post-preflight range fallbacks. Debug assertions now make all
three proven range invariants visible while retaining fail-closed release
fallbacks. The repository owner retested signed remediation candidate
`79027316d1d023b0f55870d8371b22a2c536a7ae` and reported it green with no
remaining finding. The permanent report records `PASS`/`PASS` with zero open
findings, and the signed `v0.8.0` tag is complete. The v0.9.0 exact workspace
and arena assessment passed retest with zero open findings; signed tag
`v0.9.0` is complete. The v0.10.0 pentest and remediation retest passed with
zero open findings; its hosted checks, signed tag, and selected crates.io
publication are complete.
