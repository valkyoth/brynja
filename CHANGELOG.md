# Changelog

All notable changes to Brynja will be documented here. The format follows
Keep a Changelog and Semantic Versioning.

## [Unreleased]

### Added

- Implement eighteen independent provider operations spanning cryptographic,
  signature, KEM, AEAD, entropy, clock, certificate-path, storage, and pending
  boundaries without implementing any provider effect or algorithm.
- Add immutable capability snapshots, transactional named installation, frozen
  resource/work limits and destruction duties, opaque borrowed handles,
  exact-operation authorization, and bounded version-neutral request metadata.
- Add nine provider-contract test groups, four compile-fail token examples,
  a SHA-256-locked four-file provider source policy, and nine broken fixtures.
- Implement private normalized `Choice` and `CtMask` values plus constant-time
  equality, conditional selection, conditional swap, and a compiler barrier for
  every unsigned word width and compile-time-sized byte arrays.
- Add exhaustive byte-pair, word-boundary, array mismatch-position, and
  compile-fail tests; a hash-locked source policy with fourteen negative fixtures;
  and optimized LLVM/assembly witnesses across ten stable compilers and nine
  promised targets with five evidence-policy fixtures.
- Add target-aware assembly function-body inspection and six negative fixtures
  for RV32 secret branches and secret-indexed loads, non-public fixed-array
  branches including a backward direct-`Choice` classifier bypass, and
  x86_64/AArch64 conditional branches.
- Canonicalize RISC-V numeric argument-register aliases, classify all eighteen
  base, pseudo, and compressed conditional forms, and retain ten focused
  negative branch/address fixtures.
- Add the versionless post-1.0 hash-ecosystem plan and the updated Brynja
  project image.
- Implement separately selected `brynja-sanitization 0.1.0` with opaque
  fixed-size ownership, closed source failures, transactional replacement,
  redacted diagnostics, explicit clear, and named exact-length copies to and
  from Brynja owned regions.
- Add behavior, every-failure-position, capacity, unwind, differential, and
  compile-fail tests plus Miri and adapter-level MIR/LLVM/assembly evidence.
- Admit exactly one external resolved package in machine policy: first-party
  `sanitization 2.0.3`, owned only by the adapter, with no enabled feature or
  transitive dependency.

### Changed

- Advance the `brynja` facade to `0.13.0` while retaining `brynja-core 0.7.0`
  and every other supporting-crate version; select zero crates for crates.io
  publication at this internal development milestone.
- Freeze provider authority in upstream `brynja-core`; keep
  `brynja-platform` as a downstream future implementation boundary and do not
  introduce a registry, fallback provider, platform dependency, or effect.
- Refresh the Miri and Rust sanitizer evidence toolchain to
  `nightly-2026-08-10` at exact Rust revision
  `969b803cbe1d4499f841ae0a49c637d8c70a0458` after the online freshness gate.
- Complete the v0.12.0 constant-time foundation without selecting any crate for
  publication; require its exceptional assessment before the signed tag.
- Clarify in the shared package header and main README that Brynja is a
  TLS-first cryptography and secure-protocol ecosystem, with reusable leaf
  hash/MAC families below the still-essential `brynja-crypto` provider and
  composition layer.
- Advance the development facade to `0.11.2` without crates.io publication or
  any facade, engine, default-feature, legacy-specific, or FIPS activation.
- Add the adapter to the package, release, archive, version-matrix, SBOM, and
  documentation inventories while deferring its first publication to a public
  checkpoint.
- Expand the future roadmap with scalar-first, per-primitive CPU acceleration
  milestones; separate no_std ISA kernels from opt-in std detection; and name
  native AMD, AWS Intel, Apple M2, AWS Arm, and qualifying RISC-V evidence lanes.
- Establish the permanent first-party Rust cryptography golden rule and plan
  separately locked downstream `brynja-rustls` and `brynja-tokio` companion
  adapters without admitting either dependency to the core workspace.

### Security

- Require one explicitly chosen provider and one exact declared operation;
  reject unsupported direction without registry search, implicit fallback, or
  authorization reuse.
- Check aggregate immutable input, output capacity, provider-operation count,
  and work limits before effects, and reject installation without an explicit
  nonempty local/external/accelerator/cache/DMA destruction-duty set.
- Keep handles, authorization, and request tokens non-cloneable and
  non-formattable; forbid provider-native IDs, mutable request output, protocol
  versions, allocation, platform coupling, unsafe code, and completion claims
  from the v0.13 boundary.
- Remediate the pentest's High RV32 timing finding by passing every expanded
  word and array mask through the non-inlined optimization barrier before
  XOR/AND selection, then close two Medium assurance-scanner bypasses through
  register canonicalization and complete RISC-V conditional classification.
- Record the repository-owner retest of exact signed candidate
  `7ce43fffdf81a349c7c44aae33b229d077d4512d` as PASS/PASS with zero open
  findings; keep the tag blocked until GitHub and CodeQL are green.
- Keep decision and mask construction private, expose one explicitly named
  public declassification, forbid ordinary equality/formatting, dynamic slices,
  secret-dependent lengths, and fallible surfaces in the v0.12 boundary, and
  document that emitted code is evidence rather than proof or a
  microarchitectural guarantee.
- Record the exceptional v0.11.2 repository-owner assessment as PASS/PASS with
  no findings and zero open findings; retain the adapter in the later
  v0.10.0-through-v0.15.0 cumulative assessment scope.
- Keep `brynja-core` authoritative for protocol-region destruction and require
  explicit copies whose two owners clear their storage independently.
- Require an exceptional v0.11.2 assessment because the first production
  wrapper around external unsafe secret-storage code is a material boundary.
- Preserve fail-closed re-review on upstream version, source, checksum,
  feature, dependency, unsafe, advisory, target, ownership, or FIPS drift.
- Require exact CPU feature bundles, forced backend differentials, KAT health
  and quarantine, native performance and side-channel evidence, honest
  candidate status, scalar fallback, isolated unsafe review, and exact FIPS
  implementation-symbol and operational-environment ownership.
- Reject C and other foreign/native cryptographic implementations, wrappers,
  vendor libraries, source and binary artifacts, package build scripts, Cargo
  native-link metadata, foreign ABIs, and external-module FIPS substitutions
  through policy, CI, and nine permanent broken fixtures.

## [0.11.1] - 2026-08-09

### Added

- Commit an exact, machine-readable admission record and reviewer-facing audit
  for first-party `sanitization 2.0.3`, including source/package hashes,
  features, graph, unsafe inventory, target evidence, advisories, upstream
  pentest, residual risks, and re-review conditions.
- Add an independent candidate wrapper with six behavior tests and three
  compile-fail tests, eleven broken policy fixtures, and release-gate online
  crates.io freshness, package-archive, compiler, and target verification.

### Changed

- Advance the development facade to `0.11.1` without publishing a crate or
  adding `sanitization` to any Brynja production manifest or lockfile.
- Conditionally admit one future protocol-neutral `brynja-sanitization`
  adapter at v0.11.2 with an exact pin, default features disabled,
  adapter-owned wrappers, explicit selection, and no legacy split.

### Security

- Keep Brynja's v0.11.0 owned-region destruction primitive mandatory and
  authoritative; the optional adapter cannot become an engine dependency or
  weaken protocol destruction duties.
- Exclude the adapter from all facades, engines, defaults, implicit
  conversions, and the FIPS validated-module closure. Upstream independent
  review remains evidence, not Brynja verification or FIPS validation.
- Remediate the candidate fixture's secret-bearing error-remanence finding by
  replacing arbitrary generic source errors with a payload-free Brynja-owned
  `SourceFailure`, rejecting rich errors at compile time, and making policy
  validation fail on generic error acceptance. The fixture was never in the
  production graph.
- Record the repository-owner PASS retest of signed remediation commit
  `cd1c881d2eb6c9aa925f1527a326330c1cf3b80a` with zero open findings; v0.11.1
  remains an internal tag with no crates.io publication selection.

## [0.11.0] - 2026-08-09

### Changed

- Advance the development facade to `0.11.0` and adopt signed tags for every
  automated-tested milestone while reserving routine cumulative pentests and
  crates.io publication for each fifth-minor public checkpoint.
- Bind every future checkpoint report to the backwards-looking change range
  after its prior public tag through the new candidate, beginning with
  v0.10.0 through v0.15.0 and then v0.15.0 through v0.20.0.
- Refresh the reviewed IANA TLS ExtensionType and DNS Parameters pins for one
  caller-owned provisional ALPN entry and three reference-only changes, without
  admitting draft/RFC implementation authority or executable behavior.

### Added

- Affine write-only initialization and readable ownership for one complete
  exclusively borrowed caller secret region.
- Complete-region volatile clearing on admission, incomplete finish, both Drop
  paths, and explicit owner clear, with failure-atomic sequential writes.
- Machine-enforced single-unsafe-block policy and MIR, LLVM IR, assembly, Miri,
  AddressSanitizer, ten-compiler, and nine-target verification.

### Security

- The zeroization claim is limited to the exclusively borrowed Rust allocation
  and excludes registers, copies, caches, DMA-visible copies, dumps, suspend
  images, physical memory, concurrent access, forgotten owners, and termination.
- v0.11.0 requires an exceptional committed PASS pentest before its signed
  development tag because it introduces the first unsafe secret-destruction
  boundary; it still selects no package for crates.io publication.
- Closed the initial pentest's unsafe-policy bypass by SHA-256 pinning the exact
  approved module and, after retest exposed comment-separated and nested-
  attribute variants, replacing syntax-shaped matching with broad fail-closed
  low-level/code-inclusion identifier rejection, fixed library targets, and
  non-symlink source confinement; the repository-owner retest of signed commit
  `88a6c73d3b2ad055702aede3858b1e7ecc8d24aa` passed with zero open findings.

## [0.10.0] - 2026-08-03

### Added

- Abstract affine secret initialization and live-state contracts with exact
  complete-write transition and no byte-backed production owner.
- Explicit local-memory, external-store, accelerator, cache, and DMA
  destruction duties for every early exit, replacement, obsolescence, and
  drop.
- Repository-only RFC 9850 key-log encoding with complete-line transactional
  writes and mechanically enforced production-graph isolation.
- Tested requirement and protocol-surface evidence for secret lifetime,
  test-only key logging, and the production key-log prohibition.

### Changed

- Advance `brynja-core` to `0.7.0`, the eight changed exact-pinned modern
  support packages to `0.1.6`, and the facade to `0.10.0`.
- Mechanically classify post-v0.10 roadmap tags as development milestones or
  each-fifth-minor cumulative public checkpoints.

### Security

- Secret states remain non-clonable, non-formattable, secret-free in
  diagnostics, and impossible to construct before complete initialization.
- No local-memory erasure claim is made before the separately gated v0.11.0
  primitive and emitted-code evidence.
- Destruction failure reached through `Drop` is delivered to a mandatory
  platform-specific durable/fail-stop handler instead of being discarded.
- The repository-owner retest passed with the Medium Drop-failure finding
  closed, the informational v0.11 evidence blocker retained, and zero open
  findings.

## [0.9.0] - 2026-08-03

### Added

- Exact caller-owned workspace partitioning across named secret, plaintext,
  transcript, certificate, and output arenas.
- Monotonic complete-range arena allocation with capacity, used, remaining,
  high-water, and successful non-empty allocation-count telemetry.
- Exhaustive small-layout, every-domain duplicate/omission,
  every-position/request, overflow, exhaustion, zero-length, sentinel,
  pointer-identity, domain-isolation, diagnostic, and compile-fail tests.

### Security

- One exact backing slice is safe-split once in fixed named order, eliminating
  caller-selected independent-buffer overlap and provenance decisions.
- Sealed zero-sized domain markers make simultaneous arena handles distinct
  Rust types and reject accidental secret/output or other domain swaps.
- Both backing-length mismatch directions and every rejected allocation leave
  caller bytes and accounting unchanged.
- Workspace and arena state is private, non-clonable, non-formattable, and
  lifetime-bound to the exclusive caller buffer; errors carry no capacity,
  offset, request, count, byte, string, or provider-native values.
- Allocated bytes retain caller contents and require initialization. No
  release, reuse, zeroization, destruction, protocol, independent-review,
  production, or FIPS-validation claim is advanced.
- Pentesting confirmed the documented drop-remanence and retained-allocation
  boundaries. `SecretDomain` now states that it is not a secret owner,
  `CertificateDomain` rejects private-key semantics, and v0.10 explicitly
  requires typed complete initialization while v0.11 retains the unsafe-policy
  and emitted-code gate for optimization-resistant destruction.
- The repository-owner retest passed with both observations closed and zero
  open findings.

## [0.8.0] - 2026-08-03

### Added

- Allocation-free `WriteCursor<'output>` exclusively borrowing caller-owned
  mutable output.
- Transactional single-slice, multi-part, and repeated-byte writes with exact
  consuming completion and immutable written-prefix inspection.
- Exhaustive every-position/request, whole-buffer no-mutation, aggregate-part,
  overflow, zero-length, empty-output, identity, representation, and
  compile-fail tests.

### Security

- Every operation checks its complete destination before changing any byte;
  capacity or arithmetic failure preserves the full output and cursor position.
- Debug builds assert that each mutable destination lookup remains reachable
  after successful preflight, while release builds retain the fail-closed
  optional-range fallback.
- Multi-part writes preflight the overflow-safe aggregate length before copying
  their first part, so one call is one mutation transaction.
- Cursor state is private, non-clonable, non-copyable, non-formattable, and
  holds an exclusive borrow that prevents safe outside output mutation.
- Write errors are closed and value-free. No integer encoding, framing, arena,
  secret-destruction, protocol, production, independent-review, or FIPS claim
  is advanced.
- The repository-owner pentest and retest passed with the post-preflight
  invariant observation closed and zero open findings.

### Changed

- Beginning after signed `v0.10.0`, group ordinary pentesting and crates.io
  publication into five-minor release trains while retaining a signed tag for
  every roadmap version. Scheduled cumulative checkpoints occur at `v0.15.0`,
  `v0.20.0`, and every fifth minor through `v0.160.0`; exceptional security and
  early-release triggers remain fail-closed.
- Development milestones and patch rows require their complete tests,
  evidence, documentation, signed commit, full automated tag gate, and green
  GitHub and CodeQL before tagging, but create no scheduled release report or
  crate publication. Plan validation mechanically distinguishes all 47 public
  checkpoints from 151 tagged development milestones.

## [0.7.0] - 2026-08-03

### Added

- Allocation-free `ReadCursor<'input>` borrowing caller-owned immutable bytes.
- Exact dynamic, typed `Length<MAX>`, and fixed-array reads with checked end
  offsets and explicit consuming trailing-data validation.
- Exhaustive every-position/request, every-truncation-byte, trailing-suffix,
  overflow, zero-length, borrow-identity, representation, and compile-fail
  tests.

### Security

- Failed reads never advance the cursor or change its remaining input.
- Cursor state is private, non-clonable, non-copyable, non-formattable, and
  bound to the caller input lifetime; no read path uses unchecked indexing.
- Remaining-input accessors assert the internal position invariant in debug
  builds while retaining fail-safe, panic-free release behavior.
- Read errors are closed and value-free: they contain no bytes, offsets,
  requested lengths, available lengths, strings, or allocation.
- No framing, integer decoding, protocol parsing, secret ownership,
  independent review, production, or FIPS-validation claim is advanced.
- The repository-owner pentest and retest passed with the defense-in-depth
  cursor observation closed and zero open findings.

### Fixed

- Replaced the hosted-macOS-sensitive detached-descendant timeout fixture with
  an ordered handshake that proves survival only after process-group cleanup.
- Release publication now accepts the properly capitalized signed tag subject
  `Brynja vX.Y.Z` while retaining compatibility with historical lowercase
  `brynja vX.Y.Z` tags; strict tag checks remain confined to the publisher's
  explicit publish context.

## [0.6.0] - 2026-08-01

### Added

- Private-field bounded `u64` and `usize` values with fallible construction
  and checked addition, subtraction, and multiplication.
- Semantically distinct bounded counts and byte lengths with fail-closed
  `u64`-to-`usize` conversion.
- Protocol-neutral sequence-number and 16-bit epoch values that return typed
  exhaustion instead of wrapping.
- Explicit immutable resource and work budgets with no defaults or setters.
- Exhaustive small-domain arithmetic/advance matrices plus boundary,
  representation, no-mutation, zero-budget, and compile-fail tests.
- Reviewed the 2026-07-31 IANA DNS Parameters refresh and classified its three
  new registries and seventeen entries as caller-owned v0.140.0 surfaces.

### Security

- Primitive overflow, configured-bound violations, underflow, pointer-width
  truncation, and monotonic-value exhaustion all fail closed in every profile.
- Count/length confusion is rejected by the type system, and numeric values
  and budgets implement neither `Debug` nor `Display`.
- Budget failures preserve resource class and operation phase without carrying
  configured numeric limits.
- Replaced the seven-argument resource-budget constructor with a named builder
  that fails closed until every domain is supplied, and deny future overlong
  positional APIs through workspace Clippy policy.
- Added safe `Debug` diagnostics for the closed, valueless `NumericError` enum
  while bounded values and budget types remain non-formattable.
- Made every named resource-budget setter single-assignment and return a typed
  `Duplicate(domain)` error instead of silently replacing an earlier limit;
  incomplete builds now return typed `Incomplete(domain)` errors.
- No TLS/DTLS record, sequence, epoch, parser, mutable accounting, protocol,
  independent-review, production, or FIPS-validation claim is advanced.
- Provisional draft references carried by IANA registry records are not
  admitted as implementation authority.
- The repository-owner pentest and follow-up retest passed with all three
  reported API-design findings closed and zero open findings.

## [0.5.0] - 2026-07-31

### Added

- Exhaustive TLS AlertDescription classification across all 256 registry
  bytes, preserving assigned, reserved, and unassigned identities.
- Protocol-version-aware assigned alerts with derived semantic class and
  hardened severity.
- Distinct orderly-close, cancellation, alert-failure, local-failure,
  provider-failure, and resource-exhaustion domains in `brynja-core 0.2.0`.
- Positive, negative, exhaustive, representation-bound, and compile-fail tests
  linked to the tested `BRY-REQ-TLS-0005` requirement.

### Security

- Failure envelopes accept no arbitrary text, bytes, provider-native codes,
  cryptographic material, or numeric limits and implement neither `Debug` nor
  `Display`.
- Close and cancellation cannot be ambiguously collapsed into `TlsFailure`;
  only error-class alerts can become alert failures.
- The alert registry is the only protocol surface marked implemented. TLS,
  DTLS, cryptography, PKI, providers, independent verification, production
  readiness, and FIPS validation remain explicitly unclaimed.
- The repository-owner pentest of the signed implementation candidate passed
  with no findings; the permanent report records `PASS`/`PASS` and zero open
  findings.

## [0.4.0] - 2026-07-31

### Added

- A first-party deterministic mutation runner covering empty, original,
  truncation, deletion, bit-flip, and zero/`0xff` insertion cases with exact
  replay indexes and SHA-256 failure identities.
- A canonical raw-stdin differential protocol requiring at least two distinct
  process adapters and rejecting crash, timeout, output exhaustion, malformed
  JSON, noncanonical hex, unsupported classes, and semantic mismatch.
- OS-less all-feature workspace checks for ARMv7E-M, RV32IMAC, and x86_64.
- Deterministic assurance evidence binding policy, runners, CI, and every Cargo
  manifest, with 24 positive and broken fixtures.

### Security

- Child processes run without a shell and both output streams are capped while
  produced. Inputs are explicitly public test data, and campaign launchers
  must provide OS network, filesystem, process, and device isolation.
- Kani 0.67.0, AFL++ 5.02c, honggfuzz 2.6, Miri, and Rust sanitizers have exact
  upstream source revisions and cannot enter repository Cargo manifests.
- Stable Rust 1.97.1 remains the release compiler; Kani 0.67.0 uses a separate
  compatible Rust 1.90.0 verifier pairing. No proof harness is admitted, and
  policy-only status cannot be claimed as formal verification.
- Bare-metal compilation does not claim startup, allocation, interrupts,
  entropy, time, transport, storage, emulator, hardware, or Aesynx support.

## [0.3.5] - 2026-07-31

### Added

- Fifty optional, HPKE, ECH, ML-KEM, entropy, operational, legacy, and
  residual requirements, bringing the deterministic matrix to 167 records.
- Local-only checksum pins for final FIPS 203, SP 800-227, SP 800-90B, and
  SP 800-90C.
- Exact residual coverage of 33 authorities, 182 normative RFC sections, and
  all 743 surfaces left by the foundation, domain, and transport bundles.
- A generated closure report mapping all 126 locked authorities, 206 roadmap
  rows, 4,424 protocol surfaces, and 167 requirements in both directions.
- Twenty-two residual broken fixtures, bringing the requirement suite to 110
  positive and negative tests.

### Security

- Concrete ECDHE-ML-KEM groups remain blocked because the current IANA values
  are provisional and the group specification is not yet a final RFC; drafts
  and private code points cannot satisfy the gate.
- Non-RFC legacy implementations remain blocked on authenticated source bytes,
  hashes, errata, redistribution rights, cipher decisions, isolation review,
  and a separate pentest.
- FIPS validation milestones remain blocked on a dated, rights-reviewed FIPS,
  ISO, CMVP, laboratory, certificate, caveat, and operational-environment
  baseline; no current package or profile claims FIPS validation.
- Every local NIST/ITU authority has an explicit local-only distribution
  record, while all eight IANA registries and five mutable NIST publication
  pages have dependent-milestone refresh owners.
- Raw Public Keys, Delegated Credentials, certificate-compression receive,
  artifact, and send phases, HPKE context/base/export phases, ECH phases, and
  entropy phases now match their exact roadmap owners.
- Two Medium pentest findings are remediated: all 741 residual surfaces are
  explicit, reciprocal, independently validated, and homogeneous by code/test
  boundary; all 182 residual normative sections have one or more of 165 exact
  mappings or one of 17 reviewed exclusions instead of RFC-wide inheritance.
- Three additional Medium retest findings are remediated: section decisions
  reconcile globally across bundles, RFC 9853 RRC extension and registry
  ownership is confined to the v0.111.1 DTLS boundary, and SSL 2, WTLS, PCT,
  SNP, and SSL 1 requirements remain mechanically source-blocked.
- Two further Medium retest findings are remediated: RFC 9853 ContentType 27
  is confined to a dedicated DTLS-only admission boundary, and RFC 6066
  sections are split among exact SNI, status, alert, exclusion, and
  cross-bundle delegation decisions instead of being attributed wholesale to
  OCSP.
- Three final Medium retest findings are remediated: unsupported RFC 6066 peer
  ClientHello extensions use a bounded opaque ignore path distinct from
  rejected local configuration and unsolicited responses; RFC 6066 has an
  independent TLS 1.2 owner at v0.90.1; and generated `delegated` section
  evidence is declared and contract-tested against the schema.
- The repository-owner retest of the complete ten-finding remediation passed
  with zero open findings; the permanent v0.3.5 report is `PASS`/`PASS`.

## [0.3.4] - 2026-07-30

### Added

- Sixty-three stable TLS, hardened TLS 1.2, QUIC-TLS, DTLS 1.2, and
  DTLS 1.3 semantic surfaces, one for every owning implementation milestone
  from the shared secret contract through the DTLS audit gate.
- Seventy transport requirements, bringing the deterministic matrix to 116
  stable records and explicitly covering 40 authorities, 550 normative RFC
  sections, and 480 transport surfaces.
- Exact current, compatibility, evidence, exclusion, and caller-owned source
  roles plus explicit requirements for Heartbeat, legacy TLS 1.3 PKCS1 client
  signatures, post-handshake authentication, certificate-with-external-PSK,
  and the QUIC transport boundary.
- A generated transport-coverage artifact and eight positive and
  broken-fixture tests for milestone, authority, role, binding, identity,
  surface, and reproducibility failures.
- Reviewed domain and transport section policies that bind all 914 normative
  RFC sections to exact requirements, extraction anchors, and section hashes,
  plus seven dedicated positive and broken section-binding fixtures.

### Security

- Every planned transport state transition has one stable owner, target
  symbol, positive and negative test target, work bound, evidence gap, and
  residual-risk statement without claiming protocol code exists.
- QUIC packet, frame, recovery, congestion, Retry, migration, and transport
  semantics remain mechanically caller-owned; TLS, TLS 1.2, TLS 1.3, DTLS,
  and QUIC requirements cannot hide behind a generic cross-version mapping.
- RFC 9850 key logging and four optional TLS facility groups remain explicit
  v0.3.5 deferrals; the status_request_v2 exclusion remains bound to its
  already reviewed v0.3.3 OCSP requirement.
- Protocol-surface and requirement artifacts now bind the separate transport
  policies and reject missing owner milestones, authority drift, role swaps,
  duplicate identities, and stale projections.
- The pentest's two Medium governance-integrity findings are remediated:
  every linked surface must independently match authority and owner or use an
  exact structured exception, and every normative section must have an
  explicit requirement binding or reviewed disposition. External retest of
  the remediated candidate passed with zero open findings; the permanent
  v0.3.4 report is `PASS`/`PASS`.

## [0.3.3] - 2026-07-30

### Added

- Thirty-four cryptography, encoding, PKIX, OCSP, and Certificate
  Transparency requirements, bringing the deterministic matrix to 46 stable
  records.
- Exact authority-role coverage for all 53 assigned sources, section-hash
  coverage for 364 normative RFC sections, and requirement or explicit
  deferral coverage for all 3,322 selected protocol surfaces.
- Local-only checksum pins for FIPS 202 and the in-force ITU-T X.690 (2021)
  plus Erratum 1.
- Explicit SHA-3/SHAKE, GHASH, and ChaCha20 semantic decisions and corrected
  SHA-2, HMAC, HKDF, and AES milestone ownership.
- A generated domain-coverage artifact and 15 positive and broken-fixture
  tests for authority, scope, role, ownership, work-bound, invariant,
  test-polarity, surface-group, and reproducibility failures.

### Security

- Every new requirement records explicit resource or work assurance,
  positive and negative target tests, unresolved evidence, and residual risk
  without claiming planned code exists.
- Current, compatibility, evidence, and exclusion authorities cannot be
  silently interchanged; every in-scope source must be cited and every
  selected surface must be assigned.
- ML-KEM algorithm and PKIX credential surfaces remain explicitly deferred to
  the complete hybrid review at v0.3.5.
- Five newly reported RFC Editor errata were reviewed as
  `track-not-applied`; no reported erratum was silently incorporated.
- The repository-owner pentest passed the signed v0.3.3 implementation
  candidate with zero findings and required no remediation.

## [0.3.2] - 2026-07-27

### Added

- A stable normative-requirement policy and deterministic schema, resolved
  matrix, bidirectional indexes, and human-readable coverage report.
- A 12-requirement authority pilot spanning all eight lifecycle states and
  binding exact RFC, errata, IANA, source-ledger, and protocol-surface
  evidence.
- Fifty-one positive and broken-fixture tests for identity, source, section,
  lifecycle, transition, ownership, target, evidence, SHOULD-deviation, drift,
  symlink-escape, immutable history, revision, semantic-link, and stale-output
  failures.

### Security

- Protocol requirements cannot claim implemented, tested, or evidenced status
  before their owning implementation milestone and existing anchors.
- Ordinary and release checks now fail closed on requirement-policy or
  generated-evidence drift.
- Actual target validation resolves symlinks and rejects paths that leave the
  repository root.
- Requirement changes are compared with the immutable parent matrix; IDs
  cannot disappear, lifecycle transitions must be legal, and content changes
  require exactly one revision increment.
- Exact-source decision mappings now enforce source, disposition, and owner
  consistency, while broader governance mappings require explicit reviewed
  rationale.
- Reviewed-global mappings are restricted to governance requirements, and a
  released requirement cannot change between governance and protocol scope.
- Ordinary CI accepts only a well-formed, current, committed
  `RETEST REQUIRED`/`PENDING` pentest report while remediation awaits external
  retest; release and tag gates continue to require `PASS`/`PASS`.
- The repository-owner retest passed after all v0.3.2 remediations, leaving
  zero open findings and the permanent report in `PASS`/`PASS` state.

## [0.3.1] - 2026-07-27

### Added

- A deterministic protocol-surface register containing 45 explicit semantic
  decisions, 192 nested IANA registries, and all 4,106 individual records from
  the eight pinned registry collections.
- Required disposition, normative-source, milestone-owner, planned-code-target,
  planned-test-target, and rationale fields for all 4,343 classified surfaces.
- Explicit decisions for Heartbeat, status_request_v2, production and
  test-only SSLKEYLOGFILE handling, TLS 1.3 post-handshake authentication,
  certificate-with-external-PSK, legacy PKCS1 client signatures, ML-KEM PKIX
  credentials, HPKE non-base modes, unsigned X.509 certificates, QUIC
  version-specific cryptography, and certificate compression.
- Human-readable generated disposition, kind, and domain coverage.
- Twenty-five positive and broken-fixture tests for completeness, ownership,
  source binding, classification, override, parser, and reproducibility
  failures.

### Security

- Bound the surface policy to the byte-exact v0.3.0 source ledger so RFC
  status, errata, registry, source, and classification drift cannot remain
  silent.
- Rejected missing or duplicate collections, registries, semantic IDs, JSON
  keys, and overrides; unknown sources, milestones, dispositions, and targets;
  overlapping rules; unmatched selectors; unsafe XML declarations; and any
  premature `implemented` claim.

## [0.3.0] - 2026-07-27

### Added

- A deterministic standards ledger covering all 103 locked RFCs, eight
  local-only NIST authorities, eight exact IANA registry snapshots, and every
  owning roadmap milestone.
- A complete reviewed inventory of 285 official errata with fail-closed
  dispositions based on RFC Editor status.
- Offline source, checksum, lifecycle, relationship, ownership, blocker, and
  reproducibility validation with 28 positive and broken-fixture tests.
- A networked release check that rejects RFC index, errata, or IANA drift.
- A permanent evidence index and explicit final-RFC plus final-IANA admission
  blocker for concrete ECDHE-ML-KEM groups.

### Fixed

- Replaced refresh-time trust-on-first-use hashes with independently reviewed,
  non-self-replacing RFC, NIST, RFC-index, errata, and IANA pins.
- Enforced the exact HTTPS source and redirect allowlist in the Python
  standards pipeline.
- Bounded all upstream responses and rejected XML DTD and entity declarations
  before parsing to prevent compromised-source expansion and memory denial of
  service.
- Kept local-only, redistribution-restricted NIST bytes optional in clean CI
  while still validating their complete manifest and automatically checking
  every byte whenever a local cache exists.

## [0.2.0] - 2026-07-27

### Added

- Machine-readable classification and exact dependency/feature/publication
  policy for all 24 workspace packages.
- Separate no-default and all-feature graph validation with modern, legacy,
  QUIC, repository, target, pin, and feature-smuggling negative fixtures.
- Machine-checked GitHub main-branch release controls matching the protected
  `eth` ruleset model.

### Changed

- Required pentest reports to be regular committed files synchronized against
  every prior report-bearing parent.
- Required release tags to be directly targeted, signed and annotated with the
  exact `brynja vX.Y.Z` subject.
- Extended Clippy enforcement to both all-feature and no-default-feature
  workspace configurations.
- Supplied step-scoped GitHub workflow authentication to the live protected
  release-control validator and enforced that wiring in release metadata.
- Documented the intentional fail-closed release panic posture and its
  availability tradeoff.

## [0.1.0] - 2026-07-26

### Added

- Security-first, dependency-free, `no_std` workspace foundation.
- Modern and legacy protocol package boundaries.
- Standards provenance, toolchain, platform, and release planning policies.
- Guarded independent-version crates.io planning and dependency-order
  publication with mandatory facade releases.
- Committed per-version pentest reports that must stay synchronized with every
  later release-candidate fix before green CI and explicit tagging.
- Versioned admission and conditional implementation stops for one optional
  protocol-neutral `brynja-sanitization` downstream adapter, with no
  `zeroize`, third-party activated dependency, facade, engine, or FIPS-module
  path.
- Independently pinned and verified CI security-tool archive checksums.

### Changed

- Made truncating-cast and sign-loss Clippy lints non-overridable.
- Enforced publication of `brynja` for every official tag, selected the full
  initial modern dependency closure, and added non-uploading package-archive
  validation to the guarded publisher.
