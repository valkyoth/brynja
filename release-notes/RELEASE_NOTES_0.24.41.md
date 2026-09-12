# Brynja v0.24.41

Status: exceptional owner retest and four-lane native collection passed; final
release and GitHub checks remain required. No tag or crates.io publication is
authorized by these notes.

Adds separate default-off operational SHA-1 execution for ordinary public legacy
data. Static x86 SHA/SSE2 and AArch64 NEON/SHA1 routes reuse first-party kernels;
the optional hosted adapter accepts only reviewed AArch64 system feature APIs.
Generic x86 hosted selection fails required mode or uses portable preferred mode.

New APIs provide explicit portable/preferred/required selection, public-data
classification, streaming, one-shot byte/bit hashing, checked length preflight,
consuming finalization/cancellation, diagnostic reports and permanent revocation.
Borrowed operations remain thread-bound and cannot outlive their authority.
Old candidate APIs remain evidence-gated, and portable defaults are unchanged.

The modern facade, TLS/PKIX defaults and FIPS graphs do not gain legacy SHA-1.
No third-party dependency or new instruction kernel is introduced. SHA-1 remains
collision-broken. Operational acceleration is public-data-only; hardened
secret-bearing acceleration is separate v0.24.42 work. Registers, spills,
compiler-created copies and platform storage are not guaranteed erased.

Acceptance covers NIST vectors, independent bit-message comparisons, packaged
consumers, ownership and revoked-owner behavior. Full scoped verification,
fresh native qualification and the exceptional pentest remain release gates.
Project-owned tests are neither independent cryptographic verification nor
FIPS validation. This internal milestone publishes zero crates.

Development verification passed:

- Scoped repository gate, workspace all-feature tests, Clippy, documentation,
  crate README checks, modern/legacy dependency isolation and current SBOM.
- Rust 1.90.0 leaf/adapter tests and bare-metal `no_std` compilation.
- All 529 NIST vectors and million-byte hashing through ordinary execution;
  1,135 independent bit-message cases through extracted-package consumers.
- 19 packaged ownership/classification rejections and four compiled
  debug/release revocation/finalization regressions.
- 60 SHA-1 policy/documentation mutations and native-capture rejection tests.
- Native x86 SHA-NI tests, including AddressSanitizer with explicit SHA/SSE2
  compilation; AArch64 static/hosted QEMU correctness (not native evidence).
- Scoped SHA-1/legacy Miri and Kani, plus existing SHA-1 emitted-instruction
  and cleanup checks at the supported compiler endpoints.

The old native snapshot remains immutable. A narrow, hash-bound operational
source delta is explicitly not fresh native proof. The documentation-only unsafe
module-count regression remains in mandatory repository checks without selecting
unrelated Miri campaigns. This development pass is separate from the subsequent
owner retest and native collection recorded below.

Pentest follow-up requires a platform revalidation callback instead of an
always-true hook. A reported loss irreversibly revokes live streams. Revalidation
does not replace the deployment's lifetime-long feature guarantee or prove safe
VM migration. Public-data acknowledgement cannot detect confidential input;
the ordinary/hardened split and per-boundary health checks remain unchanged.
The subsequent owner-supplied retest is clean; it is not a named independent
cryptographic review.

The follow-up review downgraded the platform-trust finding to a Low residual,
not a closed issue. The SHA-1 documentation now records all five OS detector
mappings and their individual trust limits, with six regression checks against
missing platform justifications or a cached-detection/live-revocation conflation.
This follow-up changes no production Rust or platform availability.

Fresh ordinary execution observations passed on AMD, Intel, AWS AArch64 and
Apple M2 Pro at `83a30e23`. Original records, hashes, route coverage and limits
are preserved in the [native archive](../assurance/sha1-execution-observations/v0.24.41/README.md).
The final documentation updates do not change production code or capture commands.
The Low platform-trust residual remains accepted and disclosed, not eliminated.

Release tooling also checks that the older TupleHash/ParallelHash native input
drift is exactly a facade fixture version and its hash pin. It preserves the
original captures, revalidates every artifact, and rejects any other changed
native input, executable policy, fixture setting or result. Fourteen Git-backed
regression tests cover both families. This is evidence reuse, not fresh hardware
execution. No other changed workspace crate is selected for publication.
