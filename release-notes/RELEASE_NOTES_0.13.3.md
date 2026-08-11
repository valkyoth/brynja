# Brynja v0.13.3 Development Milestone

Status: implementation and retest complete; awaiting green GitHub and CodeQL

Brynja v0.13.3 implements the repository assurance boundary that every future
CPU-accelerated cryptographic backend must satisfy. It advances only the
`brynja` facade version to 0.13.3, admits no backend, and selects no crate for
crates.io publication.

## Evidence And Admission Contract

- `assurance/cpu-evidence-policy.toml` defines exact bounded fields for source,
  runner, CPU, microcode or firmware, observed features and operating state,
  OS, compiler, flags and measured binary, clock and frequency policy, workload distribution,
  measurements, claims, and raw result artifacts.
- `security/cpu-backend-admissions.toml` retains all eight reserved x86_64,
  AArch64, and RISC-V backends as explicitly `unadmitted`.
- Five native lanes cover local AMD x86_64, observed-feature AWS Intel x86_64,
  Apple M2, AWS AArch64, and the available RISC-V cloud host. Three QEMU lanes
  are supplemental-only and can never satisfy native performance or side-
  channel evidence.
- The generated `assurance/cpu-evidence-ledger.json` binds the policy, lanes,
  harnesses, backend decisions, and future manifests byte for byte.

## Harnesses And Budgets

Thirteen first-party contracts cover forced backend selection, required mode,
unsupported features, KAT and quarantine faults, scalar differential and
concurrency isolation, emitted code, code size, cold start, latency,
throughput, and statistical side channels.

Admission requires fresh single-logical-CPU evidence, 31 or more samples,
deterministic balanced interleaving, no more than ten-percent coefficient of
variation, at least a five-percent speedup, no more than 64 KiB code growth,
and at most 5 ms cold-start overhead. Every artifact is bounded exact JSON,
hash-bound and semantically tied to the complete run context and declared
results. Statistical side-channel testing retains an explicit not-proof
residual gap. Hashes and recorded runner ownership are not authentication, so
all candidate/native claims remain forbidden until a reviewed trusted-runner
verifier exists.

## Verification

- 55 adversarial evidence fixtures reject checkout-byte drift, stale or future timestamps,
  incomplete feature or exact operating-state bundles, fabricated native labels, wrong runner owners,
  vendor/model substitution, mixed CPUs, non-finite/noisy/biased measurements, insufficient samples or
  speedup, exceeded size/start budgets, failed correctness and security gates,
  raw-file drift or path escape, forged or semantically inconsistent
  machine-readable results, unauthenticated candidate/native claims, false
  eligibility, and QEMU promotion.
- A dependency-free non-cryptographic `no_std` fixture exercises scalar,
  positive forced mock, unsupported, opportunistic fallback, required-no-
  fallback, KAT mismatch, permanent quarantine, scalar differential mismatch,
  and independent interleaved sessions.
- The fixture runs under host tests and compiles across the stable Rust and
  OS-less target matrices. Its source may contain no atomic, allocation,
  standard-library, or low-level code.
- Unavailable Intel, unmeasured hardware, and non-qualifying RISC-V state stay
  visibly unadmitted without changing or blocking portable scalar builds.
- The release-time live standards gate reviewed and pinned IANA's 2026-08-11
  `_x402` TXT underscored service-name addition as caller-owned v0.140.0
  planning data; its provisional draft reference admits no authority or code.
- A subsequent live-gate run reviewed and pinned IANA's 2026-08-11 C509
  Certificate type allocation as non-authoritative future work; the
  provisional draft reference admits no authority, implementation, or runtime
  behavior.
- GitHub's ordinary repository-gate job installs all three OS-less Rust targets
  before the CPU-admission fixture runs; assurance validation rejects removal
  of that setup.
- Repository text is checked out with LF on every host, and CPU-evidence tests
  reject removal of that rule so reviewed policy hashes remain portable to
  Windows runners.

## Security And Verification Status

The voluntary assessment of implementation candidate
`9d2f6f48770bb832b1b36e2ec3e647a8a362159c` found two High issues: self-
asserted evidence could authorize a candidate, and arbitrary operating-state
strings could bypass reviewed ISA prerequisites. Both are locally remediated
through the authentication hard gate, exact artifact semantics, and exact
backend operating-state equality. First remediation retest confirmed both High
findings resolved and found one Low oversized-JSON-integer traceback. Signed
64-bit-only artifact parsing and controlled float/non-finite rejection remediate
that issue. Repository-owner retest of exact signed second remediation
candidate `1f08ca0fd9be6bf1995a22a9ca806addc17641e0` passed with zero open
findings; the permanent report records `PASS`/`PASS`. See
`security/pentest/v0.13.3.md`.

This milestone contains no cryptographic primitive, ISA kernel, CPU detector,
native benchmark result, native side-channel result, executable backend, new
unsafe allowance, performance claim, independent cryptographic verification,
or FIPS validation. The existing two CPU packages remain inert and unpublished.

## Release Process

v0.13.3 is an internal development milestone in the cumulative range after
v0.10.0 through v0.15.0. It selects zero crates for crates.io publication. The
complete local gate, green GitHub and CodeQL, and explicit repository-owner
authorization remain mandatory before the signed `v0.13.3` tag. A voluntary
assessment may be recorded for this tag, but the scheduled cumulative pentest
and crates.io publication occur at v0.15.0 unless an exceptional trigger is
activated earlier.
