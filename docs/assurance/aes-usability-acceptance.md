# AES public API usability acceptance — v0.27.5 worklist

Status: in progress, not release approval. This step consolidates consumer
usability over the existing AES primitive; it adds no mode, protocol, provider
requirement or backend admission. Internal v0.27.5 candidate metadata is now
prepared; final checks, a clean commit and GitHub/CodeQL handoff remain separate.

## Owner scope decision — 2026-11-13

The owner confirmed that the previously documented timing investigation should
remain deferred, with its public discussion available for further input, rather
than require further hours of investigation before usability acceptance. After
clarification that the ARM accelerated observations are inconclusive rather
than a demonstrated portable-AES defect, the owner explicitly agreed to carry
that disposition into v0.27.5 and revisit it in the future.

This narrows milestone closure to usability acceptance with an explicit residual;
it does not complete timing qualification. The original observations, declarations,
alarm/noise classifications and binary identities remain unchanged. A stronger
claim needs a new prospective study, not retries-to-pass. No version or deadline
for that study is implied. Newly demonstrated defects still require assessment.
This decision is not tag authorization, publication approval or an expansion of
hardware admission. The existing release workflow remains unchanged.

## Initial portable composition slice

The checkout-external and archive-only consumers now require 21 named tests
per configuration instead of 18. Three new tests cover AES-128/192/256 with
six deterministic public key/block pairs each and all four combinations of
operation-local/cached encrypting and decrypting owners: 72 round trips per
configuration. Decryption consumes the actual encrypted block after the first
key owner is cleared. A checked slice-to-array reference conversion borrows
the exposed block without making an unowned secret copy.

Both result owners are explicitly cleared; key/schedule and result canaries
are checked, as are untouched storage and caller input copies. Frozen known
answers remain mandatory: a round trip alone cannot detect matching forward
and inverse defects. All new cases are required by exact test names and count;
the existing negative controls reject missing, ignored or duplicated tests.
The new source is included in both consumer fingerprint groups.

Run the existing scoped registrations explicitly:

```sh
brynja-verify run aes downstream
brynja-verify run aes packaged-portable
```

These cover direct/facade consumers, Rust 1.90.0 and 1.99.1, debug/release,
and no_std Cortex-M compilation. Packaged acceptance also retains its paired
API misuse probes, archived README runs and default-off feature controls.
Consult the verifier for actual execution dates and source fingerprints; this
document does not assert a current pass or require unrelated campaigns.

## Accelerated composition slice

The existing packaged campaign runner now has an explicit `roundtrip` suite.
It reuses the portable test source byte-for-byte except for its public import,
forced-authority construction and the four owner-constructor arguments. The
adapter has no portable fallback. Regression controls reverse the adaptation
to recover the original source, reject missing/symlinked or changed anchors,
and reject missing/duplicated/ignored tests, wrong summaries or backend markers.

```sh
brynja-verify run aes --needed --category aes-roundtrip
```

Twelve registrations cover both compiler endpoints and direct/facade routes
with native static AES-NI, ARM QEMU static and ARM QEMU hosted selection. Each
runs debug and release with three exact test names and three matching forced
backend markers per profile. This is 24 configurations and 1,728 round trips.
These runs exercise lifecycle/composition only: they supplement rather than
replace the independently frozen KAT, AESAVS and differential campaigns.

## Accelerated width and ownership contracts

The paired compiler probes now cover wrong-sized keys and owner storage for
all six accelerated key owners, plus wrong-sized input/output blocks for each
owner's encryption, decryption and explicitly acknowledged public encryption
methods. Every negative case has a compiling positive counterpart and must
produce exactly the expected type-mismatch diagnostic. These are compile-time
API contracts, not executions of the cryptographic backend.

The host runner requires 223 paired probes per compiler endpoint across the
direct/facade and hosted API groups. Archive-only no_std consumers require
110 paired probes per route/endpoint, including feature-isolation controls.
The RISC-V probes retain the distinction between ordinary unadmitted routes
and evidence-only builds; compilation does not establish hardware support.

```sh
brynja-verify run aes execution-api-msrv
brynja-verify run aes execution-api-current
brynja-verify run aes --needed --category aes-accelerated-no-std
brynja-verify run aes --needed --category aes-riscv-no-std
```

The portable README example already exercises all six portable owner types
with frozen answers, round trips, borrowed result buffers and explicit
clearing, and is executed from packaged archives. No production API changes are
needed for this width-contract slice. The [usage guide](../aes-usage.md) now
connects the existing tested portable, accelerated no_std and hosted examples,
including authority ownership and unavailable required routes, without adding
another code sample or release gate.

## Consumer and qualification matrix

| Consumer route | API/admission contract | Composition slice | Qualification boundary |
| --- | --- | --- | --- |
| Portable, direct/facade | Explicit `hazmat-aes-block`, no CPU authority | Archive and checkout consumers, all widths and owner combinations | Named portable observations only; no physical-security claim |
| Static x86 AES-NI | Complete target bundle and healthy startup authority; deployment must keep it valid | Packaged native endpoint runs, no fallback | Existing emitted-code/AVS records retained; accelerated timing remains inconclusive |
| Static AArch64 | Explicit AES/NEON specialization and healthy startup authority | Packaged ARM QEMU endpoint runs | Functional emulation only; previous native records keep their original source identities |
| Hosted AArch64 | OS system-wide feature detection and `Mode::Require`; portable fallback rejected | Packaged ARM QEMU endpoint runs with baseline target features | Not fresh Linux/Apple native qualification or whole-owner DIT/DMP protection |
| Hosted x86 | Generic hosted selection remains unavailable | No positive forced-hosted registration | Current-core CPUID is not a lifetime deployment contract |
| RISC-V | Ordinary routes unadmitted; explicit evidence cfg only | Existing v0.27.4 QEMU KAT/AVS/oracle and linked records | No native acceptance, new admission or timing claim |

## Evidence mapping, not a new qualification claim

All references below retain their original compiler, source and executable
identities. They are not imported as fresh passes merely because this milestone
changes tests or documentation. The compiler endpoints are Rust 1.90.0/1.99.1;
profiles and routes within each linked record remain part of its scope.

| Evidence | Retained scope | What v0.27.5 does not infer |
| --- | --- | --- |
| [Portable AESAVS and differential campaigns](aes-portable-acceptance.md#aesavs-monte-carlo-and-multiblock-slice) | Archive-only direct/facade, all widths/directions, operation-local/cached owners; separate independent OpenSSL comparisons | A round trip does not replace known answers or independently qualify changed arithmetic |
| [Portable timing and linked matrix](aes-portable-acceptance.md#qualification-boundaries-still-open) | Named x86 and native AWS ARM builds, including recorded final-linked/LTO, panic-profile and helper/caller review boundaries | No universal constant-time or spill-erasure proof; passing portable screens do not settle accelerated timing |
| [Accelerated native inventory](aes-acceleration-acceptance.md) | Named x86, Linux ARM and Apple correctness/AESAVS/differential runs and bounded linked reviews | No fresh ARM/Apple execution from local QEMU; historical pre-DIT reviews do not qualify later dispatch changes |
| [DIT linked-session review](aes-dit.md#bounded-linked-session-review-2026-11-12) | Nine Session bodies and six raw kernels per named Linux ARM compiler consumer, with explicit exclusions | Not whole-owner, Apple, arbitrary caller or timing-fixture qualification |
| [Finite DIT timing screen](aes-dit-finite-results.md) | Linux ARM and Apple, exact frozen builds and samples; both screens inconclusive | No timing pass, subtraction of diagnostic offsets, or clean-result rerun |
| [RISC-V campaigns](aes-riscv-development.md) and [linked review](aes-riscv-linked.md) | QEMU evidence-only RV64 scalar AES, archive AESAVS/oracle, bounded emitted-code review and non-admission controls | No native hardware, vector AES, hosted admission, timing or physical qualification |

The new composition and width checks above add public-consumer coverage without
changing production arithmetic, dispatch or dependencies. Hosted selection
reproduction is `brynja-verify run aes --needed --category aes-hosted`: native
x86 checks pre-execution unavailability, while ARM QEMU exercises the admitted
hosted route, known answers and terminal quarantine on both compiler endpoints
in debug/release. These are functional results, not timing experiments.

## Remaining acceptance work

- Preserve the distinct platform/admission contracts in the consumer matrix
  and usage guide. Native ARM/Apple composition refreshes remain distinct from
  the local QEMU registrations above; these examples do not refresh them.
- Keep [accelerated timing uncertainty](aes-acceleration-acceptance.md)
  unresolved under the owner decision above. No new experiment is launched;
  the revised roadmap closes usability, not full timing qualification.
- Keep [RISC-V evidence](aes-riscv-linked.md) separate from native acceptance.
  QEMU does not establish native timing, power/EM or physical-fault resistance.
- Prepare candidate metadata, public documentation and scoped review after
  the bounded acceptance work. Retain the existing finite release workflow;
  optional PKCS#11 and fault-detecting profiles remain separate milestones.

## Candidate working-tree preflight — 2026-11-13

The facade, isolated consumer pins/lockfiles and SBOM now identify 0.27.5.
All 30 existing finite checklist commands passed on the prepared working tree,
including 1,076 registry tests, 42 scoped-release tests, packaged modern/legacy
HKDF endpoints, portable AES downstream endpoints, lint/format, requirement
mapping, dependency policy and the updated RustSec advisory scan. Check commands,
timeouts and CI selection are unchanged. No timing or native campaign was added.

The first pass found a stale generated `requirements/closure.json` row after
the owner-approved roadmap scope change; regeneration changed only that row
and the requirement check then passed. The advisory check initially could not
lock its database inside the sandbox; the explicitly permitted rerun updated
the database and passed. Other successful checks were not repeated.

This is working-tree preflight, not a clean-commit release-gate result or
independent security review. The existing final gate's unconditional review
guard has not been changed. The current handoff remains candidate commit,
owner retest, commit-bound final checks, exact-commit green GitHub/CodeQL and
separate tag authorization. The broader internal-milestone scheduling policy
is not used here to bypass that guard. No PASS review record has been invented.

Existing [portable acceptance](aes-portable-acceptance.md) and accelerated
records retain their historical populations and limitations. No universal
spill/register erasure, physical protection or arbitrary-build qualification
is implied by consumer success.
