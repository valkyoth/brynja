# Portable AES acceptance (v0.27.2)

Status: completed at signed `v0.27.2` (`56a1b780`). Owner-approved scoped retest,
the thirty finite final checks and exact-candidate GitHub CI/CodeQL passed.
This milestone adds acceptance evidence around the
existing AES-128/192/256 implementation; it does not add an accelerated backend,
mode, protocol or mandatory hardware provider. v0.27.3 remains the planned
x86_64/AArch64 acceleration milestone.

## Package-external consumer slice

Run explicitly from the repository root:

```sh
brynja-verify run aes packaged-portable
brynja-verify show aes packaged-portable
```

The underlying command is `python3 scripts/aes/check-aes-packaged.py`. It needs
installed Rust 1.90.0 and 1.99.1 with `thumbv7em-none-eabi`, but downloads and
publishes nothing. It is a scoped verification registration, not an added
release gate or a requirement to rerun unrelated crypto campaigns.

The runner packages the necessary first-party resolution closure in a private
workspace with an empty Cargo home. It unpacks Cargo's actual `.crate` archives,
rejects unsafe archive members, compares the selected files byte-for-byte with
their source inputs, and prints archive SHA-256 identities. Cargo-generated
metadata is distinguished from original manifest/source bytes. Every package
must contain its README and both license texts.

The external consumer uses exact version requirements patched to these archives,
never checkout dependencies. Both host and Cortex-M metadata graphs must match
the expected package identities, manifest locations and feature sets. Inactive
resolved packages are also constrained to their intended archives. Optional
CPU/platform packages needed for dependency resolution are not admitted into
the active portable consumer graph. Tools and the host remain trusted; this is
not an authenticated or hermetic build attestation.

The existing `assurance/aes-public-api` Rust fixture is copied unchanged:

| Configuration | Evidence |
| --- | --- |
| Direct `brynja-crypto` and facade `brynja`, Rust 1.90.0/1.99.1, debug/release | 18 exact consumer tests each; 144 test executions |
| Both routes and compiler endpoints | 134 paired positive/negative API probes each; 536 pairs |
| Both routes and compiler endpoints | Archived README example executed for all six key-owner types; four runs |
| Both routes and compiler endpoints | Default-on/off AES absence plus nearby HKDF and explicit AES positive controls |
| Both routes and compiler endpoints, `thumbv7em-none-eabi` | Four no_std library compilation checks, not target execution |

The tests cover FIPS 197 public expected outputs, encryption/decryption,
ephemeral/cached keys, caller-buffer canaries, explicit clearing, Drop, reuse,
output lifetimes, public ciphertext persistence and caller unwinds. The paired
compile probes constrain exact key/storage/block widths, borrowing, lifetime
and move rules, thread/format/copy restrictions, and explicit public-output
authority. Each negative must be paired with a successful positive and the
expected compiler diagnostic at the consumer's probe source. An unrelated
dependency error, killed compiler or zero-test run is not a pass.

The README example is extracted from the **archived** `brynja-crypto/README.md`;
the facade run changes only its public import path. It checks all three FIPS
197 Appendix C vectors through both key-owner forms and observes cleanup.
Public test key copies are explicitly outside owner cleanup guarantees.

The runner's fail-closed regression tests are included in the existing registry
test suite. They cover archive-vs-checkout identity, wrong versions/features,
duplicate/missing nodes, workspace isolation, missing/symlinked fixtures,
unchanged fixture bytes, missing README examples, paired diagnostics, failed
positive controls and feature-gate false positives.

The initial observations were collected before the facade version change.
The internal candidate now names 0.27.2, with matching isolated consumer pins
and unchanged supporting-crate versions. Candidate input reconciliation and
the finite final gate remain separate: no v0.27.2 release approval is implied
by an individual green registration. Consult `show` for the actual source
snapshot and execution time, not this document as a live pass record.

## Acceptance configuration boundary and remaining work

The matrix at the end of this document names the acceptance configurations;
it is not a promise to qualify every downstream build. Functional packaged
acceptance covers debug/release and both compiler endpoints. Emitted-code review
covers the named optimized library artifacts and representative opt3/fat-LTO
consumers, with abort/unwind variants on x86_64 and AArch64. Timing retains the
predeclared opt3/fat-LTO/cgu1/overflow/**panic-abort** experiment on the two named
hosts, with both compilers. There is no new panic-unwind timing claim: those
builds have correctness/cleanup observations and bounded machine review only.
No thresholds, sample counts or collected alarms are changed by this clarification.

Other optimizations, architectures, arbitrary consumer inlining, exception-table
dispatch and physical protections remain outside these bounded claims. They
must not be silently described as qualified, but they are not an unbounded list
of additional release tests. The plan asks for representative final-linked
consumers, not a review of every possible downstream executable.

Candidate reconciliation on 2026-11-08:

- The facade/consumer version is 0.27.2. Archive-only acceptance, all four
  AESAVS and four packaged differential configurations, eight feature test/doc
  configurations and four x86_64 final-linked/lifecycle registrations passed
  after that change. Thirty affected functional/API/provider/review registrations
  were refreshed, including the fourteen-compiler consumers and provider
  Miri/ASan. Other scoped dynamic/proof/cleanup observations retain their actual
  input identities; unchanged checks are not reported as new executions.
- New native AWS collection uses a separate candidate source bundle. Both
  compiler endpoints passed correctness/lifecycle checks; all 48 retained
  artifact hashes were checked. Offline review matched 876 current input files
  and rejected all 17,756 mutations using the existing instruction policies.
  The prior collection and its original source/artifact bundles are preserved
  separately. No manifest mismatch was waived or old observation relabeled.
- Both candidate compiler endpoints on each named host completed one fixed/random
  measurement with zero alarms and zero inconclusive contrasts, under unchanged
  predeclared policy. Raw AWS samples reproduced the remote summaries locally.
  Earlier development `timing-screen` / `wide-timing-screen` observations remain
  historical/outdated where their input identities differ; the v0.27.2 acceptance
  experiment is the separate packaged fixed/random screen, not a claim that
  those older diagnostics were rerun.

Remaining before closing the milestone: commit the prepared candidate for the
owner's scoped pentest, test any accepted remediation, then use the existing
finite final gate and exact-commit green GitHub/CodeQL before a signed tag.
The review record is explicitly pending. No new release receipt, certification
requirement or publication campaign is added. A subsequent source change still
requires checking the affected observation identities rather than assuming
that these working-tree passes cover it.

Missing evidence within a declared configuration remains unfinished. Cortex-M compilation
does not qualify that target; passing timing screens cannot establish power/EM
or physical-fault resistance. Rust clearing cannot establish complete erasure
of compiler spills, registers, caller copies, paging or dumps. These deployment
limits remain separate from crate usability and do not impose an HSM.

## Feature composition and scoped dynamic/proof checks

The eight `aes/feature-{msrv,current}-{minimal,all}-{test,doc}` registrations
exercise Rust 1.90.0/1.99.1 with `brynja-crypto` and the `brynja` facade, using
no default features or all features. Test registrations include doctests:
32 passing tests in each minimal configuration and 97 in each all-feature
configuration. Three explicitly opt-in OpenSSL corpus tests are ignored by the
all-feature default test command; their separate differential registrations,
including packaged independent comparisons, cover those corpora. Documentation
registrations build both public crates with dependencies omitted from the
documentation output. These are checkout integration observations, not a
replacement for archive-only acceptance or the paired AES absence/opt-in probes.

The feature checks fingerprint the workspace manifests/lockfile and crate tree,
because all-feature facade composition reaches optional dependencies. This
deliberately broad invalidation applies only to these cheap integration checks,
not the separate timing experiments. No new publication gate is introduced.

On 2026-11-08 the working tree passed refreshed registered AES-128 and wide
vector/KAT sanitizers, internal fault-cleanup sanitizer tests and provider
sanitizers; four Miri registrations cover AES-128 ownership, public ciphertext,
wide ownership and the provider suite. The five field/layout Kani proofs,
x86_64/AArch64 helper reviews, owner dispatch, ordinary/wide operation cleanup
and compiling mutation controls also passed. The proof remains about field
arithmetic and admitted indices, not full AES correctness or constant time.
These observations exercise existing production code; additions in this
milestone are acceptance fixtures/review tooling and documentation. Consult
`brynja-verify show aes ID` for actual scope, dates and current freshness.

## AESAVS Monte Carlo and multiblock slice

The four `aes/avs-{msrv,current}-{direct,facade}` registrations exercise the
pinned NIST ECB MCT/MMT sample files against actual Cargo archives. See
[`assurance/aes-avs/README.md`](../../assurance/aes-avs/README.md) for provenance,
hashes, exact recurrence and raw-block semantics. The API fixture itself remains
unchanged; a separate test target drives the additional campaigns through its
public AES re-export. No production AES code or mode API is added.

Each release-profile configuration covers AES-128/192/256, encryption and
decryption, ephemeral and cached keys: 600 MCT records with 1,000 inner
iterations each (1,200,000 operations including both owners), plus 60 MMT
records containing 330 reference blocks. Both owners also exercise explicit
public encryption for the MMT encryption records. Every generated next key,
next input and final MCT output is compared with the pinned record sequence.

Twelve Rust tests include strict parser rejection, exact iteration counts,
penultimate/final output selection and independent key-update boundary tests.
Eight Python runner regressions enforce fixture hashes, exact test/marker
populations, source binding and fail-closed execution. Those lightweight tests
join the existing registry suite, not a new publication requirement. The full
campaigns remain explicit; consult each registration's recorded freshness for
the current source snapshot.

Passing these samples is correctness evidence, not CAVP validation, a timing
screen, cross-target qualification or evidence of resistance to physical faults.

## Packaged independent differential slice

The four `aes/packaged-diff-{msrv,current}-{direct,facade}` registrations compare
public archive-resolved operations with OpenSSL on Rust 1.90.0 and 1.99.1,
through both direct and facade imports, in debug and release. Run them with
`brynja-verify run aes --needed --category package-differential`. See
[`assurance/aes-differential/README.md`](../../assurance/aes-differential/README.md)
for corpus construction, commands and oracle trust boundaries.

Each profile compares AES-128/192/256 using 64 public synthetic keys per width
and 32 blocks per key in each direction. Decryption consumes independently
generated ciphertext, not only Brynja's encryption output. Both ephemeral and
cached owners exercise secret encryption/decryption and explicit public
encryption. Secret-output Drop clearing and explicit key/schedule clearing are
also checked. There are 36,864 output comparisons per profile, or 294,912 across
the four registrations and two profiles; these are not all distinct inputs.

The runner binds one absolute OpenSSL executable to preflight known-answer
checks and the corpus, records its SHA-256 identity before and after execution,
and rejects ambient loader/configuration overrides. It does not authenticate
the executable or measure its shared-library closure. The host and admitted
oracle remain trusted. No third-party Rust dependency or release gate is added.

Each profile requires exactly four passing Rust tests, no ignored tests, and
all nine comparison markers exactly once. Twelve Python regressions exercise
missing/duplicate markers, malformed test summaries, fixture admission,
compiler/route restrictions, oracle preflight and identity failures, and the
registered execution contract. They join the existing registry suite. Consult
the recorded snapshots for freshness; this correctness comparison is not
timing, machine-code or physical-side-channel qualification.

## Fixed-versus-random timing slice

`aes/packaged-fixed-random-{msrv,current}` builds an archive-only direct public
consumer with Rust 1.90.0/1.99.1, explicit `x86_64-unknown-linux-gnu`, opt-level 3,
fat LTO, one codegen unit, overflow checks and panic abort. The full policy was
written before collection in
[`assurance/aes-fixed-random/README.md`](../../assurance/aes-fixed-random/README.md).
It specifies input generation, class order, timer boundaries, samples, thresholds,
noise limits and failure retention. No old screen was reclassified as this one.

Each compiler run has 39 campaigns covering all widths, ephemeral/cached secret
encrypt/decrypt, explicit public encryption, key/block contrasts and cached
expansion. Each campaign retains 8,192 pairs with four operations per class,
following 256 warmup pairs. Both first-order Welch and paired-difference absolute
t statistics must stay below 4.5; zero class variance or coefficient of variation
above 1.0 is inconclusive. No samples are cropped. These are finite host
observations, not constant-time, higher-order or physical-leakage proofs.

The initial runs on 2026-11-07 both passed on their first measurement, on an AMD
Ryzen 9 9950X3D, microcode `0xb404035`, logical CPU 0, SMT sibling 16, powersave
governor and boost enabled. No CPU isolation or disabled-SMT claim is made.

| Compiler | Completed (UTC) | Maximum absolute Welch / paired t | Maximum class variation | Result |
| --- | --- | --- | --- | --- |
| 1.90.0 | 2026-11-07T12:55:14.920807129Z | 1.810850 / 2.019935 | 0.551547 | 39 campaigns; zero alarms/inconclusive |
| 1.99.1 | 2026-11-07T12:54:33.533934439Z | 2.002132 / 2.132949 | 0.039951 | 39 campaigns; zero alarms/inconclusive |

Executable SHA-256 identities:

- 1.90.0: `fce8e397511a473a264a2ae1b7b5591cc81cd198acab0178fc6374072cd87715`
- 1.99.1: `d92c6a690b214487a38edc0aa7b0683e5382dcc6f30d0ad932e153214c3b605e`

The larger variation in the MSRV observation remains in its raw samples; it was
not trimmed or recollected. Local raw logs are
`verification/.runner/logs/2-1794056088953655295.log` (MSRV) and
`verification/.runner/logs/2-1794056046964780562.log` (current). Their hashes and
scoped before/after snapshots are recorded in `verification/results.json`.
Logs remain local, not large tracked evidence files. Preserve them for review;
the local result index is not authenticated evidence. These dates describe the
initial observations, not a promise that future source edits remain qualified.

Four Rust harness tests pass on both compiler endpoints, and fourteen Python
regressions cover corpus/class separation, exact populations, independently
calculated statistics, synthetic alarm/noise cases, oracle/preflight failures,
timeout output retention, executable changes, affinity restoration and no retries.

## Native AWS AArch64 execution slice

On 2026-11-08, an operator-supplied AWS host reporting two ARM Neoverse-V2 r0p1
cores completed the same archive-only fixed/random fixture on native
`aarch64-unknown-linux-gnu`. No hardware AES backend was enabled. Both compiler
endpoints used opt3/fat-LTO/cgu1/overflow/panic-abort and logical CPU 0.

| Compiler | Completed (UTC) | Maximum absolute Welch / paired t | Maximum class variation | Result |
| --- | --- | --- | --- | --- |
| 1.90.0 | 2026-11-08T08:28:12Z | 2.194697 / 2.155475 | 0.331400 | 39 campaigns; zero alarms/inconclusive |
| 1.99.1 | 2026-11-08T08:29:00Z | 3.047207 / 2.979107 | 0.067563 | 39 campaigns; zero alarms/inconclusive |

Preflight permission failures occurred before any measurements and were retained;
the first actual measurement passed for each compiler. Local reanalysis of every
raw sample reproduced both summaries. This is not a fixed-frequency, isolated
CPU, hostile-hypervisor or physical-leakage qualification.

Separate native linked consumers passed all eight compiler/route/panic
configurations: 144 known-answer operations, 576 normal lifecycle cases and 192
caller unwinds. ELF identities, all eleven portable helper symbols, disassembly
and execution output are retained. These observations do **not** apply the x86
machine policies to ARM or mark the final-linked ARM review complete.

The subsequent offline `aes/aarch64-linked-helpers-review` checks all eleven
portable AES helpers, six surviving secret-output wrappers, copy and zeroizer
in all sixteen retained executables, including expansion and complete transforms
for all three key widths. Instruction
encodings, branch targets, calls and constant-pool bytes are bound to the ELF files;
Six public boundaries and six constructors are additionally reviewed in each of
the eight linked KAT executables. Six focused cleanup bodies in each lifecycle
executable and four ELF-bound unwind imports are also reviewed; 17,756 injected
mutations are rejected overall. See the
[bounded final-linked review](aes-aarch64-linked-review.md). Other inlined
secret entry points, lifecycle constructor copies, arbitrary caller cleanup and
external unwind dispatch remain outside this review. It records uncleared compiler-generated intermediate
spills in AES-192 expansion and Rust 1.99.1 substitution; it does not establish
spill erasure.

See [the native collection record](../../assurance/aes-native-observations/v0.27.2/README.md)
for source/binary identities, raw local artifact locations and the distinction
between direct remote script observations and runner-owned attempts. Registrations
`packaged-fixed-random-arm-{msrv,current}` and `packaged-arm-native-{msrv,current}`
are available for future explicitly requested native runs. Do not repeat the
timing experiment solely to create a local runner receipt.

## AArch64 compile-only emitted-code slice

`aes/aarch64-dataflow-review` checks four library builds for
`aarch64-unknown-linux-gnu`: Rust 1.90.0/1.99.1, release abort/unwind. Eleven
portable LLVM helpers pass the conservative secret-dataflow model. All eleven
emitted assembly bodies also pass operand admission and separately reviewed
instruction fingerprints: inverse, both round-key additions, substitution,
mixing, and expansion/transform for all three key widths. Policies bind local
branch destinations, selected callees, public loop/bounds operands and scratch
clear-call pointers/extents. Six surviving secret-output wrappers additionally
have pinned result/guard/scratch/schedule handling and emitted cleanup bodies.
Seven matching core dependency bodies now cover initialization, guarded output
transfer and clearing, including private copy-register cleanup and the
zeroizer's LLVM volatile store/compiler fence. Six public-output boundaries
also pin success-before-copy ordering, cached schedule admission and temporary
cleanup. Six constructors additionally pin key/schedule admission, guard
ownership transfer, result tags and emitted cleanup paths. All twelve
secret-output API entry points additionally pin direction/argument forwarding
and cached-wide guard admission/transfer. Each configuration rejects 804 unsafe
or unreviewed mutations, 3,216 in total. This does not execute code on AArch64
or qualify arbitrary consumer inlining or other API/lifecycle bodies,
exception-table/runtime unwind dispatch or final-linked binaries.
Rust 1.99.1 AES-192 expansion has an observed key-derived stack spill outside
the explicitly cleared scratch word; no whole-frame erasure is claimed.
See [the bounded review](aes-aarch64-review.md) for reproducible settings,
dataflow observations, fingerprint policy and explicit exclusions.

## Qualification boundaries still open

The additional `aes/packaged-linked-msrv` and `aes/packaged-linked-current`
checks inspect and execute eight actual x86_64 fat-LTO binaries: both compiler
endpoints, direct/facade imports and abort/unwind. They check 18 known-answer
operations per binary, output/key-storage clearing, the eleven-helper symbol
population, and all eleven portable AES helper bodies, six surviving secret
wrappers, six explicit public consumer boundaries, six constructors and core
copy/zeroizer instruction text/encoding with 256 negative
mutations per binary. Mixing, substitution
and transforms bind loaded ELF constant-pool bytes; direct calls must target
the exact independently checked helper entries. This includes expansion and
transform loop bounds, temporary scratch clearing and surviving secret-wrapper
normal/error cleanup, plus the public boundaries' construction, success-guarded
output publication and explicit owner clearing. It does **not** cover other
inlined caller paths or unwind dispatch. The decoded inverse still spills secret
intermediates. See [the final-link scope](aes-linked-review.md).

Separate `aes/packaged-lifecycle-msrv` and `aes/packaged-lifecycle-current`
registrations exercise the final-linked public owner lifecycle: 576 normal
cases, 192 actual caller unwinds and eight panic-harness negative controls
across the same compiler/route/panic matrix. They cover all six key owners,
both secret directions, explicit clear/Drop, surviving-key reuse, output
outliving its key and public ciphertext persistence, with buffer canaries.
Six explicit consumer cleanup bodies and their zeroizer are also reviewed per
binary, including emitted unwind landing pads and the resume import binding;
552 machine mutations are rejected across the eight binaries. They do not
inject faults inside production AES, observe internal scratch, or qualify
other callers, exception tables or the runtime unwinder.

| Configuration | Evidence currently available | Outside this observation / residual limits |
| --- | --- | --- |
| x86_64, 1.90.0/1.99.1, opt3/fat-LTO/abort | Packaged fixed/random observations above; final executable identity recorded | Other timing profiles; timing alone does not perform machine review |
| x86_64, 1.90.0/1.99.1, opt3/fat-LTO, abort/unwind, direct/facade | Packaged known-answer/clearing observations; eleven portable helpers, six surviving secret wrappers, six public boundaries, six constructors and core copy/zeroizer instruction review with constant/call binding; separate caller-unwind lifecycle observations and six focused cleanup-body/landing-pad reviews | Other inlined caller paths and exception-table/runtime unwind dispatch; spill erasure is not established |
| x86_64, 1.90.0/1.99.1, optimized abort/unwind library artifacts | Existing helper dataflow, instruction-stream and delegated clearing checks described in the AES development documents | Other optimizations; final-link transformations are reviewed separately above; library artifacts are not whole-application qualification |
| Native AWS AArch64 GNU/Linux, 1.90.0/1.99.1, opt3/fat-LTO | Fixed/random observations for panic-abort; direct/facade KAT and lifecycle executions for abort/unwind; eleven AES helpers, six secret wrappers, copy and zeroizer reviewed in sixteen retained final-linked ELF files; six public boundaries and six constructors in eight KAT ELFs; six caller cleanup bodies in eight lifecycle ELFs and four bound resume imports | Other secret entry points, lifecycle constructor copies, arbitrary caller cleanup and external unwind dispatch; other profiles; no spill-erasure, hardware acceleration or physical qualification |
| AArch64, 1.90.0/1.99.1, optimized abort/unwind library artifacts | Compile-only LLVM model and reviewed assembly for eleven helpers, six surviving secret-output wrappers, six public-output boundaries, six constructors, twelve secret-output entry points and seven matched core initialization/transfer/clearing bodies; zeroizer LLVM policy | Arbitrary consumer inlining/other API and lifecycle bodies, exception tables/runtime unwind dispatch; final-linked review and native execution are recorded separately above, not inferred from these artifacts; observed compiler spill is not erased by the scratch clear |

No accelerated backend work or v0.27.2 completion is claimed before final
candidate preparation and its scoped checks/review. The crate remains usable
under its documented software threat model; the residual deployment limits
do not create a mandatory HSM requirement.
