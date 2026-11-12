# AES x86_64 / AArch64 acceleration development (v0.27.3)

Status: in progress, not release-ready. The predecessor portable acceptance
closed with signed `v0.27.2` at `56a1b7805c9517fbdb5e3c28b137ea8c9108cf7e`.
The frozen portable consumers and existing key-owner APIs remain unchanged.
The release metadata still identifies the last completed milestone until the
new candidate is prepared; this document is not a release approval.

## Explicit static implementation slice

This section records the initial round-only slice. The later hardware-assisted
expansion integration section below supersedes its portable-expansion route.

`crates/brynja-crypto-cpu/src/aes/{x86,aarch64}.rs` contain private, isolated
round kernels for AES-128/192/256 encryption and decryption. The default-off
`aes-static-execution` feature now links them through sealed static admission
and explicit clearing owners in `brynja_crypto::aes::execution`, with feature
forwarding through `brynja`. Existing portable constructors remain portable.
There is no automatic dispatch. Private unsafe primitives are not application APIs.

- x86 uses AES-NI with the exact AES/SSE2 bundle, not VAES/AVX.
- Little-endian AArch64 uses the exact NEON/AES bundle.
- Forward schedules have exactly 11, 13 or 15 round keys. Both directions
  accept that layout; decrypt inverse-mixes middle keys in registers without
  modifying or retaining another schedule. Key expansion in the harness is
  test-only, not a production key API or cleanup implementation.
- The round bodies are opaque assembly boundaries, use unaligned accesses,
  and clear their working vector registers before return. They contain no
  calls or stack accesses. These source properties are **not** final-linked
  emitted-code qualification, whole-program spill erasure or fault resistance.
- Private unsafe entry points require a stable ISA bundle on every eligible
  CPU throughout the operation. The test harness checks the host features
  before entering. Static admission requires the matching compile-time target
  feature bundle; deployments must guarantee that bundle on every eligible CPU.
  It is not a runtime CPU-affinity or migration guarantee.

`execution::Authority::new` checks the compiled bundle before running startup
KATs for all three widths and both directions. Borrowed sessions bind operations
to that authority and its generation. Testing, quarantined and stale sessions
cannot execute; an incomplete selected operation revokes the authority without
falling back to portable execution. This is local lifecycle enforcement, not
physical fault detection or module certification.

The explicit `execution::Aes{128,192,256}Key` owners expand a temporary schedule
per operation; `execution::Aes{128,192,256}ExpandedKey` retain a caller-owned,
clearing schedule. At this initial stage both used portable fixed-work expansion and
the selected hardware rounds. Secret destinations are guarded and cleared on
failure, and public ciphertext is staged until success. Key and schedule owners
remain thread-bound and clear on explicit clearing or drop. Hardware key
expansion and performance qualification were not claimed by this initial slice.

The different round/key ordering follows the AES-NI and Arm AES instruction
contracts ([Rust/Intel AESDEC](https://doc.rust-lang.org/core/arch/x86_64/fn._mm_aesdec_si128.html),
[Rust/Arm AESE](https://doc.rust-lang.org/core/arch/aarch64/fn.vaeseq_u8.html)).
NIST expected ciphertext/plaintext, not round trips alone, checks that ordering.

## Explicit correctness checks

```sh
brynja-verify run aes --needed --category kernel-candidate
```

Four configurations cover Rust 1.90.0/1.99.1 on native x86 and AArch64 QEMU.
The native x86 checker requires AES-NI; lack of the instruction fails rather
than skipping tests. QEMU runs are visibly emulation, not AWS/Apple native
qualification. The underlying commands are:

```sh
python3 scripts/aes/check-aes-kernel-candidate.py --toolchain 1.90.0
python3 scripts/aes/check-aes-kernel-candidate.py --toolchain 1.99.1
python3 scripts/aes/check-aes-kernel-candidate.py --toolchain 1.90.0 --qemu-aarch64
python3 scripts/aes/check-aes-kernel-candidate.py --toolchain 1.99.1 --qemu-aarch64
```

Each executes all 2,078 checked-in NIST single-block KAT records: 568 AES-128,
700 AES-192 and 810 AES-256, with exact per-file populations and both directions.
The opposite direction is then exercised without rebuilding the schedule.
Another 768 cases cover every pairing of byte alignments for the state and
schedule at all three widths, with output canaries and immutable-schedule
checks. Parser tests reject malformed, incomplete or substituted populations.
Paired no_std compile controls instantiate all three supported schedule widths
and require an invalid ten-round-key instantiation to fail at the exact constant
assertion, not from a missing compiler or target.
The runner requires all completion markers and exactly five passing tests,
with zero failed/ignored tests. Binaries and execution logs are retained under
`target/aes-kernel-candidate`; neither those logs nor the verifier index are
authenticated execution receipts. No dependencies, tests or targets download
implicitly. These entries are independent of the finite release gate.

Initial development runs on 2026-11-09 passed both compiler endpoints on the
AMD Ryzen 9 9950X3D host and in AArch64 QEMU. Hiding AES in x86 QEMU rejected
execution before the kernel. See verifier observations for current fingerprints;
this prose is not a live pass record. No new timing campaign was performed.

### Static admission and owner integration

```sh
brynja-verify run aes --needed --category aes-static
```

Six local configurations cover both compiler endpoints with native x86,
AES-disabled baseline, and explicitly emulated AArch64. The baseline requires
seven passing control tests and does not count as an accelerated execution.
Native/emulated configurations require 23 passing tests: eight authority and
admission tests, thirteen owner tests, and two exhaustive expansion error/unwind
tests. The owner tests replay all 2,078 NIST records through both owner forms,
with exact completion markers. Failed or ignored tests cannot satisfy the runner.
The native runner executes a baseline ISA probe before target-specialized code.
The no_std facade also compiles for Cortex-M on Rust 1.90.0; this does not admit
an unsupported hardware route.

On 2026-11-09 the same static runner passed natively on Apple M2 Pro, macOS
27.0.1, with Rust 1.90.0 and 1.99.1. See the bounded
[development observation](../../assurance/aes-native-observations/v0.27.3/apple-static-development.json)
for source archive and retained log hashes. This observation is from an
uncommitted development tree, not final candidate qualification or a local Linux
verifier pass. It establishes neither final-linked/LTO review nor timing,
spill-erasure, physical side-channel or fault resistance.

## Explicit hosted selection

`aes-runtime-execution` is default-off in the CPU leaf, crypto layer and facade.
It does not add std or a detector to the facade. Applications separately opt into
`brynja-crypto-cpu-std` with the same feature and use `aes::Authority` there.
`Portable` does not probe; `Prefer` can select portable only for pre-execution
unavailability; `Require` returns that unavailability as an error. After admission,
startup failures retain a quarantined hardware owner and never select portable.
`kernel_authority()` returns a checked borrow for the explicit clearing owners;
no key copying, owned-authority extraction, report conversion or reset is added.

This slice admits the reviewed Linux/macOS little-endian AArch64 system feature
interfaces. Generic x86 observes AES/SSE2 but reports a missing migration guarantee;
CPUID alone does not prove the lifetime-long all-eligible-CPU contract. Other
hosted platforms remain unavailable pending their AES-specific review. Explicit
static selection remains available for compatible target-specialized deployments.
The low-level `Authority::from_platform` is an unsafe integration boundary, not a
safe feature-mask constructor. Static `Authority::new` still requires the complete
compiled bundle even when the runtime feature is enabled.

The system ABI assumptions follow the existing
[hosted CPU contract](../hosted-cpu-execution.md). Rust 1.90.0's local detector
sources were inspected: Linux uses HWCAP, and Darwin queries `FEAT_AES`,
`FEAT_PMULL` and `AdvSIMD` through system sysctl. The adapter uses Rust's complete
`aes`/`neon` feature predicates rather than reimplementing those feature groups.
Linux explicitly requires checking the relevant
[HWCAP flags](https://docs.kernel.org/arch/arm64/elf_hwcaps.html) before using an
instruction feature. A conforming OS/hypervisor must preserve its advertised
process ISA ABI across scheduling, hotplug and migration. Thread-bound ownership
and successful startup tests are not themselves migration protection.

```sh
brynja-verify run aes --needed --category aes-hosted
python3 scripts/aes/check-aes-execution-api.py 1.90.0
python3 scripts/aes/check-aes-execution-api.py 1.99.1
```

Hosted tests build with global AES disabled and exercise detection plus isolated
target-feature kernels. Each compiler runs five selector/lifecycle tests and a
downstream debug/release consumer. Native x86 must report unavailability; AArch64
QEMU must execute all 2,078 KAT records through both owner forms and demonstrate
quarantine, secret clearing and unchanged public output on rejection. Exact
markers prevent unsupported execution from being counted as accelerated coverage.
The paired compiler probes check all six owners' thread/clone/copy restrictions,
storage and authority borrows, unsafe platform admission, feature isolation and
hosted-owner lifetime. They compile positive controls and require the intended
diagnostic for each negative case; they do not execute the probe programs.

The baseline-compiled hosted tests also passed on native Apple M2 Pro in debug
and release with both compiler endpoints; see the
[hosted development observation](../../assurance/aes-native-observations/v0.27.3/apple-hosted-development.json).
The earlier static observation remains historical for its archived source, not
fresh evidence for the changed admission layer. Neither observation closes the
full native or final-linked qualification milestone.

## Forced-backend packaged campaigns

```sh
brynja-verify run aes --needed --category aes-campaign
```

Sixteen local configurations exercise both compiler endpoints and both the
direct crypto and facade routes. Native x86 static admission runs AESAVS and
independent OpenSSL comparisons; emulated AArch64 runs AESAVS through both static
and baseline-compiled hosted admission. QEMU is never counted as native evidence.

The runner builds byte-checked Cargo archives in an isolated, offline workspace
and checks the exact active dependency and feature graph. Its test-only adapter
exports accelerated owners only and requires a healthy selected authority;
hosted admission uses `Require`, never `Prefer`. Every constructor borrows that
authority. The existing portable campaign sources remain unchanged: generated
copies change only the import, authority creation and constructor arguments,
with exact anchor counts and reversible-adaptation regression tests.

Each AESAVS configuration checks 600 Monte Carlo records (1.2 million block
operations) and 60 multi-block records across all three widths and both owner
forms. Each OpenSSL configuration runs debug and release, each with 12,288
independent input/direction cases through both owners, plus public-output checks.
The oracle is preflighted against published vectors and its executable hash is
checked before and after; this does not authenticate OpenSSL or measure its shared
libraries. Exact test names/counts, population markers and selected-authority
markers reject skipped, missing, duplicated or wrong-backend execution. Logs and
metadata remain under `target/aes-accelerated-campaigns`; disposable builds are
removed. These are correctness observations, not timing or final-linked evidence.

On 2026-11-09 all sixteen local configurations passed. See the verifier for their
current fingerprints; this dated prose is not a live freshness assertion. Seven
new runner regression tests cover adaptation, feature/source graph drift,
injected configuration and incorrect completion populations.
An intentional hosted/native request on the AMD host failed with
`MissingMigrationGuarantee` before any accelerated campaign operations, emitting
no pass marker. This is a negative admission control, not accelerated coverage.

The same runner passed sixteen additional configurations natively on Apple M2
Pro: both compiler endpoints, both API routes, static/hosted admission and both
campaign suites. See the [native campaign development observation](../../assurance/aes-native-observations/v0.27.3/apple-campaigns-development.json)
for the source archive, exact commands, populations, OpenSSL executable identity
and retained log hashes. The shared `/tmp` preflight refusal is preserved; the
unchanged source ran in a private builder-owned directory instead. This is still
uncommitted development-source evidence, not AWS coverage or final qualification.

## Bounded final-linked kernel review

```sh
brynja-verify run aes --needed --category aes-linked-kernel
```

On 2026-11-09 all six configurations passed: both compiler endpoints with
native x86 static admission and emulated AArch64 static/hosted admission.
Each builds four byte-checked package-external consumers (direct/facade,
abort/unwind) with opt3, fat LTO, one codegen unit and overflow checks, for
24 executed and inspected binaries. Both owner forms pass known answers,
clearing and quarantine checks. Exact executable-byte and instruction checks
cover all three complete round-kernel bodies, including their prologues and
register clearing; each binary also rejects 465 x86 or 570 ARM mutations.
The nine new regression tests pass within the 600-test registry suite.

See the [bounded kernel review](aes-accelerated-linked-kernels.md) for the
instruction-level rationale, artifact locations and limitations. This does not
close the surrounding caller/dispatch/expansion/cleanup review, native ARM
qualification or timing assessment. Capture-only runs cannot produce a pass.

### Cached public-encryption callers on x86

```sh
brynja-verify run aes --needed --category aes-linked-public
```

On 2026-11-09 both compiler configurations passed across eight freshly linked
native x86 consumers (direct/facade, abort/unwind). The bounded review now
covers the complete cached public-encryption wrappers for all three widths:
authority and schedule-bound checks, private staging, matching kernel calls,
publication and volatile staging cleanup. It includes the emitted 1.90.0 unwind
landing pad and binds its resume import, without claiming exception-table
dispatch qualification. The 1.99.1 streams omit that landing pad and have their
own pinned policies. Seven new regression tests pass within 607 registry tests.

See the [cached public caller review](aes-accelerated-linked-public.md) for
instruction-level reasoning and negative controls. Secret-output callers have
their separate bounded review below. Constructors, ephemeral operations,
ARM callers and native timing remain unfinished;
this is not a whole-consumer pass or an erasure guarantee.

### Cached secret-output callers on x86

```sh
brynja-verify run aes --needed --category aes-linked-secret
```

On 2026-11-09 both compiler configurations passed across eight freshly linked
native x86 consumers (direct/facade, abort/unwind). Complete cached secret-output
wrappers for all three widths bind authority and schedule bounds, the public
encrypt/decrypt selector, private staging, copying into the admitted destination,
staging cleanup and successful secret-owner pointer/length/discriminant fields.
Rejected cached encryption and decryption both clear a prefilled destination in
the executable fixture. The newer compiler's clearing tail jump is bound to the
exact volatile helper; other shared-observer users still reject external jumps.

The [cached secret caller review](aes-accelerated-linked-secret.md) records the
compiler-specific normal, error and emitted unwind paths and their limitations.
Every consumer rejects 903/1299 (1.90.0 abort/unwind) or 969 (1.99.1) individual
wrapper mutations, plus eight copy-helper and three clearing-helper controls.
Seven new caller tests and one tail-edge observer test bring the passing registry
suite to 615 tests. This remains a bounded caller review, not qualification of
constructors, ephemeral operations, returned-owner destruction, exception-table
dispatch, ARM callers or native timing.

### Per-operation secret-output callers and expansion on x86

```sh
brynja-verify run aes --needed --category aes-linked-ephemeral
```

On 2026-11-09 both compiler configurations passed across eight newly linked
native x86 consumers (direct/facade, abort/unwind). The review covers the
complete secret-output wrappers of all three operation-local key owners:
initial admission, temporary schedule initialization, matching expansion,
post-expansion authority rechecks, encrypt/decrypt selection, copying to the
returned owner, and staging/schedule/destination cleanup. The portable expansion
and scalar inverse still match their existing reviewed policies; they are
validated in each accelerated executable rather than assumed from source reuse.
The cached secret-output review is also replayed in each executable.

The shared fixture now tests rejected per-operation decryption and rejected
construction for both owner forms after quarantine, requiring prefilled storage
to become zero. These constructor observations are behavioral coverage; their
inlined machine code is not included in this bounded review. The
[per-operation caller note](aes-accelerated-linked-ephemeral.md) records the
exact streams and limitations. Per executable, 2040/2430 (1.90.0 abort/unwind)
or 2172/2088 (1.99.1 abort/unwind) wrapper mutations are rejected, in addition
to the expansion, inverse, cached-caller and kernel controls. Seven new unit
tests pass within the 622-test registry suite.

The public-output slice is recorded separately below. Inlined constructors,
destructor entry points, ARM callers, dispatch qualification and native timing
remain unfinished.
This step changes test/tooling coverage, not production AES code or release gates.

### Per-operation public-output callers on x86

```sh
brynja-verify run aes --needed --category aes-linked-ephemeral-public
```

The next bounded slice retains package-external `public128/192/256` operation
boundaries without changing production inlining. It reviews the complete
inlined public-encryption operation: initial admission, full temporary schedule
initialization, matching expansion, post-expansion rechecks, hardware encryption,
publication only on success and clearing. Both public-output owner forms are
executed after quarantine and must preserve a prefilled caller destination.

The [public per-operation note](aes-accelerated-linked-ephemeral-public.md)
records the compiler-specific normal/error paths and emitted 1.90.0 unwind pad.
Each executable must reject 1455/1731 (1.90.0 abort/unwind) or 1599/1458
(1.99.1 abort/unwind) new wrapper mutations. Previously pinned cached public,
cached/ephemeral secret, expansion/inverse and helper policies are replayed in
the same executable, not refreshed. Eight new tooling regressions cover symbol
population, exact dependency binding, fail-closed mode selection and registry
scope. This does not qualify arbitrary downstream inlining, constructors,
destructors, ARM callers or native timing.

On 2026-11-09 both registered configurations passed across eight freshly linked
native x86 consumers. All 630 verification-registry tests passed, including the
eight new regressions. The updated shared executable also passed all six
linked-kernel configurations (24 consumers: native x86 and QEMU AArch64,
static/hosted where admitted). These emulated ARM runs are regression checks,
not native platform or ARM caller-body qualification. Formatting, documentation
links, release-plan checks and 4582 roadmap regressions passed. No production
AES code or release-gate policy changed in this step.

### X86 lifecycle follow-up

```sh
brynja-verify run aes --needed --category aes-linked-lifecycle
```

The [constructor/destruction review](aes-accelerated-linked-lifecycle.md)
adds exact policies for all six package-external constructors and the two
destruction bodies retained by LTO. It binds destination clearing before
admission, authority/generation retention, exact-width key copying, cached
expansion and temporary cleanup. The destruction bodies preserve the owned
pointer/length and branch only to the reviewed volatile clear helper. Both
explicit clear and ordinary Drop are exercised for all key-owner types and
secret output. The merged bodies do not imply a proof of every fixture call
site or arbitrary downstream inlining. The entire previous x86 operation and
expansion review is replayed; ARM lifecycle and native qualification remain
separate work. This step changes fixtures/tooling, not production AES.

On 2026-11-09 both registered lifecycle checks passed across eight fresh
direct/facade, abort/unwind builds on Rust 1.90.0 and 1.99.1. Each build also
replayed the preceding x86 operation review. The lifecycle reviewer rejected
1835 instruction/byte mutations per build, or 1873 for Rust 1.99.1 unwind.
The shared fixture was then rechecked through all six registered kernel
configurations: 24 consumer builds across native x86 and emulated AArch64
static/hosted admission passed. Emulation does not establish native ARM
qualification. All 640 registry tests (including ten lifecycle regressions),
formatting, documentation links, release-plan checks and 4582 roadmap
regressions passed. These results do not refresh unrelated verification
attempts or close the remaining v0.27.3 work below.

### AArch64 clearing and destruction follow-up

```sh
brynja-verify run aes --needed --category aes-linked-arm-cleanup
```

The [ARM cleanup review](aes-accelerated-linked-arm-cleanup.md) adds exact
instruction-word templates for the complete volatile-clear helper and the two
destruction bodies retained after LTO merging. It binds both branch encodings
and annotations to the actual clear implementation and preserves the existing
round-kernel review. The shared fixture exercises all six key-owner clear/Drop
routes and returned secret-block clearing. The four registered configurations
cover both compilers and static/hosted admission, each with direct/facade and
abort/unwind consumers. These are emulated AArch64 ELF builds, not native CPU
qualification. ARM constructors, operation callers and broader native work
remain separate; no every-call-site or spill/register-erasure claim is added.

On 2026-11-09 all four registered configurations passed across sixteen fresh
emulated builds. Together they rejected 1040 cleanup instruction/byte mutations
and 9120 kernel mutations. Both x86 lifecycle registrations were then replayed:
eight fresh native consumers passed the unchanged constructor, destruction and
operation policies through the modified shared runner. All 650 registry tests,
formatting, documentation links, release-plan validation, 4582 roadmap
regressions and diff-integrity checks passed. No production Rust, fixture,
dependency, timing threshold or release-gate policy changed in this step.

### AArch64 constructor follow-up

```sh
brynja-verify run aes --needed --category aes-linked-arm-constructors
```

The [ARM constructor review](aes-accelerated-linked-arm-constructors.md) adds
whole-body policies for all six raw/cached constructors and the complete copy
helper. It binds initial destination clearing, authority/generation retention,
exact-width copying, cached expansion and failure quarantine/cleanup. It
replays unchanged portable inverse/expansion policies and the ARM cleanup and
round-kernel review. External clearing tail branches are explicitly admitted
and bound to the actual helper; the shared observer's default remains closed.
Four registered compiler/admission configurations each build direct/facade and
abort/unwind emulated consumers. Operation callers, broader native evidence,
arbitrary inlining, exception-table dispatch and spill erasure are not claimed.

On 2026-11-09 all four constructor registrations passed across sixteen fresh
emulated consumers, rejecting 32280 constructor/copy mutations and 672 portable
expansion/inverse controls, alongside the replayed cleanup/kernel controls.
Both x86 lifecycle registrations also passed across eight fresh native
consumers through the modified shared runner. All 661 registry tests,
formatting, documentation links and release-plan checks passed, including
4582 roadmap regressions. A separate historical-artifact regression matched
192 helper bodies in sixteen retained v0.27.2 ARM binaries and rejected 1968
mutations using the changed observer. That replay is tooling regression
coverage only: it is neither current-source qualification nor a fresh native
execution. No production Rust, fixture, dependency, timing policy or release
gate changed in this step.

### AArch64 cached operation callers

```sh
brynja-verify run aes --needed --category aes-linked-arm-cached
```

The [ARM cached caller review](aes-accelerated-linked-arm-cached.md) covers
three public-encryption and three shared secret encrypt/decrypt bodies. It
binds health/generation/bundle/schedule checks, matched-width kernel dispatch,
staged output, returned secret-owner fields, clearing and failure quarantine.
The older compiler's unwind paths are separately pinned, including their
trusted runtime boundary, without claiming exception-table or unwinder proof.
Every check replays the constructor, expansion, copy, cleanup and kernel
closure. Per-operation-key callers are covered by the next slice below;
native qualification remains unfinished.

On 2026-11-09 all four cached-caller registrations passed across sixteen fresh
emulated consumers. They rejected 35910 caller instruction/byte mutations and
736 trusted-runtime byte mutations, in addition to replaying the existing
constructor and dependency controls. Both x86 lifecycle registrations passed
across eight fresh native consumers through the modified shared runner. All
671 registry tests, formatting, documentation links, diff-integrity and
release-plan checks passed, including 4582 roadmap regressions. These results
do not refresh unrelated registrations or establish native ARM qualification.
No production crypto, dependency, fixture, timing threshold or release gate
changed in this step.

### AArch64 per-operation callers

```sh
brynja-verify run aes --needed --category aes-linked-arm-ephemeral
```

The [ARM per-operation caller review](aes-accelerated-linked-arm-ephemeral.md)
binds six public/secret bodies, temporary schedules of 176/208/240 bytes,
matched-width expansion and kernels, post-expansion admission rechecks,
staged output, clearing and quarantine. Complete streams were inspected for
both compiler endpoints, both admission routes and both panic profiles before
pinning 48 policies. Every check replays the cached caller and full dependency
closure. The retained older-compiler unwind boundary remains explicitly trusted,
not an exception-dispatch or unwinder qualification.

This step changes verification tooling and documentation only, not production
crypto, dependencies, fixtures, timing thresholds or release gates. Fresh
registered observations are recorded independently by `brynja-verify`.

On 2026-11-09 all four per-operation registrations passed across sixteen fresh
emulated consumers. They rejected 69480 per-operation caller instruction/byte
mutations, replayed 35910 cached-caller mutations and 736 runtime-byte mutations,
and repeated the constructor/expansion/copy/cleanup/kernel controls. Both x86
lifecycle registrations also passed across eight fresh native consumers through
the shared runner. All 681 registry/tooling tests passed, as did formatting,
documentation links, diff-integrity and release-plan checks, including 4582
roadmap regressions. These observations do not refresh unrelated registrations
or establish native ARM qualification.

## Unchanged portable package replay

The frozen `assurance/aes-public-api` consumer remains byte-for-byte unchanged
from v0.27.2. On 2026-11-09 `brynja-verify run aes packaged-portable` passed
against the current development archives: eight direct/facade host
configurations on both compiler endpoints in debug/release, 18 lifecycle/API
tests per configuration, 536 paired compiler probes, four archived README
executions, four default-off feature checks and four no_std Cortex-M compile
checks. The active portable graphs remained exact, with no acceleration enabled.
This preserves portable compatibility; it does not substitute for accelerated
owner lifecycle qualification or native side-channel evidence.

## Packaged accelerated sanitizer lifecycle

The [accelerated sanitizer check](aes-accelerated-sanitizers.md) reuses the
archived public lifecycle tests through direct and facade imports, on the
pinned sanitizer nightly and native x86 AES-NI. Each debug/release profile
requires two deliberately failing sanitizer controls before its thirteen
positive tests: a diagnosed one-byte heap overread and a 64-byte leak. The
runner pins test names/counts, vector markers, archive-only graphs and fatal
sanitizer options. Control failures are expected and separately labeled;
sanitizer diagnostics from AES tests always fail acceptance.

```sh
brynja-verify run aes --needed --category aes-accelerated-sanitizers
```

The control binary is test-only and never enters published library crates.
No production crypto, fixture assertions, dependency, timing threshold or
release gate changes in this step. Installed std is not rebuilt; this does not
qualify every memory access, native ARM, timing, physical faults or spill erasure.

On 2026-11-09 both registrations passed: four fresh archive-consumer profile/route
combinations, 52 lifecycle test executions and eight deliberately failing
ASan/LSan controls. The initial development control run correctly detected the
overread but exposed conflicting sanitizer exit-code expectations in the harness;
both options now explicitly use exit code 23, with regression coverage. This was
a harness correction, not an AES failure or a timing rerun. All 693 registry and
tooling tests passed, including twelve new sanitizer-runner regressions. Rust
formatting (including the standalone control), documentation links, release-plan
validation and diff-integrity checks passed. Unrelated observations were not
refreshed and no native ARM host was used.

## Packaged accelerated no_std and feature isolation

The [no_std acceptance runner](aes-accelerated-no-std.md) adds archive-only
direct/facade library builds for static and low-level runtime features, in
debug/release on both compiler endpoints. It covers bare-metal Cortex-M,
Linux x86 AES-NI and AArch64 musl AES/NEON, plus paired ownership/admission and
feature-isolation diagnostics. Hosted adapters remain outside these graphs.
This is compile-only coverage, not native execution or final executable linking.

An initial bare-metal x86 Rust 1.90.0 build hit an LLVM failure; its diagnostics
are retained and the target remains unsupported by this campaign. No soft-float
ABI override, production change or relaxed test was used. The named Linux x86
library build is a different target and does not resolve that limitation.

```sh
brynja-verify run aes --needed --category aes-accelerated-no-std
```

On 2026-11-09 all four registered configurations passed: 48 library builds and
212 positive/negative compiler pairs across the two compiler endpoints and API
routes. All 704 registry/tooling tests passed, including eleven new runner
regressions. Workspace/fixture formatting, documentation links, release-plan
validation and diff-integrity checks passed. No production sources were changed
in this step, no remote ARM host was used and unrelated verification observations
were not refreshed.

## Separating setup cost from hardware-round performance

The [performance diagnostic](aes-accelerated-performance.md) compares the
existing portable/accelerated raw and cached owners at every key width. It
separates construction/clearing from block operations, excludes authority
startup from timings, retains all samples and declares the initial local
compiler/profile/sample population before measuring. It does not change
production expansion, set a speed gate or replace fixed-versus-random testing.
Four registrations validate fixture correctness without collecting timings;
measurement requires an explicitly named, non-overwriting observation.

On 2026-11-09 all four fixture registrations passed, with sixteen Rust test
executions and 192 case checks across the compiler/API configurations. All
715 registry/tooling tests passed, including eleven new performance-runner
regressions. Workspace/fixture formatting, links, release-plan validation and
diff-integrity checks passed. The two predeclared measurements then ran
sequentially on the local AMD Ryzen 9 9950X3D, without concurrent agent-launched
verification campaigns; all 864 samples were retained and neither observation
was retried. Full raw output, summaries, archive/binary identity and selected
host context are retained in the [MSRV observation](../../assurance/aes-native-observations/v0.27.3/local-x86-msrv-20261109.json)
and [current observation](../../assurance/aes-native-observations/v0.27.3/local-x86-current-20261109.json).

Median secret-encryption cost in nanoseconds per operation, for these exact
public fixtures and profiles (not a speed guarantee):

| Compiler | Key bits | Portable raw | Accelerated raw | Portable cached | Accelerated cached |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1.90.0 | 128 | 6736.0 | 1424.4 | 5307.3 | 11.7 |
| 1.90.0 | 192 | 7508.5 | 1191.8 | 6311.7 | 12.4 |
| 1.90.0 | 256 | 9222.5 | 1772.1 | 7425.2 | 13.1 |
| 1.99.1 | 128 | 7019.2 | 1463.9 | 5648.9 | 12.0 |
| 1.99.1 | 192 | 8069.7 | 1215.4 | 6858.2 | 12.5 |
| 1.99.1 | 256 | 9939.5 | 1903.6 | 7976.3 | 13.3 |

Cached construction/clearing costs remain similar between the two backends:
roughly 1.2–2.0 microseconds, depending on key width/compiler. Together with
the source-level use of the same portable expansion, this supports prioritizing
backend-assisted expansion next. It does not isolate expansion from every other
setup cost, qualify the tiny cached timings statistically, or close native
side-channel work. No production sources or remote hosts were changed here.

### Isolated hardware-assisted expansion candidates

The next slice adds private x86 AESKEYGENASSIST and little-endian AArch64 AESE
expansion candidates for all three key widths. They are deliberately absent
from the production module tree: public accelerated owners still expand with
the portable implementation. The separate
[candidate acceptance](aes-expansion-candidates.md) compares every schedule
byte for 2,078 NIST cases and 774 generated keys, checks 768 key/output
alignments and canaries, and compiles three valid/five invalid no_std shapes.
Four registered compiler/architecture configurations distinguish native x86
from emulated ARM. This is not admission, lifecycle, emitted-code, timing or
native ARM qualification. No new measurements were taken for this slice.

### Hardware-assisted expansion admission and owners

Following the isolated candidate slice above, the explicit accelerated owners
now use the hardware expansion kernels. Portable constructors are unchanged.
Session expansion performs the same sealed admission and generation/health
checks as round execution. Startup independently compares complete generated
schedules with fixed expected bytes; tests reject all 624 one-byte schedule
mutations. The four owner regression tests cover both error/unwind boundaries,
post-expansion revocation and cached reuse without re-expansion. Assembly is
opaque and non-unwinding; this does not claim instruction-level fault injection.
Static registrations now require 26 tests for supported ISA configurations;
baseline rejection still requires seven. Compiler acceptance adds nine paired
width/aliasing probes per API route. See the updated
[expansion acceptance](aes-expansion-candidates.md).

Previous linked-code results and native observations describe the earlier
portable-expansion implementation. They cannot qualify the replacement; scoped
fingerprints become stale, and strict old machine-code policies must be reviewed
before accepting changed code. No timing or performance measurements were
repeated as part of integration.

Integration verification on 2026-11-09:

- Six registered static configurations passed (118 Rust test executions), plus
  all four hosted and four isolated expansion configurations.
- Both checkout API compiler runs passed 127 paired probes each. Packaged
  no_std acceptance passed all 48 builds and 248 paired probes across both
  compilers and direct/facade routes.
- All 16 packaged accelerated AVS/OpenSSL configurations passed, and both
  sanitizer route registrations passed (52 lifecycle test executions plus the
  existing eight deliberately failing bounds/leak controls).
- All 726 registry/tooling tests passed. Both affected crates' all-feature test
  suites passed with their existing explicitly ignored optional campaigns;
  ignored cases are not execution evidence. The portable AES unit/fault suite
  also passed separately.
- Strict Rust 1.90 AES-feature Clippy passed. Rust 1.99 strict checks encounter
  existing `chunks_exact_to_as_chunks` warnings in SHA/Keccak modules. With only
  that lint suppressed for a diagnostic run, the AES-feature check passed; this
  is not a claim that unrestricted strict Clippy is green.
- The first refreshed linked check, `accelerated-ephemeral-linked-current`,
  passed its direct-abort executable KAT/lifecycle preflight, then rejected the
  changed expansion population in the old review policy. Its failure is retained
  in the verifier and under
  `target/aes-accelerated-linked/1.99.1-native-static-pszc54ov`.
  No machine-code policy was relaxed. The other linked configurations still
  require their updated review and replay; this is not a final gate pass.

One initial static run also retained a marker-validation failure caused by
interleaved libtest progress output. The runner now uses captured, ordered
output; regression tests still reject prefixed, missing and duplicate markers.
All six static registrations then passed on the corrected runner.

### Integrated expansion: exact final-linked bodies

On 2026-11-09 the existing six `aes-linked-kernel` registrations were extended
to require the complete hardware expansion bodies as well as the round bodies.
All six passed across 24 newly built package-external fat-LTO consumers, direct
and facade routes with abort/unwind profiles. Rust 1.90.0 and 1.99.1 cover native
x86 static admission, emulated AArch64 static admission, and emulated AArch64
hosted admission with global AES disabled. No production Rust changed in this
review slice. See the instruction-by-instruction
[expansion review](aes-accelerated-linked-expansion.md).

Each executable binds all three widths to exact instructions and ELF bytes,
then rejects 570 x86 or 735 ARM expansion mutations plus the existing 465/570
round mutations. Across the 24 consumers this is 29,160 rejected byte/text
mutations and 432 known-answer operations with clearing/quarantine preflights.
The full registry/tooling suite passes 734 tests, including eight new expansion
review tests. Release-plan, documentation links and diff-integrity checks pass.

Both `aes-linked-public` and both `aes-linked-secret` x86 registrations also
passed against 16 additional freshly built consumers, without changing their
cached-caller policies. They replay the new expansion-body checks as well as
their existing caller/copy/volatile-clear dependencies. This does not include
cached construction. Ten registrations and 40 built consumers passed in this
slice overall.

This closes only the hardware expansion **body** review for these exact ELF
configurations. It does not rehabilitate the old portable-expansion caller
policies. Startup/dispatch, constructors and per-operation caller/cleanup
closure still require updated review; native AArch64 and timing/performance
observations must be refreshed separately. No timings were collected or retried.
The captured x86 per-operation bodies now also retain separate
`Session::encrypt128/192/256` and `decrypt128/192/256` call edges. Their admission
streams and matched round-kernel edges need explicit dependency review, not
merely replacement hashes for the outer per-operation bodies.

### Integrated expansion: x86 per-operation secret caller closure

On 2026-11-10 both `aes-linked-ephemeral` registrations passed across eight
fresh package-external direct/facade, abort/unwind consumers on Rust 1.90.0 and
1.99.1. The [updated caller review](aes-accelerated-linked-ephemeral.md) binds
each width to its reviewed hardware expansion and to separate reviewed session
encrypt/decrypt bodies, which in turn bind the matching round kernel. It covers
initial and post-expansion admission, staged secret output, full temporary
schedule cleanup, error quarantine and the emitted 1.90.0 unwind pads/import.
The cached secret/copy/volatile-clear dependency review is replayed as well.

The eight consumers exercised 144 known-answer operations with clearing and
quarantine preflights. They rejected 17,004 outer-wrapper and 4,560 session-body
instruction/byte mutations, in addition to the replayed expansion, kernel and
cached-caller controls. The registry/tooling suite passes 742 tests, including
seven new session-review tests and a new required-dependency regression.
Retained artifacts are under `target/aes-accelerated-linked/` in
`1.90.0-native-static-s0ulpamo` and `1.99.1-native-static-52rldk6r`.

No production Rust changed and no timing experiment was collected or retried.
The old public per-operation and constructor policies have **not** been refreshed
by this work; their shared expansion binding now understands the new hardware
bodies, but their own caller streams still require explicit review. Startup,
hosted admission, ARM caller/cleanup closure and native qualification remain
separate unfinished boundaries. This is not a release-gate pass or an erasure
claim for compiler spills, registers, padding or unwinder internals.

### Integrated expansion: x86 public callers and construction/destruction

On 2026-11-10 both `aes-linked-ephemeral-public` and both
`aes-linked-lifecycle` registrations passed across sixteen additional fresh
packaged consumers on Rust 1.90.0 and 1.99.1, direct/facade and abort/unwind.
The [public caller review](aes-accelerated-linked-ephemeral-public.md) now binds
hardware expansion, its before/after authority checks, exact raw-key admission,
staged publication and cleanup. These inlined public wrappers still call round
kernels directly; the secret-path session dependencies are replayed separately.

The [constructor/destruction review](aes-accelerated-linked-lifecycle.md) now
includes post-expansion health/generation/kernel admission and the new 1.90.0
cached-constructor unwind pad: quarantine, full temporary and destination
clearing, and validated resume import. Abort/unwind policies are separate.
Raw-key constructor policies and retained destruction templates are unchanged
and passed their replay. No exception-table dispatch proof is claimed.

The sixteen consumers exercised 288 known-answer operations with existing
clearing, rejection and explicit-clear/Drop preflights. The public registrations
rejected 11,886 public-wrapper instruction/byte mutations; the lifecycle
registrations rejected 16,532 constructor/destruction mutations and also replayed
the complete operation dependency controls. The full registry/tooling suite
passes 745 tests, with three new regressions for constructor profile separation,
unwind call binding and mandatory import validation. Release-plan, documentation
links and diff-integrity checks pass.

Artifacts remain under `target/aes-accelerated-linked/` in
`1.90.0-native-static-s7r60sp0`, `1.99.1-native-static-uxdvbemt`,
`1.90.0-native-static-7ula25ge` and `1.99.1-native-static-50d_1s20`.
No production Rust changed, no timing experiment was collected or retried, and
no native ARM observation was refreshed. This closes these named static x86
caller/constructor/destruction boundaries, not startup/hosted admission, ARM
caller review, arbitrary application inlining, or the remaining native/timing
qualification. It does not introduce a new release gate.

### Integrated expansion: ARM constructors and cached callers

On 2026-11-10 all four `aes-linked-arm-constructors` and all four
`aes-linked-arm-cached` registrations passed across 32 fresh packaged
direct/facade, abort/unwind consumers: Rust 1.90.0 and 1.99.1, static and hosted
admission, `aarch64-unknown-linux-musl` under QEMU. These are emulated observations,
not refreshed native AWS/Apple evidence.

The [constructor review](aes-accelerated-linked-arm-constructors.md) now binds
all three complete hardware expansion bodies by checked instructions and actual
ELF bytes. Whole-body inspection covers destination clearing before admission,
full temporary schedule initialization, post-expansion health/generation/kernel
checks, exact-width copy, temporary cleanup and quarantine. The MSRV unwind
policies include the emitted cleanup pads and the pinned executable runtime
boundary. That boundary is shared with the cached-caller reviewer; it is not
an exception-table or libunwind qualification. Raw constructors, copy and
destruction policies passed unchanged.

The [cached caller review](aes-accelerated-linked-arm-cached.md) passed its
unchanged public/secret caller policies with the new constructor/expansion
dependency checks. The 32 consumers exercised 576 known-answer operations,
plus existing clearing/quarantine and explicit-clear/Drop preflights. Constructor
registrations rejected 38,820 constructor/copy mutations, 11,760 expansion
mutations and 736 runtime-boundary mutations, plus cleanup/kernel controls.
Cached registrations rejected 35,910 caller mutations and replayed those
dependency controls. The full registry/tooling suite passes 747 tests, including
the new panic-profile and unwind-binding regressions and updated selector tests
that reject damaged expansion bytes and duplicate widths.

Constructor artifacts under `target/aes-accelerated-linked/`:
`1.90.0-arm-qemu-static-dhv7afao`, `1.90.0-arm-qemu-hosted-zqoac1rf`,
`1.99.1-arm-qemu-static-fd7sotq8`, `1.99.1-arm-qemu-hosted-5oygwgo0`.
Cached artifacts:
`1.90.0-arm-qemu-static-_nknvvsx`, `1.90.0-arm-qemu-hosted-1p59xk27`,
`1.99.1-arm-qemu-static-px5xpeb8`, `1.99.1-arm-qemu-hosted-91tjbkvr`.

No production Rust changed, and no timing experiment was collected or retried.
At this stage the old ARM per-operation caller policies still rejected the integrated
layout; they were not refreshed by these constructor/cached passes. Startup
source inspection found the complete-schedule comparisons and independent
encrypt/decrypt answers still precede healthy admission, but its final-linked
qualification remains open. Broader native, timing and release work remains
unfinished; this adds no publication gate or hardware requirement.

## Integrated hardware expansion: ARM per-operation and session review

The four `aes-linked-arm-ephemeral` registrations now pass for integrated hardware
expansion on Rust 1.90.0 and 1.99.1, static and hosted admission. Sixteen fresh
packaged direct/facade, abort/unwind consumers exercised 288 known-answer
operations plus the existing clearing/quarantine and explicit-clear/Drop
preflights. This is emulated AArch64 evidence, not refreshed native observations.

The [per-operation review](aes-accelerated-linked-arm-ephemeral.md) pins the
inspected whole public/secret wrapper bodies. Hardware expansion is entered only
after raw pointer/length validation, and admission is checked again afterward.
Secret wrappers now call six separate session bodies, which are mandatory
reviewed dependencies: health/generation/backend checks, hosted admission where
applicable, direction selection and matching-width round-kernel calls. MSRV
unwind cleanup and the pinned trusted runtime boundary remain explicitly scoped.
Current compiler outer wrappers differ between abort/unwind and are separately
pinned even though their session bodies match.

The runs rejected 71,180 caller instruction/byte mutations and 16,080 session
mutations, plus replayed cached/constructor/expansion/copy/cleanup/kernel controls.
All width-specific schedule sizes, frame offsets, saved registers and remapped
local branch destinations were reviewed before policy updates. The full
registry/tooling suite passes 755 tests, including failed-session dependency,
swapped-direction, changed-target and strict-symbol regression controls. No
production Rust changed and no timing experiment was collected or retried.

Artifacts under `target/aes-accelerated-linked/`:
`1.90.0-arm-qemu-static-xs1n0_6h`, `1.90.0-arm-qemu-hosted-nwzxy6az`,
`1.99.1-arm-qemu-static-2ejb11t5`, `1.99.1-arm-qemu-hosted-j6v6d64a`.

At this point startup final-linked admission remained a distinct unfinished review. Native
platform refresh, timing/performance and release completion also remain open;
these passes do not add a publication gate or hardware requirement.

## Static ARM startup admission review

The two `aes-linked-arm-startup` registrations now pass on Rust 1.90.0 and
1.99.1 across eight fresh direct/facade, abort/unwind packaged LTO consumers.
The [startup review](aes-accelerated-startup.md) covers the complete emitted
startup boundary, including wrong-backend rejection before kernel entry, all
three complete expected expansion schedules, six independent block answers,
generation/health construction and the complete public-data comparison helpers.
Hardware expansion and round-kernel dependency reviews are replayed.

The dedicated fixture retains opaque caller-key operations so LTO cannot
specialize its startup round kernels to known-answer data alone. It also checks
successful admission, cached operations/clearing for all widths, and terminal
quarantine. Startup/reference policies were pinned only after instruction,
encoded-address and immutable-data review. Production Rust is unchanged.

Across the eight consumers, the reviewers rejected 8,360 startup/comparator
instruction/byte mutations and 5,824 referenced-data mutations, plus 4,560
round-kernel and 5,880 expansion controls. Separately, all 5,024 corrupted-answer
executions returned the required admitted generation-2 quarantined owner and
rejected session: each consumer executes 624 schedule-byte corruptions plus
one corruption in each plaintext/ciphertext input. Crashes, healthy results,
pre-admission rejection and fallback do not satisfy these controls. The full
registry/tooling suite passes 764 tests. These are software mutation controls,
not evidence of resistance to physical fault injection.

Retained artifacts under `target/aes-accelerated-startup/`:
`1.90.0-54qb9sbj` and `1.99.1-h2jgmfqs`.
The preceding capture-only builds were diagnostic and are not verification passes.
An initial fixture-only slice/array compile error was corrected before these
registered runs; no production API or code was changed to accommodate the test.

This closed the named static ARM startup slice. Hosted Linux ARM admission is
covered by the subsequent slice below; x86 startup and broader final-linked/native
qualification remain unfinished.
No timing experiment was run or retried, and no release gate or HSM requirement
was added.

## Hosted Linux ARM startup admission review

Both `aes-linked-arm-hosted-startup` registrations pass on Rust 1.90.0 and
1.99.1 across eight fresh packaged direct/facade abort/unwind consumers.
The [hosted startup review](aes-accelerated-hosted-startup.md) binds the complete
crate boundary: Portable and wrong-architecture early returns, the exact mutable
feature cache and cold detector call, AES feature admission before kernels,
complete expected schedules, six independent answers and terminal health.
Prefer never falls back after a failed startup self-test. NEON is a target
baseline, while std_detect and Linux capability reporting remain trusted
dependencies, not independently qualified operating-system behavior.

The image reviewers rejected 10,120 startup/comparator code mutations and
5,824 referenced-data mutations, plus replayed round/expansion controls.
All 5,024 corrupted-answer binary executions retained quarantined accelerated
owners in both Require and Prefer. Sixteen additional warm/cold missing-AES
software controls produced the required rejection/fallback without an owner.
These are software controls under QEMU, not native or physical-fault evidence.

Six new tooling regressions cover fixed policy populations, every instruction
and byte, cache relocations and zero-fill permissions, strict platform symbols,
admission-control edits and registry scope. The full suite passes 770 tests.
Release-plan validation, documentation links and diff integrity also pass.
No production Rust, timing policy, public API or release gate changed.

Retained artifacts under `target/aes-accelerated-startup/`:
`1.90.0-hosted-ic1vju79` and `1.99.1-hosted-k3_0lnup`.
The initial capture-only builds were diagnostic; an input-group registration
typo was rejected before execution and corrected before these passing runs.
Both static startup registrations were also rerun successfully against the
shared runner changes: eight fresh consumers and another 5,024 quarantined
corrupted-answer executions. Their retained directories are
`1.90.0-static-rgfdg6kq` and `1.99.1-static-jr7jvnur`.

## Static x86 startup admission review

Both `aes-linked-x86-startup` registrations pass on Rust 1.90.0 and 1.99.1,
with eight fresh direct/facade abort/unwind native consumers. A baseline host
probe checks AES/SSE2 before specialized execution. The
[x86 startup review](aes-accelerated-x86-startup.md) covers the whole emitted
startup boundary: wrong-backend rejection, all three complete schedules, six
independent block answers, generation and terminal health. The hardware
expansion/round reviews are replayed. Actual ELF dynamic metadata binds the
three libc bcmp calls; libc and the loader remain trusted dependencies, not
independently qualified code.

All 5,024 separately corrupted-answer executions retained an admitted,
generation-2 quarantined owner and rejected its session. The image reviewers
rejected 8,460 startup instruction/byte mutations and 5,760 referenced-data
mutations, plus replayed kernel controls. Nine new regressions exercise complete
policies, code/constants, malformed imports and conflicting relocations, bounded
corruption controls, the baseline host probe and registry scope. The full
registry/tooling suite passes 779 tests; release-plan validation, documentation
links and diff integrity pass. Production Rust and public APIs are unchanged.

Retained native artifacts under `target/aes-accelerated-startup-x86/`:
`1.90.0-yieqqaq9` and `1.99.1-3bxi5d6h`. The earlier capture-only builds are
diagnostic, not passes. This is local-host static coverage, not admission of
hosted x86 (whose migration guarantee remains missing), qualification of the
other planned native CPUs, a timing experiment or physical fault resistance.
No remote machine was used and no release gate changed.

## Native AWS ARM integrated-expansion refresh (2026-11-10)

The Neoverse-V2 AWS host has now executed the integrated AESE key expansion
and round backend, replacing the earlier portable-expansion baseline for these
specific correctness observations. Rust 1.90.0 and 1.99.1 both passed the direct
and facade packaged APIs under static admission (`+aes,+neon`) and baseline
hosted admission (`-aes`). All 16 configurations passed: eight release AESAVS
campaigns, each covering 600 MCT records / 1.2 million block operations and 60
MMT records, plus eight independent OpenSSL comparisons in debug and release.
Both raw-key and cached-schedule owners and all three key widths are exercised.
The forced-authority markers require `ArmAes`; portable fallback cannot satisfy
these checks. These executions are native Linux AArch64, not QEMU.

Both compiler endpoints also passed the native static startup/owner/fault suite
and hosted selection/consumer suite. The static checks include the 624 startup
schedule mismatches, 36 operation-error/unwind cases, 12 constructor cases,
three cached-schedule cases and 12 revocation cases. These are software controls,
not physical fault-injection qualification. Hosted consumers replay all 2,078
NIST known-answer cases in debug and release.

The campaign runner now selects exactly one matching Cargo test executable
from a successful JSON build, retains it, and executes that retained binary.
It records the compiler identity, build and execution commands, flags, oracle
identity and before/after executable hash. Regression controls reject ambiguous
or mismatched artifacts, failed/missing build completion, non-executable files,
symlinks and paths outside the private target tree. All 780 registry/tooling
tests and all 16 registered local AMD/QEMU campaign checks passed after this
runner change. No production Rust changed in this refresh.

The compact observation is
[`aws-arm-integrated-expansion-20261110.json`](../../assurance/aes-native-observations/v0.27.3/aws-arm-integrated-expansion-20261110.json).
It records the source bundle hashes, all package hashes, 24 retained campaign
binary hashes, logs and host context. The source bundles were byte-compared
against this working tree after retrieval. Full logs and campaign binaries are
retained in `target/aes-native-aws-arm-expansion-20261110/observations.tar.gz`
(SHA-256 `337a7718a4d9bd84362950ea8fcd7ebb57983cd60b2c30fcf01184d476c162c6`),
with the remote scratch checkout retained as well. The first attempt rejected
a group-writable scratch target before compiling; its diagnostic remains in
the archive. Restricting that directory and using umask 077 resolved the setup
issue without weakening the runner.

This is an unauthenticated working-tree development observation, not clean-tag
certification or an imported current-pass receipt. It does not qualify final
linked instructions, timing, power/EM behavior, physical fault resistance,
spill erasure, or every ARM deployment. No timing measurements were taken;
correctness checks were allowed to overlap. The native final-linked and
separately declared timing work below remains open. No publication gate changed.

## Native AWS ARM linked/startup replay (2026-11-10)

The existing ARM musl policies now also pass against fresh binaries executed
directly on Neoverse-V2: 16 linked-operation consumers and 16 startup consumers,
covering both compiler endpoints, direct/facade, static/hosted and abort/unwind.
The operation review replays expansion, round kernels, constructors, copy,
clearing, retained destruction, cached/per-operation callers and session checks.
Startup controls quarantined all 10,048 corrupted-answer executables and rejected
all 16 simulated warm/cold missing-AES observations. The same policies were used
without relaxation; the earlier QEMU evidence remains separately labeled.

See the [native ARM review](aes-accelerated-native-arm.md) and its compact
observation for source-bundle, binary, review and artifact hashes. The new
explicit `arm-native` mode requires Linux AArch64 and directly executes the
musl binaries, with a baseline ISA probe before static startup. All 784
tooling/registry tests and ten fresh local native-x86/QEMU regression
configurations passed. No production Rust or release gate changed.

This closes the named native Linux AArch64 musl replay, not all ARM deployment
qualification. GNU-target correctness was exercised in the preceding section;
GNU-linked instruction review, Apple Mach-O, arbitrary downstream inlining,
exception-table dispatch and separately declared timing remain outside this
observation. The source is still an uncommitted development snapshot, not
clean-tag certification evidence.

## Integrated-expansion native performance (2026-11-10)

Four separately predeclared performance observations completed once each on
Neoverse-V2 and Ryzen 9 9950X3D, with Rust 1.90.0 and 1.99.1. The unchanged Rust
fixture compares portable/accelerated APIs across all three widths, raw/cached
owners and construction/encryption/decryption/public encryption. The runner
now admits explicit native Linux ARM as well as x86, verifies the matching
authority marker and retains the executed binary. Eight correctness-only
host/compiler/route configurations and all 786 tooling/registry tests passed
before measurement.

All 1,728 samples were retained, and the four saved summaries reproduced from
raw output. Block operations and cached construction were faster in these runs;
accelerated raw-key construction/clearing was slower and is recorded, not
hidden. There is no speed threshold or retry-to-pass. See the
[native performance observations](aes-accelerated-performance-results.md)
for values, identities, setup diagnostics and limits. The earlier measurements
using portable expansion remain historical baselines. This does not close
fixed-versus-random timing acceptance or establish physical protection.

## Integrated-expansion fixed/random observations (2026-11-10)

The accelerated timing fixture reuses the portable timer/corpus/policy with
reversible authority/API plumbing. Eight native correctness configurations and
797 tooling/registry tests passed. Four separately predeclared one-shot AMD/ARM
observations retained all 1,277,952 fixed/random pairs. AMD had no statistical
alarms but five/six noisy campaigns; ARM had one/two alarms plus five/six noisy
campaigns on Rust 1.90.0/1.99.1 respectively. None is a timing pass.

See [the retained results and investigation plan](aes-accelerated-fixed-random-results.md).
The ARM alarms require investigation of the exact timing binaries and potential
harness/address effects; no cause has yet been established. There were no
production-code changes, threshold changes or replacement runs. Timing
acceptance remains unfinished independently of fixture correctness.

## Timing address/value controls (2026-11-10)

Offline comparison found all six original ARM timing executable round bodies
identical to their reviewed instruction templates. The original GNU cached
timer nevertheless includes mode-string selection and a load through the
class-selected input address. A separately predeclared four-arm address/value
experiment used one binary per compiler and retained all 2,555,904 pairs.
Shared-address and identical-input controls had no alarms, while Rust 1.99.1
separate-address fixed/random data alarmed in AES-256 cached public-key work.
Every arm also had noisy campaigns. This strengthens the rationale for harness
investigation but does not identify a cause or close the original alarms.

Eight control-fixture correctness configurations and 804 tooling/registry tests
passed. No production crypto changed and no measurements were retried. See
[the complete control results](aes-timing-address-controls-results.md); timing
acceptance remains open pending better-controlled measurement and review.

## Dispatch-isolated timing diagnostics, 2026-11-10

The [next declared experiment](aes-timing-dispatch-controls.md) moves operation
selection outside each timer closure and specializes measurement/preflight,
retaining the four address/value controls and adding timer-only/copy controls.
Eight native correctness configurations passed ten Rust tests and 936 oracle
comparisons each; all 811 tooling/registry tests passed. The earlier eight
local timing-fixture correctness registrations were also refreshed successfully.

Both one-shot ARM observations completed, retaining 2,555,904 AES pairs and
32,768 overhead pairs. No AES control alarmed, but every arm remained
noise-inconclusive. Timer-only means were 31–39 ns, material beside the 84–89 ns
AES-256 cached public-block means; occasional large delays also occurred in
controls without AES. This does not explain away the original alarms or prove
constant time. See [the complete results](aes-timing-dispatch-controls-results.md).
The separately declared longer-batch experiment below follows this diagnostic;
it does not change thresholds or retry these runs.

## Amortized-timer observations, 2026-11-11

The [fixed 1024-operation experiment](aes-timing-batch-controls.md) completed
once per compiler on the user's replacement Neoverse-V2 host. All eight AES
controls had zero alarms and zero noise-inconclusive campaigns under the
unchanged rules. All 2,555,904 AES pairs and 32,768 overhead pairs were retained
and their summaries replayed. Sample means were 12.1–450.9 µs. The empty-loop
control includes 1024 repetitions and averaged about 0.4 µs; no subtraction or
outlier rejection was used. Eight native fixture configurations and 816 tooling
tests passed, as did twelve refreshed earlier local fixture registrations.

These are successful bounded observations, not proof of constant time or
retroactive closure of the earlier alarms. Both batch shape and host changed.
Six exact round bodies match the existing templates, and one current-compiler
cached public timer was inspected for its 1024-iteration clock boundary.
See [full results and limits](aes-timing-batch-controls-results.md). The next
work is explicit review of the retained alarm dispositions and remaining
platform qualification, not another automatic timing rerun.

## Apple integrated-expansion refresh, 2026-11-11

The current backend-assisted expansion passed all sixteen native Apple M2 Pro
campaign configurations on macOS 27.2.1: Rust 1.90.0/1.99.1, direct/facade,
static/hosted admission and AESAVS/OpenSSL differential suites. Static runs
used `+aes,+neon`; hosted runs used baseline `-aes` and explicitly reported
`ArmAes`. The eight AESAVS configurations each passed twelve tests, including
MCT/MMT for all three key sizes. The eight differential configurations each
passed four tests in both debug and release with OpenSSL 4.1.0.

Both compilers also passed the static startup/owner/fault lifecycle suite
(9 + 13 + 4 tests) and the hosted selection suite (5 tests), with hosted
consumer known-answer checks in debug and release. These refresh the earlier
Apple portable-expansion observations; they are not a new production change.

Local replay checked all sixteen configuration identities, the same 21
package-archive hashes per campaign, exact completion/authority markers,
dependency graphs, 24 saved campaign binary hashes and four lifecycle logs.
The [observation record](../../assurance/aes-native-observations/v0.27.3/apple-integrated-expansion-20261111.json)
binds the source and fixture-overlay hashes, compiler identities, logs and
retained bundle. Two setup failures are retained: the timing source bundle
initially lacked AESAVS fixtures, and a launcher-supplied oracle environment
override was correctly rejected. Both were corrected before their respective
campaign executions; no validation rule was relaxed and the already completed
first AESAVS run was not repeated.

This is unauthenticated development correctness evidence from an uncommitted
working tree. Lifecycle build caches are excluded from the retained bundle;
their logs and ISA probe binaries remain. Apple final-linked/LTO caller,
cleanup and timing qualification remain open. No previous timing alarm is
closed by these correctness results.

## Apple final-linked capture, 2026-11-11

The linked runner now has an explicit `apple-native --capture-only` path.
On the same Apple M2 Pro, all sixteen package-external consumers passed their
AES-128/192/256 known-answer, clearing and quarantine fixture: both compilers,
static/hosted admission, direct/facade routes and abort/unwind profiles. Builds
use opt-level 3, fat LTO, one codegen unit and overflow checks. Native Mach-O
executables, symbols, disassembly, dependency metadata and execution/build logs
are retained. LLVM 23.1.1 tools came from the Rust 1.99.1 `llvm-tools` component.

The [capture record](../../assurance/aes-native-observations/v0.27.3/apple-linked-capture-20261111.json)
binds the runner, original source/fixture overlays, package hashes, inspection
tools and all sixteen executable hashes. Local replay checked the exact
configuration population, native ARM64 executable headers, dependency graphs
and fixture completion. It did **not** approve the instruction text or bytes.
The capture emits no machine-review pass marker and is not registered as a
passing machine review. Mach-O lacks the ELF symbol-size representation, so
the existing ELF mapping and full-body rules cannot simply be reused.

Two new negative-control tests enforce Apple host/target identity, distinct
symbol capture and rejection of machine-review flags. The 818-test tooling
suite and all six existing linked-kernel registrations passed after the change
(24 Linux native/emulated consumers with their existing byte-level reviews).
No production crypto changed. Next is a fail-closed Mach-O mapping/body review,
followed by its caller/admission/cleanup closure; capture is not that review.

## Native Intel correctness and linked review, 2026-11-11

The user-provided AWS Intel Xeon 6975P-C host (four logical CPUs, Linux
7.0.0-1014-aws) advertised AES-NI and SSE2 and passed the baseline-compiled
ISA probes before specialized execution. Rust 1.90.0 and 1.99.1 both passed
the direct/facade static AESAVS and independent OpenSSL campaigns: eight
configurations, with twelve retained test binaries across release AESAVS and
debug/release differential profiles. All three key sizes and both operation-local
and cached owners ran with forced `X86AesNi`; no portable fallback is accepted.

Both compilers passed native static startup/owner/fault tests (9 + 13 + 4),
baseline static rejection tests (6 + 1), and hosted selection tests (5) plus
debug/release consumer rejection checks. Hosted x86 remains deliberately
unavailable: current-core AES flags do not supply its required migration-safe
admission guarantee. VAES and wider vector features advertised by this host
were not used or qualified.

Eight optimized direct/facade, abort/unwind lifecycle consumers passed the
existing exact-byte round/expansion, operation, constructor and retained
destruction reviews. Eight additional startup consumers passed their startup
review and 628 executed corrupted-reference quarantine cases each (5,024
software controls). These use opt3, fat LTO, one codegen unit and overflow
checks. The LLVM 21.1.8 inspection tool identities and compiled binary hashes
are retained; no instruction template or acceptance rule was changed.

The [Intel observation record](../../assurance/aes-native-observations/v0.27.3/intel-native-20261111.json)
binds the original source archive, fixture/support overlays, all 21 package
hashes, compiler/tool/host identities and retained logs/binaries. Local replay
checked the exact campaign and consumer populations, all hashes, dependency
graphs, completion markers and the full existing bounded code-review routines.
The initial linked attempt stopped after its first fixture execution because
the transfer omitted a shared Python review helper. That incomplete attempt
and failure log remain retained and are not counted as passes. The unchanged
helper was transferred and only the interrupted linked check restarted;
completed vector campaigns were not repeated.

These are unauthenticated observations from the recorded uncommitted working
tree, not independent certification. This correctness/linked campaign collected
no timing samples; the later, separately declared observations are below.
The same limits on arbitrary
downstream inlining, exception-table dispatch proof, compiler spills and
physical observation/fault resistance still apply. No production Rust changed.

## Native Intel measurements, 2026-11-11

The separately frozen Intel declaration completed once for each compiler and
fixture. Eight native direct/facade correctness configurations and all 43
performance/timing Python regression tests passed before collection. Local
replay checked all 864 performance samples, 2,555,904 AES timing pairs and
32,768 overhead pairs against their saved summaries and identities, including
independent timing preflight. All eight AES timing arms and four overhead
populations had zero alarms and zero noise-inconclusive campaigns under the
unchanged 1024-operation policy. No old alarm was cleared by this result.

Both measured binaries passed the existing exact round/expansion body reviews;
representative AES-256 cached-public timer inspection confirms the actual
1024-count loop and clock boundaries. This is bounded inspection, not a
whole-program proof. Cached secret encryption medians were approximately
18–19 ns on this VM; raw-owner construction/clearing was slower than portable
and remains reported. See the [full results and limits](aes-intel-measurement-results.md).
No production Rust changed and no measurements were retried.

## Apple complete kernel-body review, 2026-11-11

The retained sixteen Apple executables now pass a separate offline Mach-O
body review: all 96 complete transform/expansion functions match the existing
reviewed AArch64 instruction encodings. The new parser checks actual segment
and section mappings, definition symbols and canonical `LC_FUNCTION_STARTS`
boundaries before comparing the entire function extent. Native captures remain
unchanged and no native execution/timing was repeated. Both compiler endpoints,
direct/facade, static/hosted and abort/unwind configurations are covered.

All 192 real-binary edge mutations were rejected. Sixteen new regression tests,
including 1,044 synthetic body-byte mutations and malformed metadata controls,
are included in the full 834-test tooling suite, which passed. See the
[review scope and record](aes-apple-linked-kernels.md). This closes the bounded
Mach-O kernel mapping/body step only; Apple caller/admission/cleanup and unwind
review, timing qualification and earlier alarm dispositions remain open.

## Apple retained cleanup-body review, 2026-11-11

All sixteen retained Apple executables now additionally pass exact-byte
review of the volatile zeroizer and two retained destruction functions: 48
complete cleanup bodies, with all 832 actual-body byte mutations rejected.
The six AES functions in every binary were rechecked as dependencies. Apple
clear-loop scheduling has its own explicit templates; tail branches bind to
the reviewed zeroizer's actual start, not a name or arbitrary target.

Nine new regression tests join the existing Mach-O controls; all 843 tooling
tests passed. No production code or native measurements changed. See
[Apple cleanup review](aes-apple-linked-cleanup.md) for exact scope and records.
This does not approve every owner or call site. Session inspection identified
the older compiler's unwind call through a dynamic-linker stub, whose import
binding still needs review before accepting that runtime boundary. Constructor,
operation, admission/startup and exception-dispatch closure remain unfinished
at that review step; the following session review adds the static import check.

## Apple retained session review, 2026-11-11

All sixteen retained Apple binaries now pass complete instruction matching
for six session functions each: health/generation/admission checks, direction
selection and calls to the reviewed key-width transform. The older compiler's
unwind landing-pad instructions and static unwind import declaration/stub/
lazy-pointer/helper chain are also checked. Exception-table dispatch, dyld
fixups/common dispatcher and the system unwinder are not qualified.

All 12,000 real session-body byte mutations and 6,000 synthetic mutations were
rejected. Cleanup and AES bodies were rechecked as dependencies. Sixteen new
session/import tests bring the passing tooling suite to 859. No production
code, native capture or timing measurement changed. See the
[Apple session review and retained record](aes-apple-linked-sessions.md).
Higher-level constructors/operation callers and platform admission/startup
remain separate work; previous timing alarms are unchanged.

## Apple retained constructor review, 2026-11-11

All sixteen retained Apple binaries now pass exact instruction policies for
six raw/cached constructors and the shared copy helper: 96 constructor bodies
and 16 copy bodies. Checks cover initial destination clearing, admission,
exact key/schedule lengths, width-bound hardware expansion, post-expansion
revalidation, success publication and error/quarantine cleanup. The retained
MSRV cached unwind-pad instructions bind to the scoped static unwind import;
exception dispatch and the system runtime remain outside the claim.

All 30,576 actual constructor/copy byte mutations and 15,288 synthetic mutations
were rejected. Session, cleanup and AES bodies were rechecked as dependencies.
Nine new tests bring the passing integrated tooling suite to 868. No production
Rust, native capture or timing measurement changed. See the
[Apple constructor review and record](aes-apple-linked-constructors.md).
Higher-level cached/ephemeral operation callers and Apple platform startup/
lifetime admission remain unfinished; this adds no publication requirement.

## Apple retained cached-caller review, 2026-11-11

The sixteen retained Apple binaries now pass complete instruction policies
for all six cached public-encryption/secret encrypt-decrypt bodies: 96 callers.
Checks cover health/generation/admission, schedule pointer/length rejection,
width/direction-bound AES calls, staged public publication, secret-destination
clearing, scratch cleanup and retained MSRV unwind/quarantine instructions.
Exception dispatch and the system runtime remain outside the review.

All 27,888 actual caller-byte mutations and 13,944 synthetic mutations were
rejected; constructor, copy, session, cleanup and AES dependencies were
rechecked. Nine new tests bring the passing integrated tooling suite to 877.
No production code or native measurements changed. See the
[Apple cached-caller review and record](aes-apple-linked-cached.md).
Ephemeral operation callers and Apple startup/lifetime admission remain
unfinished, and prior timing alarms remain recorded.

## Apple retained ephemeral public-caller review, 2026-11-11

The sixteen retained Apple binaries also match explicit complete instruction
templates for the three fixture-inlined per-operation public-encryption
callers: 48 bodies. Checks cover raw-key lengths, initialized temporary
schedules, width-bound expansion, post-expansion revalidation, staged block
transformation, publication order, both clearing regions and retained MSRV
unwind/quarantine pads. Cached/constructor/session/cleanup/AES dependencies
are rechecked; exception dispatch and the system runtime remain outside scope.

All 24,320 actual caller-byte mutations were rejected. Eight new tests include
12,160 synthetic byte mutations and bring the passing
integrated tooling suite to 885. No production code or native measurements
changed. See the [Apple ephemeral public review](aes-apple-linked-ephemeral-public.md).
Ephemeral secret-output callers and Apple startup/lifetime admission remain
unfinished; earlier timing alarms remain recorded.

## Apple retained ephemeral secret-output review, 2026-11-11

All sixteen retained Apple binaries also match complete instruction templates
for the three shared per-operation secret encrypt/decrypt callers: 48 bodies.
Checks cover destination clearing before admission, exact raw-key lengths,
temporary expansion and revalidation, direction-bound session calls, returned
success discrimination, copy/clearing before owner construction, error cleanup,
quarantine and retained MSRV unwind pads. Public/cached/constructor/session/
cleanup/AES dependencies are rechecked. Exception dispatch and the system
runtime remain outside scope.

The retained-binary checker rejects all 29,520 single-byte mutation controls,
replaying dependencies for each; original binary hashes remain unchanged.
No altered executable is run. Nine new tests include 14,760 synthetic byte
mutations; all 894 integrated tooling tests pass. No production code
or native measurements changed. See the
[Apple ephemeral secret review](aes-apple-linked-ephemeral-secret.md).
Apple startup/lifetime admission remains unfinished; earlier timing alarms
remain recorded.

## Apple isolated startup capture, 2026-11-11

The existing startup runner now has a native Apple capture-only path. All
sixteen Apple M2 Pro configurations passed unchanged package-external startup
fixtures: Rust 1.90.0/1.99.1, static/hosted admission, direct/facade and
abort/unwind. Checks exercise healthy startup, wrong-architecture rejection,
three cached key widths, clearing and explicit terminal quarantine; hosted
fixtures additionally exercise portable and prefer/require behavior.

Local replay verified the complete population, package hashes against the
prior development source, dependency graphs, executable hashes, Mach-O headers
and exact fixture output. Every executable retains a separate startup symbol.
See the [capture scope](aes-accelerated-startup.md#apple-capture-only-follow-up-2026-11-11)
and [record](../../assurance/aes-native-observations/v0.27.3/apple-startup-capture-20261111.json).
Capture does not run Apple corrupted-answer or missing-feature controls and
does not claim machine review. Startup/comparison/callee review and platform
lifetime admission remain unfinished; prior caller approvals do not transfer
automatically to these new executables.

All 897 integrated tooling tests pass, including three added runner controls.
The existing current-compiler Linux hosted startup check still passes four
emulated consumers, 2,512 corrupted-answer quarantine executions and eight
missing-feature controls. No production Rust, timing data or release gate changed.

## Apple retained static startup review, 2026-11-11

All eight retained static startup bodies match inspected complete templates:
196 instructions on MSRV and 193 on the current compiler. Checks bind wrong-
architecture rejection before kernel calls, full schedule comparisons, six
independent block answers, generation and healthy/quarantined state. The 48
width-matched AES dependencies are rechecked. Eight declared system `memcmp`
imports are structurally bound to libSystem; the loaded libc/dyld behavior
remains explicitly trusted, not qualified by the local ELF comparator review.

Offline rejection controls cover 6,224 code-byte complements and 5,824 referenced
constant-bit flips. Equivalent immutable constant relocations are permitted;
all remaining instructions/registers/branches are exact. No altered executable
was run. Eight new startup tests plus one import test pass, and all 906 integrated
tooling tests pass. The earlier 16-binary caller review still passes normal replay.
See the [review and evidence record](aes-apple-static-startup.md).

Apple executed corrupted-answer controls, hosted startup/detector and platform
lifetime admission remain unfinished. No production Rust, native measurements
or release gates changed; earlier timing alarms remain recorded.

## Apple native static startup controls, 2026-11-11

The [native control campaign](aes-apple-static-startup.md#native-quarantine-controls)
passes all eight retained static binaries across both compilers, direct/facade
and abort/unwind. Eight originals and eight unchanged re-signed copies stay
healthy; all **5,024 public corrupted-answer executions quarantine correctly**.
Native Apple ad-hoc signing may resize its terminal payload; the runner checks
the two corresponding size fields and permits no other pre-signature changes.
The first overly strict unchanged-length pilot remains recorded as a tooling
rejection, not a cryptographic failure or successful negative control.

Original executables remain unchanged. Retained logs and hashes replay locally
against all fixed mutation bytes, full static reviews and exact execution
markers. Seven runner tests pass on Linux and macOS, and all 913 integrated
tooling tests pass. The Mac fixture-temp-path correction preserves explicit
symlink rejection. The release plan, documentation links and diff checks pass.

This completes the named static corrupted-answer controls, not hosted startup/
detector or platform lifetime admission. No production Rust, timing experiment,
publication gate or current verification-runner pass record changed. Earlier
timing alarms and other qualification limits remain recorded.

## Apple retained hosted startup review, 2026-11-11

The [hosted startup review](aes-apple-hosted-startup.md) matches eight complete
236-instruction bodies, rechecks 48 AES dependencies and binds eight system
comparison imports plus feature-cache/cold-detector pairs. Portable and wrong-
architecture paths precede detection/AES, both detector paths test the same AES
bit, and missing-feature Require/Prefer behavior stays distinct from terminal
startup quarantine. An admitted self-test failure cannot silently fall back.

The cache is symbol-bound, aligned, zero-filled and RW/non-executable; any
covering file padding must be zero. Detector bodies remain explicitly trusted
and hash-recorded, not independently qualified. Complete instruction and
reference controls reject 7,552 code-byte complements and 5,824 constant flips.
Seven new regression tests cover instruction/state changes, cache/detector
substitution, mapping/alias/padding, trusted-detector provenance and CLI failures.
All 920 integrated tooling tests pass, all eight earlier static startup reviews
still replay successfully, and the release-plan/link/diff checks pass.

Native hosted corrupted-answer/missing-feature execution and platform lifetime
admission remain unfinished. This does not replace the completed static native
controls, add a release gate or claim physical fault/side-channel protection.

## Apple native hosted startup controls, 2026-11-11

The [hosted native controls](aes-apple-hosted-startup.md#native-results-2026-11-11)
pass all eight retained compiler/route/panic configurations. Eight original and
eight unchanged re-signed positives stay healthy; all **5,024 corrupted-answer
executions quarantine** and all **16 warm/cold missing-feature executions** have
the expected Require/Prefer disposition. The cold control calls the real detector
and substitutes its returned observation; neither control claims hardware without
AES or physical fault resistance.

The generic Apple native runner retains exact, disjoint healthy/quarantined/
unavailable markers, requires both admission controls before a hosted pass, and
keeps their logs separate. Original executables remain unchanged; ad-hoc signing
still permits only the terminal signature and its two validated size fields.
Returned archive hashes, full hosted reviews, every constant mutation and both
observation substitutions per binary replay successfully locally.

Nine runner and eight hosted-reviewer tests pass on Linux/macOS; all 923
integrated tooling tests pass, as do release-plan/link/diff checks. Prior hosted
reviews replay unchanged and historical records retain their original identities.
No production Rust, timing experiment, publication gate or verifier current-pass
record changed. Platform lifetime admission and the other items below remain
separate; earlier timing alarms remain recorded.

## Hosted target-feature contract correction, 2026-11-11

The platform source review found that Linux std_detect in both pinned compiler
endpoints exposes AES and PMULL separately, despite Rust's `aes` target feature
covering both. Hosted admission now explicitly requires PMULL as well as AES
and NEON. The [hosted startup review](aes-accelerated-hosted-startup.md) records
the source identities, inspected warm/cold paths and tests. Native x86 and
emulated ARM hosted tests/consumers pass on both endpoints. All eight packaged
Linux linked/LTO fixtures pass, including 5,024 corrupted-answer executions and
32 absent-AES/absent-PMULL controls. No arithmetic, key owner or static backend
changed. Earlier native hosted records describe the pre-correction snapshot;
they do not establish a current pass for this change.

## Native hosted PMULL refresh, 2026-11-11

The corrected hosted source now passes all eight configurations on each native
Linux ARM and Apple builder: both pinned compilers, direct/facade, abort/unwind.
The [Linux refresh](aes-accelerated-hosted-startup.md#native-linux-pmull-refresh-2026-11-11)
and [Apple refresh](aes-apple-hosted-startup.md#explicit-pmull-native-refresh-2026-11-11)
retain separate current records without rewriting earlier observations.
Together they execute **10,048 corrupted-answer quarantine controls** and
**64 independent missing-AES/missing-PMULL controls**. Native originals pass;
Apple unchanged re-signed positives also pass under the existing bounded policy.

Returned archive identities, exact final-linked reviews and complete negative
case populations replay locally. Apple additionally retains and replays each
negative output and unsigned-mutation digest. Relevant crate trees match across
both builders and this checkout; source identity remains an uncommitted
development snapshot. Apple review rejects 8,096 startup-byte complements and
5,824 reference-data bit flips. The 923-test tooling/registry suite passes, as
do the seventeen scoped Apple reviewer/runner tests on macOS. No arithmetic,
owner, static backend, timing experiment or publication gate changed here.
Earlier timing alarms and the platform lifetime trust boundary remain open.

## Apple measurement runner and prerequisites, 2026-11-11

The existing performance/fixed-random runners now accept native arm64 macOS.
Linux still pins the measuring process and restores affinity; a Linux pinning
failure cannot silently become an unpinned run. Apple records explicit unpinned
status, CPU/OS context and uncontrolled scheduling/core-class limits. Failed
host queries stop collection. Thresholds, populations, timeout retention and
no-retry rules are unchanged, and correctness-only invocations still collect
no measurements. The shared baseline probe now explicitly requires PMULL as
well as AES/NEON; this is test tooling, not an arithmetic or API change.

All 931 tooling/registry tests pass locally. The Mac passes 18 performance,
32 timing-runner and seven static-runner tests. Eight native package-external
fixture configurations pass on Rust 1.90.0/1.99.1 through direct/facade imports:
four Rust tests plus 48 cases for each performance fixture, and ten Rust tests
plus 936 independent comparisons for each timing fixture. A Mac-only test mock
was fixed to create the absent Linux affinity attribute; an incomplete scratch
source copy was supplied with the missing timing fixtures and current registry
before native fixture execution. Neither setup correction followed measurement.

The [Apple declaration](aes-apple-measurement-declaration.md) fixes four
sequential one-shot observations and their interpretation limits before sample
collection. No new ARM/AMD sample run is authorized by that declaration.

## Apple measurements and offline replay, 2026-11-11

All four predeclared observations completed once. Both performance observations
retain 432 samples. The timing observations retain 2,555,904 AES pairs plus
32,768 diagnostic pairs: zero alarms across all eight controls, but one MSRV
AES-256 cached public-key campaign exceeded the unchanged noise limit. MSRV
therefore exited 2; current exited 0. No retries, filtering, changed thresholds
or concurrent task workload were used. Apple placement remained unpinned.

Offline replay matched all raw summaries, verified the declaration and retained
binary/package/fixture identities, compared the captured source for all 21
packaged crates with local files, and repeated 1,872 oracle comparisons. Both
actual timing binaries passed the six-body exact ARM round/expansion review.
Representative cached-public timer/callee inspection identified the measured
1,024-count loops separately from correctness-only formatting specializations.
This is bounded inspection, not a whole-program timing proof. Full records,
non-pass details and artifact hashes are in the
[Apple results](aes-apple-measurement-results.md); prior ARM signals remain open.

## Original ARM alarm-path inspection, 2026-11-11

Offline inspection of the three retained alarm-producing GNU/Linux binaries
matched their recorded identities and reconstructed fixture hashes. All 18
complete round/expansion bodies matched the existing templates, with 3,915
instruction mutations rejected. Manual inspection traced the successful timed
paths for all four non-noise ARM alarm campaigns, including public dispatch,
authority checks, block staging and memory helpers. No measurements were
repeated and no production code or thresholds changed.

The [bounded review](aes-arm-alarm-path-review.md) records exact addresses and
the distinction between matched bodies and manual caller inspection. It found
no secret-dependent branch or memory index in the inspected paths, but cannot
establish timing independence or attribute the observed alarms to harness
effects. Acceptance remains open; the next useful work is focused review of
the measurement design and retained populations, not undirected resampling.

## Retained timing-population diagnostics, 2026-11-11

The optional offline analyzer hash-checks and replays all 117 campaigns in the
three ARM observations containing the four non-noise alarms. All 958,464 pairs
and original verdicts are retained. Order strata, chronological eighths,
lag correlations and fixed-size block descriptions are exploratory only,
with no new acceptance threshold. Twelve synthetic analyzer regressions pass.

The address-control signal has the same sign in all 128 blocks of 64 pairs;
all four alarm campaigns retain their overall sign in both first-class order
strata and all four adjacent-order transitions. Two original current-compiler
campaigns show greater chronological variation, but no result justifies clearing
an alarm. The [diagnostic report](aes-retained-timing-diagnostics.md) supplies
the reproducible artifact and a focused independent review checklist. No new
samples, production changes, broad campaign reruns or release gates were added.

## Class/address crossover preparation, 2026-11-11

The [crossover design](aes-slot-crossover-design.md) identifies a gap in the
existing controls: no single run crosses both value classes over both input
slots. A test-only primitive now holds two stable slots, swaps the class mapping
and balances mapping/class order across the retained rounds. Materialization
uses slot order, avoiding an always-last-written value class. It adds no AES
implementation or timer and does not change the original runners.

All six control tests pass on Rust 1.90.0 and 1.99.1 in unoptimized and
optimized/fat-LTO builds with overflow checks and warnings denied: 24 test
executions. These are local control tests, not native ARM timing evidence.
Integration with the actual trial, strict parser/oracle checks, linked-path
inspection and a frozen run declaration remain necessary before sampling.
The intended experiment is restricted to the three affected cached paths and
two compiler endpoints. It cannot automatically clear historical alarms.

## Crossover AES integration and native correctness, 2026-11-11

The crossover driver now uses the original cached AES trial and verifies
stable per-slot addresses outside its timer. The Python validator checks exact
records, cell order, full populations, input layout, independent oracle answers
and all conditional contrasts. Seventeen synthetic tests cover malformed
records, failed oracles/processes, synthetic class/slot signals, noise and
correctness-only registration. A 947-test tooling/registry sweep passed before
the final registration guard; all 75 directly affected tests passed afterward.

Six archive-consumer configurations passed 13 Rust tests and 576 OpenSSL cells
each: local direct/facade and native ARM direct on both compiler endpoints.
The 21 archive hashes match across all configurations; local replay rechecked
every identity and all 3,456 oracle cells. Both ARM binaries match their six
complete round/expansion body templates. The
[integration record](aes-slot-crossover-design.md#correctness-integration-completed-2026-11-11)
retains setup corrections and limits. Four new verifier checks are
correctness-only; observation mode is explicitly rejected. No timing population
has been collected. Actual crossover caller/timer review and a frozen native
run declaration remain before the proposed finite experiment.

## Crossover linked-path review, 2026-11-12

The [bounded caller/timer review](aes-slot-crossover-linked-review.md) now
covers both retained ARM crossover executables. Slot-order materialization,
stable-address checks and cell bookkeeping are outside the original timers.
Cached constructors precede timing; the four-operation loops retain public
dispatch, authority checks and output/scratch clearing. The inspected successful
paths and complete copy/clear helpers showed no content-derived branch or
memory index. This is not timing independence or whole-binary qualification.

The retained ARM host timed out on SSH inside and outside the sandbox. No
measurement was started and no failed invocation was replaced. Host availability,
identity/affinity recheck and a frozen finite declaration remain before sampling.
All earlier alarms remain open. No production code or release policy changed.

## Finite crossover observation, 2026-11-12

The owner supplied fresh ARM host `13.49.18.65` and confirmed its SSH host
fingerprint. The two reviewed executables were restored without rebuilding;
their hashes matched and all 1,152 new-host preflight cells matched independent
AES answers. A [frozen declaration](aes-slot-crossover-declaration.md) named
the exact host, binaries, commands, CPU and finite population before sampling.

Both declared invocations completed once, with 393,216 durations retained.
The [results](aes-slot-crossover-results.md) report one non-noise slot-related
alarm in current AES-192 decrypt-block and four noise-flagged comparisons.
There is no above-threshold within-slot class contrast, but two such contrasts
are noisy. The observed slot sensitivity cannot explain away the earlier
signals. No samples were filtered, no retries added and no threshold changed.
The experiment is complete; timing disposition remains open for focused
independent review and, if needed, an explicit owner scope/risk decision.

The subsequent [retained-data follow-up](aes-slot-crossover-results.md#retained-data-follow-up-review)
reproduces the summaries and checks the declared strata without new sampling.
The current AES-192 fixed-slot difference remains positive in all eight time
eighths but reverses sign in two order patterns. No causal explanation or
production correction follows. The results document now supplies three bounded
questions for independent review; this same-implementation follow-up is not
that approval. Original alarms, noise and outstanding measured-path coverage
remain open, with no change to publication policy.

## Harness confounding and optional DIT, 2026-11-12

The independent identical-input investigation was checked against retained
binary identities and raw crossover populations. A separate frozen 32-launch
experiment then addressed the missing exact fourth executable. The
[results and limits](aes-fourth-alarm-results.md) support class/address/context
confounding; they do not retroactively turn any alarm into a passing screen.

The runner now requires [shared-address controls](aes-value-timing-policy.md)
for new observations, keeping separate-address arms explicitly diagnostic.
Both shared-value and shared-identical alarms/noise remain blocking. Malformed
outputs fail in every arm. This does not mandate repeated long campaigns.

The owner approved [optional scoped DIT](aes-dit.md), with a genuinely
fail-closed `Require` option. Existing hosted callers use it where supported;
older AES-capable CPUs remain usable under `IfAvailable`. Static callers can
request it with an explicit `+dit` deployment contract. Linux and Apple ARM
passed all-width state restoration tests on both compilers. Registered model
and emulated unsupported-CPU checks cover rejection without silent downgrade.
Production arithmetic is unchanged, but dispatch code changed: prior linked and
timing evidence is historical, not qualification of these new paths.

## DIT-required finite shared-address screen, 2026-11-12

The bounded Linux/Apple caller review and the separately frozen 64-launch
experiment are complete. The [full disposition](aes-dit-finite-results.md)
reports zero shared-input alarms, but one Linux and 36 Apple shared-control
noise flags. Both screens remain inconclusive under the unchanged policy.
Separate-address alarms/noise and every raw population remain retained;
no launch was retried or selected away. Collector/analyzer regressions are
integrated into the passing 988-test registry suite.

## Remaining v0.27.3 work

The [acceptance inventory](aes-acceleration-acceptance.md) replaces the older
blanket caller/lifecycle/native TODOs with the completed scoped evidence and
its actual limits. It does not turn historical results into current passes.

1. Preserve the [2026-11-12 owner disposition](aes-acceleration-acceptance.md#owner-disposition--2026-11-12):
   timing qualification remains inconclusive, but its documented limitation is
   accepted for progressing v0.27.3. Additional timing work is deferred; no
   threshold, sample or historical verdict changes. Stronger claims need a
   separately designed prospective study, not retries.
2. Preserve the reviewed hosted OS/hypervisor contract, portable defaults,
   clearing/error/unwind semantics and stated target limits. Generic hosted x86,
   ARM sanitizer qualification and unsupported bare-metal x86 are not added by
   the current observations; physical protection is not claimed.
3. Candidate `fd651e90` and lifecycle follow-up through `2bb2177e` received
   [owner-supplied focused retests](aes-acceleration-range-retest.md#owner-supplied-focused-retests-and-finalization).
   The internal v0.27.3 metadata is prepared. Complete the existing finite
   final checks and exact-commit GitHub handoff, retaining the accepted timing
   limitation rather than claiming complete qualification. Tag authorization
   remains separate.

Single-block AES-NI is distinct from later multi-block SIMD work; this slice
does not claim VAES batching. No HSM requirement, military-profile restriction,
new publication gate or physical side-channel/fault guarantee is introduced.
