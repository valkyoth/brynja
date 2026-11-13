# RV64 scalar AES candidate — v0.27.4

Status: in progress; functional candidate, **not natively admitted**.

## Scope and owner decision

On 2026-11-13 the owner requested QEMU-based validation for this milestone and
offered the existing slow cloud RISC-V host if its ISA qualifies. Its eight
SpacemiT X60 harts do not report Zkne, Zknd or Zvkned. No unsupported AES
instructions were attempted there; see the [host inventory](../riscv-native-host-inventory.md).
QEMU coverage is useful implementation evidence, not formal proof or native
performance, timing, migration, physical side-channel or fault qualification.

This slice selects little-endian RV64 **Zkne + Zknd**, not vector AES, RV32,
vendor engines or algorithms adjacent to AES. It supports AES-128/192/256 key
expansion, encryption and decryption through the existing ephemeral/cached
clearing owners. It introduces no message mode, authentication, HSM requirement
or production dependency. Portable constructors and existing x86/ARM defaults
are unchanged. ARM DIT policy does not imply a RISC-V timing mode.

## Instruction and admission boundary

The algorithm follows the ratified
[RISC-V scalar cryptography specification](https://docs.riscv.org/reference/isa/v20240411/unpriv/scalar-crypto.html).
AES64ESM/AES64ES and AES64DSM/AES64DS operate on paired halves with swapped
source order; decryption applies AES64IM to intermediate forward round keys.
AES64KS1I immediate 10 supplies SubWord; public positions determine RotWord,
Rcon and the additional AES-256 SubWord. There are no secret-indexed tables.
Byte loads/stores avoid requiring aligned caller buffers. Explicit scratch
registers are zeroed before return; that is not a claim about compiler spills,
caller copies, aborts, caches or physical faults.

`Kernel::RiscVScalarAes` identifies the candidate. Ordinary static construction
returns `Unadmitted` on RV64 even with both target features. Ordinary unsafe
platform constructors cannot bypass that exclusion. The hosted adapter reports
`UnadmittedCandidate` on RV64, including in an evidence build; it never admits
this backend based on current-hart detection. Preferred mode may select portable
only before execution, as with other unavailable routes.

Only an explicit `--cfg brynja_cpu_evidence` build includes the raw kernels.
Static evidence still requires both target features; missing either is rejected
before startup or secret storage mutation. The unsafe platform boundary retains
its lifetime-long complete-ISA obligation. The custom cfg is a deliberate
developer evidence opt-in, not authentication or a hostile-builder boundary.
Ordinary `--all-features` does not enable it.

`Authority::report().evidence_only()` explicitly identifies the RV64 AES
candidate even when its startup health is `Healthy`, and remains true on
quarantine. It classifies the kernel, not the entire binary or build flags.
False for another kernel is not certification. The report is copyable public
data, not an authenticated receipt or an execution permit. Builders must audit
effective Cargo configuration and compiler flags; another feature switch under
the same builder's control would not authenticate an evidence build.

The ratified instruction descriptions require data-independent latency for
the AES64 operations themselves, independently of Zkt. Zkt additionally covers
supporting instructions; it is not a runtime DIT enable bit. Future native
admission must assess Zkt or equivalent documented timing guarantees for the
actual supporting instruction stream on every eligible hart, plus platform
memory behavior and native evidence. Neither the instruction contract nor a
Zkt feature flag establishes whole-program constant time. The current candidate
still makes no native timing claim. See the
[review dispositions](aes-riscv-pentest-remediation.md) for the source and scope.

Startup compares complete schedules and both block directions for all widths.
Existing authority generation, health rechecks, error/unwind quarantine and
guarded output handling remain shared rather than copied into a new lifecycle.
These checks do not detect arbitrary operational computational faults.

## Reproduction and evidence interpretation

Prerequisites: Python 3, installed Rust 1.90.0/1.99.1 RV64 GNU targets,
`qemu-riscv64`, and a RISC-V GNU cross linker with a target runtime sysroot.
The runner installs nothing and fetches no dependencies; provision them before
running. It rejects ambient compiler/runner overrides and never falls back to
native execution when QEMU is missing.

```sh
python3 scripts/aes/check-aes-riscv.py --toolchain 1.90.0
python3 scripts/aes/check-aes-riscv.py --toolchain 1.99.1
# Registered source-scoped observations (does execute tests):
brynja-verify run aes --needed --category aes-riscv
# Archive-only direct and facade AESAVS campaigns (also executes tests):
brynja-verify run aes --needed --category aes-riscv-avs
# Host OpenSSL answers replayed through QEMU (also executes tests):
brynja-verify run aes --needed --category aes-riscv-oracle
# Bare-metal builds and paired API compile checks:
brynja-verify run aes --needed --category aes-riscv-no-std
# Packaged final-linked consumers and bounded raw-kernel machine review:
brynja-verify run aes --needed --category aes-riscv-linked
```

Each endpoint expects exactly 148 passing Rust tests across debug/release:

- Full evidence bundle: 9 authority tests, 13 owner tests and 4 fault tests per
  profile, including all 2,078 NIST KAT records through both owner forms and
  624 deliberately mismatched startup schedule bytes.
- Ordinary full-ISA build, evidence build missing encryption, and evidence
  build missing decryption: 6 authority tests and 1 owner rejection test per
  profile. Missing features are disabled in both compiler flags and QEMU.
- Six hosted selection tests in every phase/profile, retaining non-admission.
- Three boundary/differential tests per full-bundle profile: 256 key/schedule
  offset pairs per width, exercising all byte residues modulo 16 in guarded
  caller storage. Both owner forms and directions are compared with portable
  AES; public encryption, input preservation and clear/drop canaries are checked.
  Raw expansion and encryption/decryption are also called with guarded key,
  schedule and state buffers at all 16 residues; transforms must preserve the
  complete forward schedule. For each schedule residue, state covers all 16
  residues independently. Raw buffers contain public synthetic data and remain
  caller-owned, as required by the raw API contract.
  This portable comparison is not an independent external implementation.
  Canary checks detect writes outside admitted regions, not out-of-range reads;
  emitted-code bounds still require review.

## Archive-only AESAVS campaigns

The existing accelerated campaign adapter now accepts `--mode riscv-qemu`
with static evidence admission only. Hosted RISC-V selection and emulator-side
OpenSSL subprocess comparisons are rejected before packaging. The common
adapter selects `RiscVScalarAes`; output validation requires that exact authority
for all six executing campaigns, not just successful test totals.

For each compiler endpoint and each direct/facade route, the runner builds only
from byte-checked Cargo archives, checks the exact dependency/feature graph,
and reuses the pinned NIST ECBMCT/ECBMMT fixtures and existing campaign logic.
Each configuration has 12 tests: 600 Monte Carlo records with 1,000 iterations
and two owners (1.2 million block operations), 60 multiblock records (330 blocks
per owner), and parser/chain/key-update negative controls. These are single-block
API campaigns, not a new ECB mode API or CAVP certification. The runner retains
the binary and its hash, compiler identity, build/execution arguments, QEMU
version, output and explicit evidence flags under `target/aes-accelerated-campaigns/`.

```sh
python3 scripts/aes/check-aes-accelerated-campaigns.py \
  --toolchain 1.99.1 --route direct --admission static --mode riscv-qemu --suite avs
```

Use `1.90.0` and/or `--route facade` for the other three configurations. Normal
builds remain unadmitted; these package tests deliberately enable the evidence
cfg and do not qualify native execution.

## Independent host-oracle comparisons

The separate `--suite oracle --mode riscv-qemu` campaign uses an identified host
OpenSSL executable to generate public synthetic answers, then embeds those
answers in the archive-only RISC-V consumer. It does not launch OpenSSL inside
QEMU. The existing oracle preflight checks published encryption/decryption
answers for every key width; executable identity is checked again after the
campaign. Shared-library identity is not measured by that executable hash.

For each width, 128 deterministic public keys and 16 blocks per key produce
2,048 input records. The population includes zero, all-one, ascending-byte and
alternating-byte patterns. Encryption and decryption both operate on the
original input block: decryption is not merely a round trip of the encryption
answer. QEMU compares both clearing owner forms, both directions and explicit
public encryption with these external answers. It also checks explicit output,
key and schedule clearing. The forced authority must be `RiscVScalarAes`.

Both debug and release run on Rust 1.90.0 and 1.99.1, through direct and facade
routes: four configurations, each with eight Rust test executions and 6,144
distinct input records replayed in each profile. Strict population parsing
rejects truncated/extra records. Tooling regressions cover changed test counts,
missing/duplicate markers, ignored/filtered/failed tests, oracle process errors,
timeouts and wrong output lengths. The runner retains the generated corpus
bytes and hashes alongside the exact build/execution metadata and binaries.
These comparisons are implementation evidence, not exhaustive proof over AES's
input domain, native qualification or independent cryptographic review.

```sh
python3 scripts/aes/check-aes-accelerated-campaigns.py \
  --toolchain 1.99.1 --route direct --admission static --mode riscv-qemu --suite oracle
```

The host OpenSSL executable must already be installed. Use the other compiler
and facade route for the remaining configurations, or the registered command
above to run all four.

## Bare-metal no_std and API boundary checks

The `--riscv` variant of the packaged no_std runner targets
`riscv64imac-unknown-none-elf`, without a hosted runtime or allocator. Install
that Rust target for both compiler endpoints before running. Each direct/facade
configuration builds static and runtime API profiles, each in ordinary and
explicit Zkne/Zknd evidence configurations, in debug and release: eight library
builds. Ordinary compilation does not imply authority admission. The evidence
build deliberately supplies both instruction extensions and the custom cfg.

The same runner performs 62 paired compile-pass/compile-fail API and ownership
probes on this bare-metal target. Across the four compiler/route combinations,
that is 32 library builds and 248 paired probes. These are compile-only checks;
they neither execute the kernels nor establish real-machine ISA support.
Existing Cortex-M, AArch64 and x86 no_std coverage remains a separate campaign.

```sh
python3 scripts/aes/check-aes-accelerated-no-std.py \
  --toolchain 1.99.1 --route direct --riscv
```

## Compatibility checks and local observations

QEMU's SHA extension `Zknh` is disabled throughout. Initial debug cross-building
exposed an older SHA-256 helper missing its own Zknh feature annotation. The
schedule helper now carries the same explicit feature contract as its parent.
Cross-target linting also exposed older pointer-width casts and implicit
subtractions there: asm operands now use their exact u32/u64 widths and public
bounded index offsets use explicit wrapping subtraction (the range starts at
16, so no wrap occurs). The SHA algorithm is unchanged and AES does not gain a
global Zknh requirement. Separate SHA-256/SHA-512 candidate regressions pass
under QEMU on both compiler endpoints with AES disabled (9 tests each).

Logs under `target/aes-riscv/` record compiler/QEMU versions, exact commands,
flags, linker/sysroot and phase output. Registry observations remain local,
source-scoped results, not authenticated receipts. Source or harness changes
must not silently reuse earlier observations.

Initial cross-target Clippy passes for the CPU, hosted CPU and crypto crates
with evidence AES enabled, `--all-targets --no-deps -D warnings`, and the
existing `chunks_exact_to_as_chunks` compatibility exception. This is not a
claim that every feature/target lint combination has been checked. Existing
native x86 and ARM-QEMU static AES regressions also pass on Rust 1.99.1.

The 2026-11-13 initial registered refresh passed both 142-test endpoints
(284 Rust test executions). All 1,001 registry/tooling tests passed, including
six new RISC-V runner regression tests. API-profile policy/regression checks,
the release-plan checker, formatting and diff-integrity checks also passed.
These results close this implementation slice only, not the remaining milestone
work below. The generated verification report records the exact scoped source
fingerprints and execution timestamps.

The follow-up refresh on the same date passed both expanded 148-test endpoints,
including the raw-state boundary checks, and all four 12-test archive AESAVS
configurations (344 Rust test executions in total). The four AVS configurations
execute 4.8 million Monte Carlo block operations in total. All 1,007 registry
tests passed, including the added wrong-backend, missing-population, unsupported
configuration, missing-tool and ambient-override controls. The shared campaign
runner also passed the direct/native-x86 and direct/ARM-QEMU AESAVS regressions
on Rust 1.99.1. Cross-target Clippy with the compatibility exception above,
API-profile checks, formatting, release-plan and diff checks remained green.

The next same-date slice passed all four registered external-oracle and all
four registered RV64 bare-metal/API configurations described above. All 1,015
registry/tooling tests passed. No production Rust changed in this slice; it
extends the assurance consumers, runners and registry. Initial inspection of
the AES-128 expansion/transform disassembly is exploratory only: the complete
endpoint, all-width and representative final-linked review remains unfinished.
The shared-runner regression checks also passed direct native-x86 and ARM-QEMU
AESAVS on Rust 1.99.1, plus the original no_std runner's 12 Cortex-M/AArch64/x86
library builds and 62 paired API probes on that compiler.

## Bounded final-linked leaf review

The [RV64 linked review](aes-riscv-linked.md) now checks all six raw expansion
and transform bodies directly from ELF bytes, including both transform return
paths. It covers public branch/address flow, complete bounded memory-access
populations, expansion initialization and explicit scratch-register clearing.
Package-external direct/facade fat-LTO consumers exercise abort/unwind profiles
on both endpoints under QEMU. Actual-byte negative controls check that the
reviewer rejects the modeled failure cases. This replaces the earlier
exploratory AES-128-only inspection; it does not complete surrounding caller,
constructor or exception-table review.

On 2026-11-13, both registered linked checks passed: eight fat-LTO consumers
across Rust 1.90.0/1.99.1, direct/facade and abort/unwind. All 1,029 registry
tests passed, including 14 actual-byte/model/runner regression tests for this
stage. API-profile, formatting, release-plan, documentation-link and diff checks
also passed. This stage changed assurance tooling and documentation only; it
did not change the production AES routines or broaden native admission.

The next tooling slice adds exact linked-byte checks for the volatile byte-clear
loop and two retained destruction functions. All instruction bits and relocated
tail transfers to the checked clearing target are bound on both endpoints and
panic profiles. Negative controls mutate every instruction bit and redirect each
transfer. Scope remains owned-buffer clearing in these specific bodies, not
all callsites, constructor admission, output staging or compiler spill erasure.

On 2026-11-13, the clearing extension passed in all eight linked consumers.
All 1,034 registry tests passed, including the 19 linked-review tests (five new
cleanup regressions). API-profile, formatting, release-plan, documentation-link
and diff checks also passed. No production cryptographic code changed in this
tooling slice.

The block-session review now binds the six encrypt/decrypt authority wrappers,
their pre/postchecks, terminal quarantine, direction arguments and matched-width
leaf calls. The MSRV unwind landing pad is included, with the resume edge
validated against the live ELF import metadata. This does not yet review
constructors/startup, expansion callers or higher-level staging/cleanup paths.

On 2026-11-13, this extension passed in all eight freshly built linked QEMU
consumers, covering six block sessions per executable. All 1,041 registry tests
passed, including the 26 linked-review tests (seven new session/import
regressions). API-profile, formatting, release-plan, documentation-link and
diff checks passed. This slice changed assurance tooling and documentation,
not production AES code or admission policy.

The next slice extends the review to all six key-owner constructors, including
initial destination clearing, failed admission, exact key/schedule lengths,
matching expansion, postchecks, scratch cleanup and successful ownership
transfer. The MSRV unwind paths and live libc/unwind import bindings are
included. Authority startup and higher-level block output staging remain
outside this constructor slice.

On 2026-11-13, the constructor extension passed in all eight freshly built
linked QEMU consumers (six constructors each). All 1,048 registry tests passed,
including 33 linked-review tests with seven new constructor regressions.
API-profile, formatting, release-plan, documentation-link and diff checks passed.
No production cryptographic code or admission policy changed in this slice.

The authority-startup slice adds a separate package-external final-linked
consumer. The exact startup body, all six leaf targets, full public schedules,
independent encryption/decryption answers and terminal health are bound to
reviewed bytes and live ELF metadata. Its libc comparison/fill implementations
remain trusted. The public fixture exercises both wrong-architecture choices
and the evidence-only RISC-V choice without broadening ordinary admission.

On 2026-11-13, both registered startup checks passed: eight consumers across
Rust 1.90.0/1.99.1, direct/facade and abort/unwind. Each consumer separately
quarantined all 688 single-byte corruptions of its public reference material,
for 5,504 corrupted-answer executions overall. These are startup self-test
controls, not physical-fault protection for later operations. All 1,055 registry
tests passed, including 40 linked/startup tests with seven added regressions;
all 42 scoped-release tests passed. Formatting, release-plan, API-profile,
documentation-link and diff checks passed. No production AES code changed in
this slice; no native qualification or release approval is claimed.

The public-encryption slice extends the linked review to six complete callers:
cached and ephemeral owners at each key width. It binds authority pre/postchecks,
staging and expansion, matched transform calls, successful publication, scratch
clearing and unchanged caller output on rejection. Named copy/fill/resume
imports are validated against live ELF metadata. Secret-output callers remain
separate; libc behavior, exception dispatch and compiler spills are not qualified.

On 2026-11-13, all eight freshly built linked QEMU consumers passed the extended
review, including six public-encryption bodies each. All 1,062 registry tests
passed, including 47 linked/startup tests and seven new public-boundary
regressions. All 42 scoped-release tests passed. Both shared-input startup
checks were refreshed successfully: eight consumers and 5,504 corrupted-answer
executions quarantined. Formatting, release-plan, API-profile, documentation-link
and diff checks passed. No production AES code changed in this slice; evidence
remains scoped to QEMU, not native qualification or release approval.

The secret-output slice extends the linked review to all six retained cached
and ephemeral `secret` bodies, each covering both directions. It binds initial
destination clearing, authority checks, staging and matching expansion,
direction-specific leaf/session targets, result gating, cleanup and clearing
owner transfer. Every dependency is independently checked against actual ELF
bytes; the MSRV resume imports and cached rejection tail-clears are bound too.
Exception tables, runtime implementations, arbitrary client code and compiler
spills remain outside this bounded review.

On 2026-11-13, all eight freshly built linked QEMU consumers passed the secret
extension, covering six secret-output bodies and both directions in each.
All 1,069 registry tests passed, including 54 linked/startup tests with seven
new secret-output regressions. All 42 scoped-release tests passed. The two
shared-input startup checks were also refreshed successfully: eight consumers
and all 5,504 corrupted-answer executions quarantined. Formatting, release-plan,
API-profile, documentation-link and diff checks passed. This slice changes
verification tooling/documentation only, not production AES code; native
qualification and release approval are not claimed.

## Misuse and bounded-work disposition

The milestone's misuse requirements use the following existing regression
coverage; they are not a separate new release campaign:

- `crates/brynja-crypto-cpu/src/aes/tests.rs` covers wrong architecture and
  exact feature admission, testing/failed startup, stale generation without
  mutation, shared permanent/idempotent revocation, incomplete operations,
  post-operation state changes and unwind quarantine. Terminal generation is
  fixed, not a caller-incremented counter that can wrap through repeated revoke.
- `crates/brynja-crypto/src/aes/tests/execution.rs` injects expansion errors
  and unwinds at both checkpoints for all widths and secret/public directions,
  checks cleared scratch and secret destinations versus preserved public
  destinations, and checks constructor failure, revocation after expansion and
  that cached operations do not re-expand.
- `crates/brynja-crypto/tests/aes_execution.rs` checks both owner forms,
  failed-constructor clearing, revoked output behavior and caller-unwind owner
  cleanup without incorrectly blaming a successful kernel operation.
- `crates/brynja-crypto/tests/aes_riscv.rs` exercises all sixteen input/storage
  alignment residues in 256 offset pairs per width, both directions and owner
  forms, canaries, schedule preservation and comparison to portable AES.
- The paired API probes reject invalid ownership/borrowing and admission
  patterns; ordinary and incomplete-ISA QEMU builds test unavailable routes.
  Linked leaf/body checks bound schedule/block memory access, fixed public
  control flow, publication and cleanup in the reviewed artifacts.

The production raw-block API has no variable-length streaming state, partition
API, mode counter, nonce or message quota. Streaming/partition equivalence and
mode-counter exhaustion are therefore not applicable to this candidate; AESAVS
multiblock records do not introduce a streaming API. Exact key/block/storage
sizes, round bounds, retained schedule access and failure atomicity are the
applicable malformed-input and bounded-work checks. Portable arithmetic proofs
are not relabelled as proofs of RISC-V instructions: the bounded analyzer treats
AES instructions as opaque and functional campaigns check their results.

The [security-control mapping](../security-controls.md#risc-v-aes-candidate-controls-v0274)
keeps the normative AES family requirement planned and the existing API owners
at development status. No whole-cipher, whole-program, spill-erasure or native
qualification claim is added by this reconciliation.

## Remaining work before closing this milestone

On 2026-11-13, the facade/consumer pins, release plan, finite checklist, SBOM,
changelog and release notes were reconciled to 0.27.4. The AES requirement was
revised without promoting its planned lifecycle; the domain tests now retain
the RISC-V native-evidence limitation and ordinary-route rejection explicitly.
The gate still contains the same 30 commands, with no implicit QEMU, timing,
proof or dynamic-analysis campaign and zero crates selected for publication.

The metadata refresh passed 1,069 registry tests, 42 scoped-release tests,
release-policy/workspace checks, 14 core and 17 domain requirement tests,
API-profile checks/tests, release-plan regressions, protocol surfaces, SBOM,
formatting and documentation checks. Fresh separately selected runs passed
296 core QEMU test executions, 32 bare-metal builds with 248 paired API probes,
and eight packaged final-linked consumers. The earlier AVS, independent oracle
and startup-corruption observations retain their original snapshots; version
metadata is not grounds to call those old observations current executions.
No AES implementation or machine-review template changed in this refresh.

Remaining release steps:

- Owner pentest/retest, the existing finite final checks, green exact-commit
  GitHub/CodeQL and separate tag authorization. No automatic publication.

Native qualification is unavailable, not silently completed or inherited by
the next ordinary release. Timing/performance claims require qualifying real
hardware and a separately declared campaign. The owner-requested QEMU scope
does not create a new native timing gate for this candidate-only milestone.
