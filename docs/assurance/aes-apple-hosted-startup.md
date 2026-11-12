# Apple hosted AES startup review — v0.27.3 development

Snapshot status: the [explicit PMULL admission correction](aes-accelerated-hosted-startup.md)
now has a fresh native Apple capture, exact startup review and all native
negative controls, recorded in [the refresh below](#explicit-pmull-native-refresh-2026-11-11).
The earlier observations remain historical; their binaries and reports are not
rewritten. The current checker targets the corrected source. Replaying an older
snapshot requires its retained reviewer, not relaxing the current policy.

## Historical pre-PMULL observations

The following sections through the original native results describe the earlier
snapshot and checker. Their counts and source identities remain unchanged.

This bounded offline review covers the eight hosted executables retained by the
[Apple startup capture](../../assurance/aes-native-observations/v0.27.3/apple-startup-capture-20261111.json):
Rust 1.90.0/1.99.1, direct/facade consumers, abort/unwind, optimized fat LTO.
It does not turn the earlier capture into machine approval or qualify the OS.
Source identity remains the recorded development working tree, not a release tag.

```sh
python3 scripts/aes/check-aes-apple-linked.py RETAINED_EXECUTABLE \
  --sha256 CAPTURED_BINARY_SHA256 --review-hosted-startup \
  --compiler 1.99.1 --panic abort --admission hosted
```

Identity precedes parsing. Configuration is mandatory and scoped modes are
mutually exclusive. The [checker](../../scripts/aes/aes_apple_startup_hosted.py)
constructs reviewed instruction templates, not a policy learned from a binary
or trusted disassembler output. Symbols and `LC_FUNCTION_STARTS` bound the
complete startup; all **236 instructions / 944 bytes** must match. Six AES
dependencies are rechecked in each executable, and the comparison call is bound
to the declared system `memcmp` import as in the
[static startup review](aes-apple-static-startup.md).

## Admission and terminal state

The complete inspected control flow establishes these scoped properties:

- Portable mode returns before loading the feature cache or calling any AES
  kernel. Wrong architecture is rejected before feature detection.
- A zero cache calls the bound cold detector with the result pointer, kernel
  and mode preserved across the call. Nonzero cache and cold result both test
  bit 3 before entering the accelerated branch. NEON is the target ABI baseline;
  the inspected startup does not perform a separate runtime NEON test.
- Missing AES returns `Unavailable` for Require and `PortableFallback` with no
  owner for Prefer. Wrong architecture retains its distinct reason. These
  branches occur before AES key expansion.
- Only admission reaches the three full 176/208/240-byte schedule comparisons
  and six independent block answers. All twelve answer halves and all schedule
  comparison results contribute to the final health condition.
- Both successful and failed admitted self-tests return an accelerated owner
  with generation 2. Health is healthy only when every comparison agrees;
  otherwise it is quarantined. There is no post-self-test fallback branch.

The two compilers order the answer comparisons differently; both complete
sequences are explicit in the checker. Error/fallback result padding is not
treated as an initialized secret owner or an erasure guarantee. Public fixture
assertions from the original native capture exercise portable, wrong-architecture,
Require/Prefer, healthy execution, clearing and explicit quarantine; they do not
substitute for executed corrupted-answer or missing-feature controls.

## Cache and detector binding

The cache must have the exact compiler-family `std_detect` cache symbol, an
aligned eight-byte slot in a writable non-executable `__bss` zero-fill section,
and no other defined symbol beginning inside that slot. Offset, section bounds,
permissions and symbol attributes are checked. Where the linker includes file
padding covering the slot, those bytes must also be zero. Merely marking
nonzero file data as zero-fill cannot pre-admit AES.

The cold call binds to the exact compiler-family `detect_and_initialize` symbol
and its complete executable extent. If it is the final function, the instruction
section end bounds it. Startup, detector, comparison stub and AES kernel extents
must be disjoint. The detector's bytes are hashed for provenance, **not approved
as an independently inspected implementation**. A test explicitly distinguishes
changed detector-body provenance from a rejected call-target substitution.

The locally installed MSRV `std_detect` source enumerates AES at feature bit 3;
its cache uses zero as the uninitialized state. Darwin detection reads system
capabilities through `sysctlbyname`. This source cross-check explains the
inspected branch, not a claim of OS or hypervisor lifetime qualification.
Rust detection, system capability reporting, loaded libc and dyld remain trusted
dependencies. Migration/hotplug guarantees and platform admission remain separate
review obligations; these instructions cannot establish those external facts.

## Results and remaining work

The [review record](../../assurance/aes-native-observations/v0.27.3/apple-hosted-startup-review-20261111.json)
binds the unchanged capture, source and binary identities, reviewer hashes, all
eight startup bodies, 48 AES bodies, eight comparison imports and eight cache/
detector bindings. Offline controls reject **7,552 startup code-byte complements**
and **5,824 referenced-constant bit flips**. Equivalent immutable copies of a
constant remain valid relocations. Seven new tests cover both compiler layouts,
all profiles, byte mutations, cache mapping/aliases/padding, detector extent and
call binding, policy branches, terminal health, configuration and CLI failures.
All **920 integrated tooling tests** pass. All eight earlier static startup
reviews still pass a normal replay with the extended CLI, and reviewer hashes
match the new record. Release-plan, documentation-link and diff checks pass.

This record is an unauthenticated local observation, not certification evidence
or a current verification-runner execution result. No altered hosted executable
was run during the offline review. Native hosted corrupted-answer and missing-
feature controls were then unfinished; their subsequent completion is recorded
below. Platform lifetime admission remains separate. The static native controls
do not automatically transfer to hosted binaries.
No production Rust, timing experiment or publication gate changed; earlier
timing alarms and physical-protection limitations remain recorded.

## Native control method

The [native runner](../../scripts/aes/check-aes-apple-startup-controls.py) now
accepts `--admission hosted`. It verifies the captured hash and complete hosted
review before execution. Original and unchanged re-signed positive copies must
pass first. Each temporary executable uses the bounded ad-hoc signing policy
from the [static native controls](aes-apple-static-startup.md#native-quarantine-controls):
only the terminal signature and its two validated size fields may change during
signing. Original binaries are never patched.

Each hosted executable receives 628 public KAT corruptions. Its fixture requires
both Require and Prefer to keep an accelerated quarantined owner and deny kernel
authority, never silently fall back. Two additional software controls preserve
the reviewed branches and change only detector observations:

- Warm: replace the cache load with a nonzero value without the AES bit.
- Cold: force the cache observation to zero, execute the real cold-detector
  call, then replace its returned observation with the same AES-absent value.

The fixture repeats missing-feature checks for both modes. Require must return
the precise missing-feature error; Prefer must return the corresponding
portable fallback with no kernel owner. Portable mode and wrong architecture
are checked independently before these cases. These substitutions do not claim
to model hardware faults, test hardware without AES, qualify detector internals
or prove a platform's lifetime feature guarantee.

Success requires exit zero, exactly the appropriate hosted marker and empty
stderr. Healthy, quarantined and unavailable markers are not interchangeable.
Both admission cases are required before a final hosted pass report can exist;
their hashes and outputs are retained separately from KAT-corruption logs.
No production injection API or new publication gate is introduced.

## Native results, 2026-11-11

All **eight hosted configurations pass** on Apple M2 Pro, macOS 27.2.1 (26B131):
Rust 1.90.0/1.99.1, direct/facade, abort/unwind. Eight original binaries and eight
unchanged re-signed positives stay healthy. All **5,024 public corrupted-answer
executions** retain quarantine, and all **16 missing-feature executions** produce
the precise unavailable/fallback behavior. Each negative fixture checks both
Require and Prefer; counts refer to executable runs, not distinct physical CPUs
or fault-resistance trials.

The [native record](../../assurance/aes-native-observations/v0.27.3/apple-hosted-startup-controls-20261111.json)
binds the original capture and offline review, runner/helper hashes, unchanged
original-binary hashes, re-signed copies and separate corruption/admission logs.
The retained archive hash matches the remote copy. Local replay reconstructs
every expected mutation, checks all exact output markers and full hosted reviews,
and verifies that retained runner/helper sources match those used locally.
Earlier capture, static-control and offline-review records are not rewritten.

All nine native-runner tests and eight hosted-reviewer tests pass on Linux and
macOS (their mocked execution cases are not hardware evidence). All **923
integrated tooling tests** pass locally. Eight prior hosted reviews still replay
unchanged after adding the control generator. Release-plan, link and diff checks
pass. No production Rust, timing experiment or publication gate changed.

This closes the named hosted startup negative controls, **not platform lifetime
admission**, detector/OS implementation qualification or physical fault/side-
channel resistance. Previously recorded timing alarms remain recorded.

## Explicit PMULL native refresh, 2026-11-11

All eight new direct/facade, abort/unwind captures pass on Apple M2 Pro with both
Rust 1.90.0 and 1.99.1. The [new review record](../../assurance/aes-native-observations/v0.27.3/apple-hosted-pmull-review-20261111.json)
binds the captured archive, native executable hashes, source-tree comparison and
complete reviewed startup/dependency bodies. Relevant crate trees are identical
on the Apple builder, Linux ARM builder and local development checkout. The
source remains an uncommitted working tree based on the recorded commit, not a
clean release tag or authenticated receipt.

The corrected MSRV startup has **254 instructions / 1,016 bytes**; the current
compiler has **252 instructions / 1,008 bytes**. Both have fourteen calls. The
exact templates now require AES bit 3 **and** PMULL bit 1 before any accelerated
expansion. Three cache observations and two possible cold-detector calls are
bound to the declared cache/detector. The result pointer, selected kernel and
mode survive each cold call. The MSRV uses AND/CMP for the conjunction; the
current compiler uses TST. NEON remains the target ABI baseline. Portable and
wrong-architecture paths still precede detection, and the admitted KAT/terminal
health rules remain unchanged.

Offline mutation replay rejects **8,096 startup-byte complements** and **5,824
reference-data bit flips** across the eight binaries. These controls check the
reviewer's rejection behavior, not physical fault resistance.

The [new native-control record](../../assurance/aes-native-observations/v0.27.3/apple-hosted-pmull-controls-20261111.json)
records eight healthy originals, eight healthy unchanged re-signed copies,
**5,024 quarantined corrupted-answer executions**, and **32 missing-feature
executions**. Four controls per binary independently remove AES or PMULL on
warm and cold paths, preserving the other feature. Cold controls force cache
misses and substitute only the returned observations; reviewed branches, KATs
and detector bodies remain intact. Require and Prefer outcomes are asserted
by each negative fixture. Temporary ad-hoc signing retains the same bounded
policy; the original binaries are unchanged.

Local replay verifies every mutation's unsigned digest, every exact output
marker, all case populations, full reviews and retained source/helper hashes.
The returned archive digest matches the remote archive. Eight hosted-reviewer
tests and nine native-runner tests pass on both Linux and macOS; the full
**923-test tooling/registry suite** passes locally. The updated synthetic
Mach-O fixture relocates its detector so the longer startup does not overlap it.

This closes the corrected native startup review and negative controls, not OS
or detector implementation qualification, platform lifetime guarantees, physical
protection or the earlier timing alarms. No AES arithmetic, key ownership,
static backend, timing experiment or publication gate changed in this refresh.
