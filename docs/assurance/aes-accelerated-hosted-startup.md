# Hosted Linux ARM startup review

The separate [Apple hosted startup review](aes-apple-hosted-startup.md) now
covers retained Mach-O startup/cache/detector bindings offline and has its own
native corrupted-answer/missing-feature controls for the earlier source snapshot.
The explicit PMULL admission correction below requires a fresh Apple hosted
capture/review; those historical results do not approve the changed source.
Platform lifetime qualification remains separate.

This v0.27.3 development check covers the package-external hosted startup boundary
on Rust 1.90.0 and 1.99.1, direct/facade consumers, abort/unwind, opt-level 3,
fat LTO, one codegen unit and overflow checks. Builds explicitly disable the AES
target feature so admission uses runtime detection. NEON remains a target ABI
baseline. QEMU execution is not native ARM or macOS qualification. This is not
a new publication gate, OS audit or physical fault-resistance claim.

## Inspected control flow

After the 2026-11-11 PMULL correction, complete startup bodies have 254 (MSRV)
and 251 (current) instructions, eleven local branches and fourteen direct calls.
Both package routes and panic strategies agree after binding relocations:

- Instructions 0–1 return PortableRequested before feature detection or AES.
- Instruction 10 rejects the x86 kernel before any detector or AES call.
- Instructions 11–17 load the exact Rust feature-cache slot using X20 and
  extract AES bit 3 and PMULL bit 1 separately. Each read handles a zero cache
  through a cold detector call. These bits match both installed compiler
  endpoints' std_detect feature enumerations.
- The two cold paths preserve the result pointer, kernel and mode and apply
  the same two-bit conjunction before reaching any AES code. MSRV uses AND
  and CMP; current uses TST on the extracted single-bit values. Three cache
  reads bind to the same aligned slot; neither feature substitutes for the other.
- Missing features return Unavailable for Require, or PortableFallback without
  an owner for Prefer. Wrong architecture takes the analogous distinct reason.
- Only the admitted branch reaches instruction 22/21 (MSRV/current) and the
  first expansion at instruction 36/35. After that point there is no fallback.

The admitted path allocates a 432-byte frame and uses public temporary schedules
at SP+80 with exact lengths 176/208/240. Sequential public keys at SP+48 are
16/24/32 bytes. It compares all three complete expansions, then executes six
independent block answers using fixed schedules, plaintext and ciphertexts.
All comparison results and all twelve answer halves feed the final health
condition: healthy=1 only when every result matches, quarantined=2 otherwise;
generation=2. The Result/Option/Route layout returns an accelerated owner even
when quarantined, so Prefer cannot mask startup failure with portable fallback.
Public fixture assertions exercise both modes and subsequent admission denial.

The [static startup review](aes-accelerated-startup.md) supplies the independently
checked expansion/round kernels, complete bcmp/memcmp bodies and seven fixed
reference arrays. Those dependencies are rechecked against each hosted binary.
Opaque cached operations keep LTO from specializing the kernels to public KATs.

## Binding, controls and trust boundary

The checker pins every instruction, encoding and local destination. It validates
ADRP/LDR encodings against the exact std_detect cache symbol, which must be an
aligned eight-byte, zero-filled RW ELF extent; a code or immutable-data address
cannot substitute for it. The cold call must resolve to the exact detector
symbol and executable extent. The detector body hash is retained for provenance,
not used to claim its internals have been independently qualified. Rust's
std_detect implementation and Linux process-wide capability reporting remain
trusted, as do the deployment's OS/hypervisor migration guarantees. No report
claims that these are proved by our wrapper or by emulation.

Every startup/comparator instruction and code byte has a rejection control.
Every referenced public data byte also has a rejection control. Synthetic
policies exist only in tests and cannot approve production code. Baseline
executables must pass before their isolated copies are altered.

Each executable runs 628 separate corrupted-answer cases (every schedule byte,
plus one byte of each block input). Both Require and Prefer must retain an
accelerated quarantined owner and reject its kernel authority, never fallback.
Four further software controls independently remove AES or PMULL, preserving
the other feature, in warm-cache and cold-detector paths. Both modes must reject
or fallback appropriately, without a healthy owner. These replace only detector observations in temporary
copies; they do not simulate real hardware without AES or add an injection API
to production. Tool and original binary hashes are checked after execution.

## Detector source review and PMULL correction, 2026-11-11

Rust's `aes` target feature includes FEAT_PMULL, even though these AES kernels
do not intentionally execute polynomial multiplication. Both pinned Linux
std_detect implementations set the runtime AES bit from HWCAP AES plus ASIMD,
but set PMULL separately. Therefore the previous `aes && neon` check was not
the complete target-feature admission contract. The hosted adapter now requires
`aes && pmull && neon` explicitly. Darwin already combines AES and PMULL for
its AES bit; the explicit check remains portable across the reviewed detectors.
No AES arithmetic, static admission, key lifecycle or public API changes.

Inspected `library/std_detect/src/detect/os/{linux,darwin}/aarch64.rs` SHA-256:

| Rust | OS | SHA-256 |
| --- | --- | --- |
| 1.90.0 | Linux | `b9438441a4b370b1ad2dab5671f3bf97a16c7ebf3fad673a0d4fffc79ac54efb` |
| 1.90.0 | Darwin | `fe243d09e6c51c67f21f02c520ec851c6fb7be57163e6e45f11fa1d2b8d35272` |
| 1.99.1 | Linux | `bf9b9d10cef4de31b705fdc23961a8b836fa1875d722311c0c61db220d1b9300` |
| 1.99.1 | Darwin | `b1283a785181b5e9c896a566641c58c189edbe12f1d47e52efbbb06894c0a8c4` |

The source review also covers feature enumeration and macro expansion: compiler
target features can satisfy detection directly, so a target-specialized binary
still requires compatible hardware everywhere it runs. Linux obtains process
capabilities from the auxiliary vector, defaulting to no detected features on
failure. Darwin uses sysctl feature queries, treating failed calls as absent;
current Rust also accepts the alternate `hw.optional.arm.AdvSIMD` name.

Linux documents [HWCAP availability](https://docs.kernel.org/arch/arm64/elf_hwcaps.html)
and [system-wide safe feature reporting](https://docs.kernel.org/arch/arm64/cpu-feature-registers.html).
The conforming OS/hypervisor lifetime assumption remains explicit, as in the
[hosted platform contract](../hosted-cpu-execution.md). No KAT or finite native
test proves future hotplug/VM-migration correctness. Generic hosted x86 remains
unavailable; this correction admits no additional operating system.

Both compiler endpoints passed the five hosted tests on native x86 and emulated
AArch64, plus debug/release consumers. The existing missing-precondition test
now covers all sixteen AES/PMULL/vector/migration combinations, including exact
failure reasons. Eight packaged linked/LTO consumers passed full body review,
5,024 corrupted-answer executions and 32 independent missing-feature controls.
These are emulated observations. Earlier Linux and Apple records remain
historical and must not be relabeled as current-source passes; the separate
native refresh below records the corrected source.

The [compact observation record](../../assurance/aes-native-observations/v0.27.3/hosted-pmull-emulated-20261111.json)
binds all eight binaries and retained reports. All 923 tooling/registry tests,
strict scoped Clippy on both compiler endpoints, formatting, plan validation,
documentation links and diff-integrity checks passed after the correction.

## Native Linux PMULL refresh, 2026-11-11

Both compiler endpoints now pass all eight direct/facade, abort/unwind native
AArch64 musl consumers on the replacement AWS ARM builder. Every final-linked
startup passes the changed body policy. All **5,024 corrupted-answer executions**
retain quarantine, and all **32 missing-feature executions** reject admission
with either AES or PMULL absent, preserving the other feature in each control.

The [native record](../../assurance/aes-native-observations/v0.27.3/linux-hosted-pmull-native-20261111.json)
binds the archive, original binaries, tool identities and full review results.
Local replay matches the complete machine reviews and case populations; each
baseline output is retained. The runner checks every negative output and empty
stderr, but retains the negative case names rather than individual negative
logs. Relevant crate trees match the local development checkout and Apple
builder. This is an uncommitted working-tree observation, not a tagged receipt.
Missing LLVM utilities, private-directory permissions and missing musl targets
were resolved before the completed runs; those setup failures are not passes.

No arithmetic, key owner, static backend or timing experiment changed in this
refresh. The conforming OS/hypervisor lifetime assumption and detector trust
boundary remain unchanged. Earlier records retain their original identities.

```sh
brynja-verify run aes --needed --category aes-linked-arm-hosted-startup
```

Capture-only mode is diagnostic and cannot emit the registered success marker.
The [development ledger](aes-acceleration-development.md) tracks remaining native,
x86 startup, timing and broader final-linked qualification work.
