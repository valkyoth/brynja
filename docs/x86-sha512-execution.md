# Dedicated x86 SHA-512 execution

Status: v0.24.49 release candidate. Both owner-supplied retests are recorded;
F1 is closed at the opaque-kernel boundary, with caller/platform limits retained.
Native runtime evidence is collected; final release checks remain pending.
No native dedicated x86 SHA512 host measured; its execution evidence remains SDE.

## Exact capability

`brynja_crypto_cpu::static_execution::Kernel::X86Sha512` identifies the dedicated
SHA-512 instruction set. It is neither SHA-NI (SHA-1/256) nor AVX-512. Its full
Rust bundle is `sha512,avx2,avx`, including OS-enabled XMM/YMM state throughout execution.
Although the intrinsic lists SHA512/AVX, Rust's compiler feature model makes
SHA512 imply AVX2. Both supported endpoints confirm this with `rustc --print cfg`;
disabling AVX2 also disables SHA512. Authority therefore explicitly checks AVX2.
See [Rust's implied features](https://github.com/rust-lang/rust/blob/1.90.0/compiler/rustc_target/src/target_features.rs).
The three Rust intrinsics are stable since 1.89, below the workspace's 1.90 MSRV:
[Rust intrinsic contract](https://doc.rust-lang.org/core/arch/x86_64/fn._mm256_sha512rnds2_epi64.html),
[Intel instruction reference](https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html).

The ordinary kernel expands messages with `vsha512msg1`/`vsha512msg2` and performs
all 80 rounds with `vsha512rnds2`. No AVX-512 support is required. The separate
hardened kernel expands into the existing clearing owner and uses dedicated
round instructions; it never borrows the ordinary non-erasing schedule. Both
support arbitrary initial chaining states, not only the SHA-512 IV.

## Public API

Enable the leaf's default-off `static-execution` feature, then build only for
a compatible deployment with `RUSTFLAGS="-C target-feature=+sha512,+avx2,+avx"`.
The Cargo feature alone does not promise CPU support. Every schedulable CPU and
the OS/hypervisor must retain this instruction/register-state capability for
the executable's lifetime, including migration. Unsupported specialized code
can fault before a runtime check; do not distribute it as a generic executable.

```rust
use brynja_hash_sha2::execution::{Kernel, Mode, Sha512, StaticSelection};
// Prefer is explicit; a generic build returns an observable portable route.
let owner = StaticSelection::new(Kernel::X86Sha512, Mode::Prefer)
    .map_err(|e| format!("{e:?}"))?;
let output = Sha512::hash(owner.execution().map_err(|e| format!("{e:?}"))?, b"abc")
    .map_err(|e| format!("{e:?}"))?;
assert_eq!(output.digest, brynja_hash_sha2::sha512(b"abc").map_err(|e| format!("{e:?}"))?);
# Ok::<(), String>(())
```

The same execution owner supports SHA-384, SHA-512/224, SHA-512/256 and all 510
valid SHA-512/t parameters, including bit input and streaming. Narrow SHA-224/256
requests reject this identity. Require fails before instruction entry when its
static bundle is absent. A backend failure/quarantine never permits fallback.
Existing portable defaults and AVX2 independent-message batching are unchanged.

With `hardened-execution`, use `StaticSelection::hardened_execution()` and the
distinct `hardened_execution` hash APIs for confidential data. Source-owned
schedule/vector regions clear on return, error and recoverable unwind; ordinary
`execution` APIs remain public-only and non-erasing. Registers, compiler copies,
spills, process abort and platform storage remain outside this clearing claim.

The all-backend remediation now gives the private x86 and Arm
SHA-512 compression kernels a narrower, separately tested normal-return
boundary: their secret loads/computation/stores occur within opaque assembly,
followed by scratch and working-register erasure before exit. This does not
extend that guarantee to every caller, portable fallback or other kernel.
All sixteen accelerated ports are implemented. The supplied retest closes F1 at
the opaque-kernel boundary, not at every caller frame. Native functional testing
does not establish platform-wide register erasure or dedicated SHA512 silicon
qualification; see the
[source-bound checks and inventory](../assurance/register-cleanup/README.md)
and the [compiler/platform handoff](../assurance/register-cleanup/pentest-handoff.md).

The low-level unsafe runtime platform import supports the new identity with the
same explicit whole-lifetime obligation. The safe hosted x86 adapter still
rejects missing migration guarantees, even if CPUID has SHA512. This milestone
does not turn current-core detection into system-wide authority.

Internally, both instruction-entry wrappers require a private-field permit,
created from the checked static bundle or a borrowed platform-authorized owner.
The entry rechecks that permit. Checked schedule/index failures produce
`InternalDomain` and revoke the executing owner; caller state is unchanged and
the hardened operation guard clears scratch. No zero-word substitution is used
by the dedicated SHA512 kernel.

Generic-build differential/runtime instruction tests are explicitly ignored
when their complete compiled bundle is absent. They are not execution evidence.
The separate [SDE CI workflow](../.github/workflows/dedicated-sha512.yml) runs on
relevant source/test changes, with mandatory actual-execution markers, both
compiler endpoints and ASan/LSan. The owner accepted Intel's license; the
[installer](../scripts/ci/install-sde.sh) additionally requires explicit acceptance
and verifies the pinned archive before extraction. Forks must obtain their own
license acceptance before enabling this workflow. This is not a new tag gate.

## Development evidence and remaining work

On 2026-09-17, Intel SDE 10.13.1 (2026-07-28), Arrow Lake model, passed:

- 1,024 arbitrary-state compression comparisons against a separate scalar
  recurrence, including zero/max states, plus post-quarantine rejection.
- 512 ordinary/hardened comparisons and source-owner cleanup/unwind tests.
- 240 named SHA-2 cases and 4,590 all-parameter SHA-512/t cases for each of
  ordinary and hardened consumers, selecting `Static(X86Sha512)` for wide hashes.

The dedicated runner repeats the kernel tests in debug/release at Rust 1.90.0
and 1.98.1, checks missing SHA512/AVX2/AVX bundles, and verifies all three emitted
instructions plus separate ordinary/hardened symbols. Runtime dispatch also
checks the real KAT, wrong-operation rejection and post-quarantine preservation
for ordinary and hardened sessions. This is a specialized test authority, not
qualification of an OS or hosted migration guarantee. Packaged consumers reject
seven ordinary and twelve hardened ownership/classification misuses and five
compiled algorithm mutants, with a restored-source positive run afterward.
Ten additional debug/release mutants remove schedule/vector clearing, operation
cleanup, unwind quarantine or exact-operation validation. Their live tests run
only the dedicated SHA512 kernel and reject every mutant. Compiled startup-KAT,
post-startup entry-loss and scalar-substitution probes also pass.
The existing owner-cleanup MIR/LLVM/assembly checker passes at both compiler
endpoints. Affected all-feature tests/doctests, strict scoped Clippy (with the
existing chunks_exact style allowance), AArch64 compilation and bare-metal
portable compilation also pass. Shared assurance/requirements metadata and
their regressions, full workspace tests/doctests, all-feature Clippy,
no-default-feature checks, documentation generation and dependency-isolation
checks pass. These are development checks, not a full release sweep.
The pentest follow-up passes 30 generic-build CPU Miri tests, with two instruction
tests explicitly ignored, including new domain and permit lifecycle checks;
Miri does not interpret the new SHA512 instructions. Three compiled permit
negatives and six debug/release quarantine mutants also pass, covering injected
internal failures on ordinary static/runtime and hardened routes.
The pinned nightly AddressSanitizer lane executes 1,024 dedicated comparisons,
runtime authority and the 512-block hardened cleanup/unwind campaign under SDE.
LeakSanitizer is forced on with fatal error exits, overriding ambient disable
settings; this lane passes with no sanitizer diagnostic. This is emulated
sanitizer evidence, not native platform qualification.

Reproduce the dedicated tests with an owner-licensed SDE installation:

```sh
python3 scripts/sha2/check-x86-sha512.py --sde /absolute/path/to/sde64 --asan
```

Local development logs include `/tmp/brynja-v02449-pentest-sde.log`,
`/tmp/brynja-v02449-pentest-miri.log`,
`/tmp/brynja-v02449-workspace-tests.log`,
`/tmp/brynja-v02449-workspace-clippy.log` and
`/tmp/brynja-v02449-cleanup-{190,198}.log`; these transient files are not portable
release receipts. The compiler/scope checks do not relabel earlier native records.

The SDE Linux archive SHA-256 is
`94e97d623fec54385686e1e7ba65ebc9941748c05ee451423948334892bf2b50`, matching
[Intel's download](https://www.intel.com/content/www/us/en/download/684897/intel-software-development-emulator.html).
The owner accepted its license; SDE is an external test tool, not a dependency
or a redistributed crate component. QEMU 11.1.1 TCG explicitly rejects SHA512;
its failed execution attempts are not positive evidence.

Local AMD and the observed AWS C8i lack SHA512. See the
[hardware inventory](native-hardware-inventory.md). SDE correctness is not
native performance, timing, heterogeneous-core/migration evidence, independent
cryptographic verification, FIPS validation or military approval. Do not request
a larger C8i assuming it adds the missing feature.

Both owner retests and the F1 boundary disposition are recorded in the
[pentest report](../security/pentest/v0.24.49.md). Final source-bound evidence
integration and existing release verification remain required. Existing Kani
portable arithmetic/ownership proofs do not verify SHA512 intrinsics; no such
claim is made. Historical native PASS records do not qualify changed code;
current captures retain their exact source identities. The existing evidence-reuse workflow is
unchanged; unrelated implementations must not be rerun merely for these notes.
