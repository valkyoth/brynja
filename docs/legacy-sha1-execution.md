# Ordinary operational legacy SHA-1

Development implementation for v0.24.41; owner pentest and fresh native release
qualification are pending. SHA-1 is collision-broken. These APIs are not for
new signatures, certificates, authentication, passwords or confidential data.
No independent cryptographic verification or FIPS validation is claimed.

The portable `Sha1` and `HardenedSha1` APIs are unchanged. New execution is
default-off: enable `execution` on `brynja-legacy-sha1`, or `runtime-execution`
on the separate `brynja-legacy-sha1-std` adapter. The modern facade and modern
protocol dependency graphs do not acquire a SHA-1 dependency.

## APIs and authority

- `Executor::portable()` never probes or executes an instruction backend.
- `Executor::for_compiled_target(Mode)` selects an explicitly specialized binary.
- `Authority::for_compiled_target()` requires the complete compile-time bundle.
- The separate unsafe `Authority::from_platform` boundary requires an external
  process-wide, lifetime-long feature contract. It is not a safe CPUID shortcut.
- `brynja_legacy_sha1_std::execution::select(Mode)` uses only the allowlisted
  AArch64 system feature APIs already reviewed for the modern hosted adapter.
- `Mode::Prefer` falls back only for unavailability before startup. Failed KATs,
  revoked owners and operation failures never silently switch to portable.
- `start(PublicData::acknowledge())`, `hash` and `hash_bits` require explicit
  public-data classification. Streams expose checked byte/bit capacity,
  irregular byte updates, consuming byte/bit finalization and cancellation.
- `quarantine()` permanently revokes the owner and every borrowing stream.
  Owners and streams are non-cloneable and thread-bound; reports grant nothing.

| Platform/profile | Execution contract |
| --- | --- |
| x86/x86_64 static | Explicit `+sha,+sse2` binary; deployment must preserve the bundle on every executing CPU |
| Little-endian AArch64 static | Explicit `+neon,+sha2` binary (Rust's SHA2 bundle includes SHA1) |
| AArch64 hosted Linux/Android/macOS/iOS/Windows | OS-wide feature ABI, complete NEON/SHA2 bundle, startup KAT |
| Generic hosted x86, BSD, unknown targets | Required fails; Prefer returns portable; current-core feature flags alone are insufficient |
| Confidential/keyed/hardened acceleration | Not provided here; separate v0.24.42 work |

These are the existing kernels, not a new SHA-1 variant. The earlier `cpu` and
`cpu-evidence` candidate API retains its two-key evidence-only gate, even with
Cargo feature unification. Operational execution uses a separate owner; it does
not set `is_admitted()` to true or claim independent backend approval.

## Memory and lifecycle boundaries

Private source-owned byte buffers retain their existing compiler-resistant Drop
cleanup. Kernel-local temporaries, registers and spills are not cleanup-qualified;
the new APIs must not process secrets. PublicData is a caller acknowledgement,
not a mechanism for detecting confidential bytes. Borrowed sessions cannot
outlive their owner. Finalization consumes the operation on success and failure;
length preflight is atomic, while backend failure destroys retained state.

## Reproducible checks

`cargo test -p brynja-legacy-sha1 --features execution` runs the new public
acceptance, including all 529 NIST vectors, byte/bit partitions, million-byte
input, revocation and consuming ownership. Generic builds test portable control
and unavailable required routes; this alone is not instruction-execution proof.

On a qualified SHA-capable x86 machine, run with invocation-local
`RUSTFLAGS="-C target-feature=+sha,+sse2"`. The static route emits the
`SHA1_OPERATIONAL` marker only after successful real hashing. No evidence cfg is
used. `python3 scripts/sha1/check-sha1-package.py --execution` repeats acceptance
against extracted packages and 1,135 independent bit-message oracle cases.
Cross-target/QEMU correctness remains supplemental, never native qualification.

After a green owner pentest, fresh native collection uses
`python3 scripts/sha1/capture-sha1-execution-native.py LANE OUTPUT.json --attest-native`.
Registered lanes are `amd-x86_64`, `intel-x86_64`, `aws-aarch64` and
`apple-m2-aarch64`. Fetch the locked workspace dependencies first. The capture
requires a clean committed checkout, verifies each host feature bundle, runs
generic/hosted and explicit static paths without candidate-evidence flags,
and repeats the independent packaged consumer checks. The JSON binds the
commit, compiler, reviewed sources, exact routes and results. Collection is
operator-self-attested and must be reviewed before release; it is not a proof
of hypervisor migration policy, side-channel resistance or physical erasure.

Ownership checks reject 19 invalid packaged uses; compiled debug/release
mutations demonstrate that revocation and finalization guards cannot be removed
without failing the tests. Scoped Miri covers portable owner lifecycle; ASan
covers ordinary execution state. Instruction-specific native checks are separate
from that generic sanitizer run.
