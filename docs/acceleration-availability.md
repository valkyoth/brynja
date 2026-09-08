# Opt-in acceleration availability contract

Status: v0.24.30 contract only. **No backend becomes operational in this version.**
The portable implementations and historical evidence remain unchanged. Actual
static authority starts at v0.24.31, hosted selection at v0.24.32, and per-family
activation/acceptance follows the [release plan](RELEASE_PLAN.md).

## Independent status axes

Operational availability means first-party implementation, correctness and public
package tests, exact platform authority, startup/continuing health, and the
requested ordinary or hardened profile have passed their applicable gates.
It does not require a third-party reviewer or a FIPS certificate. Neither a
native benchmark, an independent review nor a FIPS claim can grant execution
authority. Native observations remain scoped by source, compiler, CPU and OS;
performance, independent verification and certificate-bound validation are
separate observations, not interchangeable approvals.

The [machine-readable inventory](../security/acceleration-availability.toml)
records eleven implemented kernels and nine families (29 algorithm identities,
including the parameterized SHA-512/t family). Reserved AES/AVX-512/RVV entries
in the older admission register are not implemented kernels. The register stays
unchanged until each activation implementation passes its own review. Updating
an inventory boolean alone must never activate a backend.

## Selection and failure semantics

| Request | Before execution | After an accelerated session begins |
| --- | --- | --- |
| Portable | Never selects or probes an accelerated route | Remains portable |
| Prefer | Exact available route, or explicitly reported portable fallback for unsupported/unavailable profile | Authority loss or integrity failure is terminal; no silent fallback |
| Require | Exact available route, otherwise typed rejection | Authority loss or integrity failure is terminal; no silent fallback |

A failed KAT or quarantined implementation is an integrity error, not an
opportunity to retry a different backend. The first terminal error is sticky.
Backend, algorithm (including SHA-512/t's t), profile and workload identities
must survive streaming, finalization, output and reporting. Failed public-output
operations preserve their destination; failed secret-output operations clear
the entire secret destination. Streaming partial-output contracts must state
what has already been released; they cannot retroactively retract output.

Future reports distinguish dedicated instructions, single-state SIMD,
independent-message SIMD, scalar tails and host worker counts. Running portable
code in multiple threads is not SIMD. Zero full blocks can legitimately perform
no accelerated compression; reports must disclose actual work, never infer it
from a selected feature. No-op, scalar-only and evidence-cfg-only implementations
cannot satisfy an operational acceleration promise.

## Authority and package boundaries

- Default features stay empty/portable. Leaf CPU features are explicit, additive
  and non-authorizing. A feature does not establish CPU support.
- Allocation-free static use needs the complete compiler target-feature bundle
  and a sound executable/platform contract. Every possible scheduled CPU/hart
  and the OS-managed register state must satisfy it. A safe caller-provided
  boolean, CPUID alone or a non-Send session is insufficient.
- Hosted detection belongs in opt-in `-std` adapters, not the no_std leaf.
  Unknown OS/VM, migration or feature-state guarantees fail closed. AVX2 needs
  OSXSAVE/XCR0 XMM/YMM state as well as ISA support. Arm SHA-512 must check its
  actual hardware capability; Rust's `sha3` compiler bundle is not proof that
  every CPU exposing another SHA3 facility also has FEAT_SHA512.
- Modern facade features must never admit legacy crates. Legacy SHA-1 and MD5
  retain separate explicit package selection and collision-weakness warnings.
- Operational APIs must compile and execute from normal extracted packages,
  without repository evidence cfgs. Present candidate APIs do not meet that gate.
- Hardened ownership is sealed, affine and mandatory, with equivalent cleanup
  for lanes, temporaries, metadata, outputs and every lifecycle exit. Ordinary
  acceleration does not approve hardened execution. Unsupported hardened routes
  stay portable under Prefer or reject under Require; never degrade ownership.
- RV64 Zknh currently has QEMU-only instruction evidence. v0.24.50 may define an
  explicitly experimental ordinary static route, not qualified native support.
  No hardened RV64 or RVV claim is scheduled by this inventory.

The inventory names the current exact symbols, compiler features, existing leaf
features and activation versions. SHA-2 ordinary/hardened activation is
v0.24.33/.34; SHA-3/SHAKE, cSHAKE and hardened Keccak are .35/.36/.37;
KMAC, TupleHash and ParallelHash integration is .38/.39/.40. Legacy SHA-1 uses
.41/.42 and MD5 .43/.44. Missing multi-message kernels, x86 SHA-512, package
reachability and final consumer/native closure remain .45–.54. Named SHA-2 and
all 510 general t values, arbitrary-bit inputs, XOF outputs and all four
fixed/XOF derived-function identities keep their existing complete API domains.

## Executable specification, not a crypto API

`assurance/acceleration-contract` is a dependency-free no_std, unpublished model.
Its public `ContractSession::begin(Request)` only permits portable operation or
reported fallback; Require rejects every candidate. Private unit-test predicates
exercise future truth tables but are not downstream authority. Public enums are
diagnostics and requests, never permits. `finish(self)` consumes the model.
There is no algorithm execution, output buffer, runtime detector or new facade
API in this fixture. Final production API spelling remains an activation task.

Run from the repository root:

```sh
python3 scripts/cpu/check-acceleration-availability.py
python3 scripts/cpu/test-acceleration-availability.py
cargo test --locked --offline --manifest-path assurance/acceleration-contract/Cargo.toml
```

The checker binds the reviewed contract and complete inventoried owner sources.
Mutation tests reject claim promotion and source drift. Compiled model mutants
must compile and then fail behavior tests (compiler failure is not a pass).
Doctests reject forged/private ownership and finalized reuse. These tests are
not cryptographic correctness, timing, native qualification or FIPS evidence.
Activation requires new implementation and evidence; historical captures are
never rewritten to claim this model executed an instruction.
