# Hardened batch platform selection

The hosted SHA-224/256, SHA-512-family and Keccak batch adapters intentionally
distinguish a compiler-selected baseline from a runtime observation. This applies
to both the ordinary and distinct hardened owners. It does not change candidate
admission, secret classification, or the release gates.

## What the constructors guarantee

| Entry/build | Outcome on x86-64 |
| --- | --- |
| `Mode::Portable` | No CPU authority; no detector or startup KAT |
| Generic or AVX-only build, `Mode::Prefer` | Explicitly reported portable selection (`kernel() == None`) |
| Generic or AVX-only build, `Mode::Require` | `Unavailable`, even on an AVX2-capable host |
| Complete build-wide AVX/AVX2 bundle, Prefer or Require | Static authority and actual vector startup KAT; deployment must satisfy that compiled baseline |
| CPU `Authority::for_compiled_target` without the complete bundle | `MissingFeatures` before KAT/instruction entry; a different architecture is `WrongArchitecture` |
| CPU `unsafe Authority::from_platform` | Explicit external platform obligation covering the complete instruction/OS-state bundle throughout the authority lifetime |

For AVX2, the static guard requires **both** `target_feature="avx"` and
`target_feature="avx2"`, on x86-64. The Cargo feature exposes the API; it is not
a promise of current-core runtime dispatch. Callers can inspect the selected
kernel and choose Require when portable selection is unacceptable.

`for_compiled_target` introduces no instruction requirement beyond the crate's
compiler-selected baseline. Its safe signature does not make a specialized
binary portable to older hardware. Code elsewhere in the same compilation can
also use enabled instructions. Rust's [architecture documentation](https://doc.rust-lang.org/core/arch/)
requires deployment onto compatible machines when features are enabled globally.
Marking this one method unsafe would not protect the rest of such a binary.

A generic build cannot bypass that guard through safe input. The separate
`from_platform` constructor, which can authorize instructions beyond the static
baseline, remains unsafe. A platform provider must uphold its documented
lifetime-wide contract; a caller-supplied `true` callback is not proof of it.

## Why adding the suggested detector is not a migration fix

Rust documents that [`is_x86_feature_detected!`](https://doc.rust-lang.org/std/macro.is_x86_feature_detected.html)
returns a compile-time true result for a globally enabled feature. Replacing the
static guard with that macro therefore does not protect an AVX2-specialized
binary deployed or migrated to an incompatible host. In a generic build it
would instead introduce a different, current-core selection policy without
establishing the scheduler/hypervisor guarantees required by this API.

The older `execution/platform.rs` detector is not a counterexample: its separate
`system_guarantee` check rejects generic x86 authority even when CPUID reports
the instruction features. The three ordinary batch siblings use the same
static-baseline policy as the hardened adapters.

Static revalidation checks the compiled contract and explicit owner health; it
is **not** live CPUID polling and cannot detect migration. Allowlisted AArch64
selection instead relies on the advertised OS instruction/context ABI. Its Rust
detector can also use compile-time knowledge or cached results; it is not a live
migration monitor either. CPU affinity, a KAT and current-core detection alone
do not establish an arbitrary future hypervisor guarantee.

If the compiled baseline cannot be guaranteed throughout deployment, use a
generic build and portable mode, or provide a qualified explicit platform
integration. Do not deploy a specialized build first and expect an in-library
fallback check to make it safe. No process-wide affinity policy is forced here.

## Reproducible regression coverage

The standalone [compiled contract test](../scripts/cryptography/test-hardened-batch-platform.py)
checks extracted packages without modifying production sources or release rules:

```sh
python3 scripts/cryptography/test-hardened-batch-platform.py
python3 scripts/cryptography/test-hardened-batch-platform.py --toolchain 1.90.0
```

It requires Linux x86-64. Generic builds exercise all six ordinary/hardened
families, precise static rejection, Prefer/Require reporting and Portable
selection. Six source mutations exercise the three hardened admission guards
and three hosted selectors. Post-guard sentinel instrumentation prevents these
negative tests from entering unsupported instructions, even on an older CPU.
Three paired external compile checks require the exact E0133 unsafe-call error;
making each platform import safe causes the same negative probe to compile.
All mutated package sources are restored and retested.

Add `--lane amd-x86_64` or `--lane intel-x86_64` only on a matching native host.
The existing host validator must accept its enumerated AVX/AVX2 bundle before
the test executes AVX-only and AVX2-specialized builds. The complete build must
run actual startup KATs; explicit quarantine must revoke the selected owner.
Without `--lane`, the specialized detector probe is compiled but never executed.
Optimized LLVM must show its AVX/AVX2 macro conjunction returning constant true.

This does not simulate a scheduler move, test an incompatible specialized binary,
establish migration safety, or qualify native Arm platforms. It documents and
tests the existing contract rather than pretending those limits were removed.
