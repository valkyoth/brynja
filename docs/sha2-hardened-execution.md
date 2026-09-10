# Hardened SHA-2 execution

The opt-in `brynja-hash-sha2/hardened-execution` feature provides complete
secret-bearing SHA-2 hashing through a separate erasing execution owner. It
does not change ordinary constructors, defaults or their public-data contract.
The implementation is under v0.24.34 review; new native Arm/Mac evidence and
the exceptional pentest are pending. No independent cryptographic review or
FIPS validation is claimed.

## API and supported routes

`hardened_execution::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256}`
support byte streaming and consuming arbitrary-bit finalization. With
`general-sha512-t`, `hardened_execution::Sha512T` covers all 510 valid parameters.
Public general IV derivation remains portable and separately counted.

Each type offers `new`, checked length preflights, `update`, `cancel`, route/work
reports, one-shot byte/bit hashing, explicit public declassification and typed
secret output. Finalization consumes the state; no reset, Clone, Copy, Debug,
ordinary-state import or implicit public conversion is available. General
secret digests retain their parameter identity and never pass through the
public `Sha512TDigest::from_bytes` importer.

| Route | Narrow SHA-2 | Wide SHA-2 / general t |
| --- | --- | --- |
| Explicit portable | Existing hardened compression | Existing hardened compression |
| x86_64 SHA + SSE2 | Owner-backed SHA instructions | Explicit portable selection |
| AArch64 NEON + SHA2 | Owner-backed SHA instructions | Not this feature bundle |
| AArch64 NEON + SHA3 | Not this feature bundle | Owner-backed SHA-512 instructions |
| RISC-V | No hardened instruction route | No hardened instruction route |

For static deployment, construct `StaticSelection` with `Mode::Portable`,
`Mode::Prefer` or `Mode::Require`, then call `hardened_execution()`. Complete
target-feature bundles are the operator's deployment contract, not a runtime
detector. A real hardened-kernel startup KAT must pass before accepting secrets.

For hosted selection, additionally enable `runtime-execution` and explicitly
use the separate `brynja-crypto-cpu-std` authority. Pass its borrowed session to
`hardened_execution::Execution::from_runtime`. A reported unavailable route may
be selected portably at construction; quarantine, generation failure or a KAT
failure never authorizes silent fallback. An existing ordinary execution owner
cannot be converted into a hardened hash state. Authority ownership and sessions
remain thread-bound; the platform must still uphold its CPU-migration contract.

```rust
use brynja_hash_sha2::hardened_execution::{Execution, Sha256};

let mut destination = [0_u8; 32];
let mut hash = Sha256::new(Execution::portable()).unwrap();
hash.update(b"confidential input").unwrap();
let result = hash.finalize_secret(&mut destination).unwrap();
assert_eq!(result.digest.expose().len(), 32);
drop(result); // clears the complete destination
assert_eq!(destination, [0; 32]);
```

## Owned-region inventory

The hash reuses `HardenedSha2Owner` and its eight regions: chaining state,
partial input, message length, phase, message schedule, block copy, padding
block and output staging. The separate CPU `Scratch` owns a 640-byte schedule
and 64-byte vector staging region. Both invoke the existing first-party
`brynja-core::clear_owned_region` compiler-resistant clearing boundary. CPU
scratch cleanup is mandatory, not dependent on the optional sanitization adapter.
The CPU crate's only new dependency is this default-off first-party core edge.

CPU scratch clears after every compression and on Drop/unwind. Incomplete
operations quarantine their authority. A mutable update guard clears and fails
the entire hash owner on backend failure or recoverable unwind, even if the
caller catches the unwind and retains the stream. Length admission errors occur
before mutation and preserve a usable state. Consuming success, error,
cancellation and Drop clear the hash owner. Secret-output errors clear the
entire destination; public-output errors preserve it.

Clearing covers live source-owned memory, not registers, compiler-created
copies/spills, caches, swap, crash dumps, DMA, abort, forced termination,
`mem::forget` or caller-owned inputs/copies. This is not a memory-locking or
military-deployment guarantee. SHA-2 alone still does not authenticate data or
provide password hashing; callers need the appropriate cryptographic construction.

## Reproducible verification

- `python3 scripts/sha2/check-sha2-hardened-execution.py`: packaged public API,
  240 NIST named bit vectors, 4,590 general-t oracle cases, streaming, secret
  output destruction, invalid outputs, quarantine and compiled regressions.
- Add `--native-x86` only on a qualifying SHA/SSE2 machine; add `--qemu` for
  supplemental AArch64 instruction execution, never native qualification.
- `python3 scripts/sha2/check-sha2-hardened-execution-codegen.py`: optimized
  MIR/LLVM/assembly cleanup inspection with unwind enabled. Repeat with
  `--toolchain 1.90.0` and `--target aarch64-unknown-linux-musl` for endpoints.
- `python3 scripts/sha2/test-sha2-hardened-execution.py`: exact region and gate
  regression checks. `security/sha2-hardened-execution-reviewed.json` binds the region inventory,
  source, consumer, dynamic-analysis commands and cleanup checks.

Miri covers bounded portable owner/lifecycle cases; native and QEMU tests cover
instructions that Miri cannot interpret. The release impact selector also
includes consumers of the changed shared CPU package, not unrelated legacy
hashes. Native evidence must identify the exact reviewed source and operational
route; older ordinary-kernel captures do not qualify these new secret kernels.
