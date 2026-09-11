# v0.24.36 cSHAKE and hosted sponge native observations

Collection passed on 2026-09-11 at `b6595c8e5e100014f68651e0ab6a974f2dd239af`.
Production code and build inputs are unchanged from the clean owner-retested
`418e9710`; the capture successor only records documentation and review metadata.
These are project/operator functional observations, not independent verification,
hardware attestation, FIPS validation or side-channel qualification.

| Lane | CPU | Prefer / required hosted | Required static |
| --- | --- | --- | --- |
| macOS 26.6.2 ARM64 | Apple M2 Pro | Runtime ArmKeccak / Runtime ArmKeccak | ArmKeccak |
| Ubuntu 26.04 AWS Arm | Neoverse-V1 | Runtime ArmKeccak / Runtime ArmKeccak | ArmKeccak |
| Ubuntu 26.04 AWS Intel | Xeon Platinum 8488C | Portable fallback / typed rejection | X86Keccak AVX2 |

Each successful mode passed 628 cSHAKE official/independent bit-oracle cases and
1,084 SHA-3/SHAKE execution cases. Portable passed on all three hosts. Intel's
required hosted mode exited 1 with exactly the expected
`Unavailable(MissingMigrationGuarantee)` reason; it is not counted as acceleration.
Both AWS hosts passed 19 leaf unit tests, two cSHAKE integration tests with
static features, and four hosted sponge tests. Mac passed all four hosted tests.
The fixture checks accelerated-owner quarantine and output preservation.

All lanes used Rust 1.98.1, compiler `48a229ceaefd4985c50990b14116b6d856af0985`,
LLVM 22.1.8. Arm hosted feature admission preceded static execution. AWS CPU flags
were checked for every reported processor before entering static instructions;
the Mac log records SHA3/SHA512 availability. Static flags were `+avx,+avx2` on
Intel and `+neon,+sha2,+sha3` on Arm. AWS used two build jobs on two-vCPU guests.
No QEMU run is counted as native evidence.

## Provenance and privacy

[observations.json](observations.json) binds the capture revision, compiler,
routes, counts, raw artifact hashes and 260 source/build/fixture inputs captured
identically on both AWS hosts. Mac ran the same source-policy check and recorded
its policy-file hash and clean commit; its complete source map was not separately
exported. Both AWS detached jobs separately recorded exit 0. The owner-provided
Mac log ends with `NATIVE_CAPTURE: PASS`; its process exit was not separately
recorded. Both AWS downloads matched remotely computed SHA-256 checksums.

Import checks rejected sixteen mutated AWS observations and six mutated Mac logs
covering commit, lane, compiler, missing completion, source binding, counts,
routes, capture-script identity and test completion. Raw logs, the reviewed
one-shot capture/import scripts and remote checksums remain gitignored under
`target/cshake-native-v0.24.36`. Public records exclude host addresses and account
paths. Project-owned import validation does not authenticate a physical CPU.

The changed optional hosted dependency and verifier pin also required refreshed
[hardened SHA-2 observations](../../sha2-hardened-native/README.md) on all three
hosts. Those artifacts pass the existing source/commit/route validator without
relaxing it; older observations are preserved under their original filenames.

## Reproduction and release boundary

At the pinned checkout, fetch locked workspace and fixture dependencies, then run
`python3 scripts/sha3/check-sha3-execution.py --policy-only` and:

```sh
cargo +1.98.1 run --locked --offline --release --manifest-path assurance/sha3-execution/Cargo.toml -- portable
```

Repeat `prefer`, supported `hosted`, and `static` with the matching flags above.
Use the published capture script for the SHA-2 hardened refresh. Full local
verification follows this collection with explicit owner approval; no full-gate
PASS is claimed by these observations. Green GitHub/CodeQL and tagging permission
remain separate steps. No crates.io publication is selected for v0.24.36.

Ordinary cSHAKE/SHA-3/SHAKE execution is non-erasing and public-data-only. Neither
this corpus nor native instructions prove scheduling/hotplug/VM migration safety,
secret erasure, timing resistance, performance or suitability for classified use.
