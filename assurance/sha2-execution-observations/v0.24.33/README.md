# v0.24.33 ordinary SHA-2 native observations

Native functional collection completed on 2026-09-10 for reviewed implementation
`e05fbd67afd9ef1b65b88649cb479e8c05c8a1e7`. No production source, API, dependency,
feature or CPU admission changed during collection. The owner supplied the Mac
log; the coding agent ran the AWS and local AMD checks. These are project/operator
observations, not independent cryptographic review or certification.

| Lane | CPU | Prefer / hosted Require | Static Require |
| --- | --- | --- | --- |
| macOS 26.6.2 ARM64 | Apple M2 Pro | SHA-256 and SHA-512 accelerated | SHA-256 and SHA-512 accelerated |
| Ubuntu 26.04 AWS Arm | Neoverse-V1 | SHA-256 and SHA-512 accelerated | SHA-256 and SHA-512 accelerated |
| Ubuntu 26.04 AWS Intel | Xeon Platinum 8488C | Portable fallback / typed rejection | SHA-224/256 accelerated; wide SHA-2 portable |
| Local Linux AMD | Ryzen 9 9950X3D | Portable fallback / typed rejection | SHA-224/256 accelerated; wide SHA-2 portable |

Every successful mode passed the normal `assurance/sha2-execution` consumer:
240 named SHA-2 cases and 4,590 general SHA-512/t cases across all 510 valid
parameters, including byte/bit operations, irregular streaming, padding/work
counts and accelerated-owner quarantine rejection. Portable mode also passed
on every lane. On Intel/AMD, the four named wide variants and general-t remain
portable; SHA-512 acceleration is not claimed on those hosts.

Generic x86 hosted Require failed with the expected
`Unavailable(MissingMigrationGuarantee)` error. This rejection was separately
checked, not counted as a successful accelerated run. Static x86 used
`-C target-feature=+sha,+sse2`; static Arm used
`-C target-feature=+neon,+sha2,+sha3`. Hosted and portable builds had those
environment flags unset. No emulation or evidence-only cfg was used.

All lanes used Rust 1.98.1, compiler commit
`48a229ceaefd4985c50990b14116b6d856af0985`, LLVM 22.1.8. Both AWS guests had
two CPUs and approximately 4 GB RAM. Rust and system linker/build tools were
installed on the fresh guests before collection. The system linker does not
provide Brynja's cryptography. Five execution tests and three transactional
rejection tests additionally passed on each AWS guest.

## Provenance and reproducibility

[observations.json](observations.json) contains privacy-filtered consumer
transcripts, original log hashes, exact source hashes, compiler and CPU metadata.
Both downloaded AWS logs matched the remotely computed SHA-256 values. The AWS
and local capture commands exited zero and all four logs end with
`NATIVE_CAPTURE: PASS`. The Mac shell command and log were owner-supplied;
its process exit code was not independently captured. No remote Mac access occurred.

Mac and AWS ran the exact reviewed commit. AMD ran documentation-only successor
`83fe89899b97bb3bff818f6df5d70767f9f8f281`; the selected source/fixture/tool files
were byte-identical to the reviewed commit. The archived source map refers to
**e05fbd67**, not later documentation/evidence binding updates. Full logs remain
gitignored under `target/sha2-native-v0.24.33`; private login paths and host/IP
details are not published. These derived summaries are not unchanged raw logs
or authenticated remote-attestation evidence.

From a matching checkout, fetch locked dependencies and run the fixture with
`portable` and `prefer`. On supported Arm, also run `hosted`. Run `static` with
the appropriate flags above; x86 must additionally pass `narrow`. The public
API guide is [here](../../../docs/sha2-ordinary-execution.md). The exact owner
command and local originals are retained separately from this public summary.

## Limits and release disposition

Native functional collection is complete for these four lanes. It does not
qualify heterogeneous scheduling, hotplug, VM migration, side channels,
performance, registers, spills, caches or platform storage. Hosted execution
still relies on the documented OS/hypervisor feature ABI. Static flags still
require a compatible deployment on every schedulable CPU.

The APIs remain public-data-only and non-erasing; hardened acceleration and
RISC-V operational support are separate work. No independent verification or
FIPS validation is claimed. The owner review and collection dispositions are
recorded in [the pentest report](../../../security/pentest/v0.24.33.md).
Final local release verification passed. Green GitHub/CodeQL and explicit
tagging permission remain required. This internal milestone publishes no crates.
