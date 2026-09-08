# v0.24.29 general SHA-512/t native observations

Apple M2/macOS and AWS Arm/Linux captures passed bounded integrity and result
review on 2026-09-08. These are project/operator-owned native correctness
observations, not independent cryptographic review, FIPS validation, CPU
admission, migration safety or machine-level side-channel qualification.

## Exact captured source

Both files report clean commit
`5c7ec3bd392776763a7ade6a5d14011751bc9cdc`, Rust 1.98.1, compiler commit
`48a229ceaefd4985c50990b14116b6d856af0985` and LLVM 22.1.8. Their complete
158-entry source maps match the reviewed checkout exactly. Attribute the
observations to that commit, not later evidence/documentation commits.

The owner ran the Mac capture locally; no remote Mac access occurred. Its
reported compiler host is `aarch64-apple-darwin`. The capture checks Apple M2
identity and NEON, SHA512 and SHA3 feature indicators before execution.

The authorized AWS guest reported Neoverse-V1, two CPUs and approximately 4 GB
RAM, with ASIMD, SHA512 and SHA3 on every enumerated CPU. The run used a fresh
HTTPS checkout of the exact commit, native `aarch64-unknown-linux-gnu` Rust,
locked offline fixture dependencies, two build jobs and a detached runner.
The capture and runner exited zero, and the checkout remained clean. No QEMU
runner was used. Provider and feature observations are not authenticated
hardware attestations or guarantees about future scheduling/VM migration.

| Lane | Original JSON SHA-256 | Result |
| --- | --- | --- |
| [Apple M2](apple-m2-aarch64.json) | `c987f458c0607cec4e0f4d11b9d660c343f67a362be7265289775d40aac35485` | PASS |
| [AWS Arm](aws-aarch64.json) | `1fb9fbd4e32de525bbf89ca707f4ed42e94e4b9d196325bd9db33fc571b3b9df` | PASS |

Original bytes are preserved unchanged. The downloaded AWS file also matches
the checksum printed by the remote runner. JSON contains no private hostnames,
server addresses, login paths or credentials; setup logs remain local only.

## Execution and integrity review

Each native capture ran both debug and release profiles with:

- All 510 valid parameters and 4590 frozen independent vector cases through
  ordinary byte/bit one-shot and irregular streaming CPU APIs.
- Normal-build rejection, even with target features enabled; private evidence
  configuration is confined to the repository's assurance campaign.
- Injected failed-KAT quarantine in disposable copied sources, rejection by
  each new operation, preservation of state on a rejected update and rejection
  of positive acceptance after the injected failure.
- Five representative t values, 32 operations each on 16 KiB public input,
  with positive bounded elapsed-time rows and portable output comparisons.

Local import review rejected duplicate JSON keys, extra/missing fields, wrong
commit/compiler/target/lane, altered or missing source hashes, incomplete
debug/release transcripts and false admission/review/FIPS flags. Eight corrupted
variants per capture confirmed rejection of commit, claim, control, coverage
and source-map changes. All reported source hashes were recomputed; these
checks establish consistency, not independent execution provenance.

The native command does not run the separate compiled portable-fallback mutant
campaign; that control was exercised under QEMU and in the supplied SAST review.
It does not run full Miri/Kani, statistical constant-time analysis or physical
side-channel testing. No measured executable archive/hash or authenticated
runner attestation is included in this JSON schema. Timing rows are exploratory
observations, not a speedup or cross-platform performance claim.

## Reproduction and disposition

Use a clean checkout of the captured commit and the
[native capture instructions](../../../docs/sha512-t-cpu-evidence.md).
Verify these archived bytes with:

```sh
sha256sum assurance/sha512-t-observations/v0.24.29/*.json
```

Both native correctness dispositions are accepted for the scoped ordinary
CPU-wrapper evidence. All backends remain unadmitted; hardened states remain
portable-only. x86 has no SHA-512 candidate in this milestone, and RISC-V Zknh
remains QEMU-only. The planned opt-in usability work is a separate later chain.
Collection does not authorize a tag: final release checks, green GitHub/CodeQL
and explicit owner permission still follow the normal workflow.
