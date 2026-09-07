# v0.24.22 MD5 native observations

Collection is partial: local AMD and both AWS lanes passed; the owner-operated
Apple M2 capture is still pending. These are non-authorizing execution
observations, not independent cryptographic review, FIPS validation, CPU
migration-safety evidence, secret-SIMD cleanup qualification or release approval.
Both MD5 backends remain unadmitted and hardened batches remain portable-only.

## Exact source and execution

All three captures ran the clean commit
`95d1d6b56282621e742b425aa08988d9568d3e84` with Rust 1.98.1, compiler commit
`48a229ceaefd4985c50990b14116b6d856af0985`. Do not attribute these observations
to later commits. The archive adds records only; it changes no captured source.

The local machine reported AMD Ryzen 9 9950X3D with AVX2. The authorized Intel
AWS guest reported Xeon Platinum 8488C, two vCPUs and AVX2. The authorized Arm
AWS guest reported Neoverse-V1, two vCPUs and ASIMD/NEON. These are OS/guest
observations, not authenticated hardware attestations. No QEMU user-mode runner
was used for these native executions.

Fresh dedicated AWS checkouts fetched the exact commit over HTTPS. Rust 1.98.1
and compiler prerequisites were installed; locked dependency fetching primed
the cache before offline capture. Both remote commands exited zero and both
checkouts remained clean. Host addresses, login names, keys and installation
logs are not included in this archive.

| Lane | Original JSON SHA-256 | Result |
| --- | --- | --- |
| [AMD](amd-x86_64.json) | `e092daaba7b38affb472e1dd888d826a5f9e3ff815bf8800b25949ac48f787ca` | PASS |
| [AWS Intel](intel-x86_64.json) | `a3d365099bf401081f2e140ddeb48e98acbe777cdb2ed21edb420e7e768e3798` | PASS |
| [AWS Arm](aws-aarch64.json) | `82204c471391acf0a264855a75d153b8e7774e42c1ce7bf86425a23d767c3ce3` | PASS |
| Apple M2 | Not yet supplied | Pending |

## Checks and result review

Each capture passed all twenty frozen legacy corpus cases, 936 mixed-length,
bit-tail and active-mask batch comparisons, sixteen lane permutations and all
nine bounded benchmark rows. The required backend identity and actual vector
block counts were checked; requesting a backend alone does not establish use.
Additional native tests passed on each of the three hosts:

- Five CPU kernel/session groups, including arbitrary-state/block differential,
  KAT fault, lost-feature quarantine, lane ordering and cancellation atomicity.
- One ordinary-build production-rejection test, without evidence keys.
- One host-adapter test confirming observational selection and required-mode
  rejection.

The downloaded AWS JSON and three test logs per host matched their remote
SHA-256 values. Review rejected duplicate JSON keys, required the exact schema,
commit, compiler and field values, recomputed every source hash from the
captured Git commit, and checked the complete nine-row benchmark matrix and
positive durations. The original JSON bytes are preserved without rewriting.
All files were checked for hostname, login-path and server-address disclosure.
Raw auxiliary logs remain local under `target/md5-native-v0.24.22/`; their
successful results are summarized here, not promoted to hardware attestation.

Full-width 16 KiB batches were faster through the candidate on these observed
runs; single/incomplete groups remain scalar. The measurements are exploratory
elapsed-time observations, not stable throughput promises or a constant-time
test. They do not establish general performance, migration-safe feature
authority, register/spill erasure or secret-bearing acceleration safety.

Apple M2 collection and the final release review remain outstanding. AVX-512
and RISC-V Vector have no implementation in this milestone; no native evidence
for either is claimed. The existing scalar fallback and admission restrictions
remain unchanged.
