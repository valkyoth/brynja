# v0.24.17 Native SP 800-185 Observations

These are non-authorizing execution observations, not CPU-backend admission,
independent cryptographic verification, FIPS validation or full release approval.
All reports retain their original `PENDING_REVIEW` field; the review below
checks capture integrity and observed results, not a hardware attestation.

## Source and execution

Both AWS hosts ran the exact clean commit
`f264a0351d4f8d86d056e7582986a297aee50672` with Rust 1.98.1. The authorized SSH
sessions observed Linux x86_64/GenuineIntel and Linux AArch64, respectively.
The Intel CPU identified as Xeon Platinum 8488C with AVX2; ARM advertised
ASIMD and SHA3. These are guest/OS-reported capabilities, not proofs of
heterogeneous-CPU migration safety. Neither run used a QEMU user-mode runner.

Fresh isolated directories were populated from a locally verified Git bundle.
The existing pinned compiler was installed where absent and the locked
dependency cache warmed. Native capture then ran offline. Both detached runners
exited 0; both checkouts remained clean at the same commit afterward. Host
addresses, login names, SSH-key information and installation logs are not archived.

The owner supplied the Apple M2/macOS arm64 report from the same f264a03
commit and Rust 1.98.1. Remote Mac access was not used; its native execution
is operator-attested, not independently witnessed. The initial offline attempt
could not resolve the pinned sanitization 2.0.4 in the local Cargo cache.
After the locked dependency fetch, the owner supplied a complete offline
capture. No dependency upgrade or source change was required. The original
JSON bytes are preserved; no hostname, login or absolute home path appears.

Local AMD evidence was recollected in a clean isolated clone of that same
f264a03 commit on Linux x86_64/AuthenticAMD (Ryzen 9 9950X3D). The complete
offline capture passed, the clone remained clean, and the original bytes are
archived. This replaces reliance on the earlier unarchived c58711b observation;
all four current reports bind the same source, compiler and capture policy.

| Lane | Raw report SHA-256 | Observation |
| --- | --- | --- |
| [AWS Intel](aws-intel-x86_64.json) | `5f117a4ebb335ba851aeebd1e86f4d8a2f76549d87e8396051c04ea2451e3897` | PASS |
| [AWS AArch64](aws-aarch64.json) | `8342c79bbd072fd9464bf3ff41985b5b85a6751c62ade03b3cba09a4d90bdf4a` | PASS |
| [Apple M2](apple-m2-aarch64.json) | `350c71198e7d9e0bbe4ee65ffaad44eddfca29aeb83b0496276321c1f7bb99b8` | PASS |
| [Local AMD](local-amd-x86_64.json) | `aa2de185349d2aa8a7cfa3a8bad9888b5c86b88e3de73d4c51972b857f6eb05c` | PASS |

## Review performed

- Matched AWS remote report checksums with the downloaded, unmodified JSON
  bytes; hashed the owner-supplied Mac file and preserved it byte-for-byte.
- Rejected duplicate JSON keys during review; checked exact schema fields,
  source commit, compiler, lane/architecture, commands and policy hash.
- Recomputed all four stdout hashes and checked zero backend admissions.
- Verified 540 parallel comparisons, 24 bounded failure cases, six worker-fault
  tests, three conditional Keccak KAT tests and twelve distinct benchmark rows.
- Rechecked the first/last tag-mismatch timing ratios against the 1.250 bound.
  Intel observed 271127/270789 ns; AWS ARM observed 335324/326317 ns;
  Apple M2 observed 202085/200586 ns; AMD observed 163459/178468 ns.
- Confirmed every benchmark measured positive durations and compared exact
  outputs before reporting success. Threaded execution was slower than
  sequential execution for these 16 KiB samples; no speedup claim is made.

The candidate tests are conditional on runtime feature detection; a green
summary alone cannot establish instruction execution. Guest CPU flags, this
bounded timing heuristic and signed source commits do not establish a trusted
runner, general constant-time behavior, keyed acceleration cleanup or backend
admission. The archived reports remain separate from formal CPU evidence.

All four native observations pass the report integrity/result review. RISC-V
has no Keccak accelerated candidate; no native RISC-V SP 800-185 run is claimed
for this milestone. Its explicit disposition is portable-only, with native
coverage unavailable here and qualifying acceleration deferred. Supplemental
RISC-V SHA-2 QEMU results do not establish native SP 800-185 execution.

The required local release checks also passed; see the
[final closure checklist](../../../docs/sp800185-final-acceptance.md).
SP 800-185 is **Fully implemented**, with independent verification, FIPS
validation and CPU admission unchanged. Green GitHub/CodeQL and explicit tag
authorization remain outstanding. This archival/documentation update does not
change the assessed Rust code or the capture fixture. Later comparisons must
bind these reports to f264a03, not silently attribute them to a newer commit.
