# v0.24.49 native runtime evidence

Collected after the two owner-supplied retests, reviewed for exact source,
compiler, execution-route, count and successful-exit consistency. These are
project-owned functional observations, not independent cryptographic review,
FIPS validation, side-channel proof or whole-process register erasure.

| Host | Capture identity | Scope |
| --- | --- | --- |
| Linux AMD Ryzen 9 9950X3D | `7a9e9cc6d309d2b0e447498f340fd26a095e2866` | Nine fresh local captures, including hardened batches, SHA-2/Keccak/KMAC/TupleHash/ParallelHash and legacy records; modern index x86 lane |
| Linux Intel Xeon 6975P-C | `32d2a88a91ebcca35a1d430644a77fbd6f6ae593`, resumed at `7a9e9cc6d309d2b0e447498f340fd26a095e2866` | Six earlier modern captures preserved without relabelling; resumed SHA-1/MD5 and strict portable/accelerated packaged tests |
| Linux Arm Neoverse-V2 | `7a9e9cc6d309d2b0e447498f340fd26a095e2866` | Nine native captures; strict portable/accelerated packaged tests and facade tests |
| Apple M2 Pro | `7a9e9cc6d309d2b0e447498f340fd26a095e2866` | Nine native captures; strict unsupported-platform rejection |
| Windows Server 2025, Xeon 6975P-C | `7a9e9cc6d309d2b0e447498f340fd26a095e2866` | 60 successful MSVC collection steps; workspace/native kernels, batch and legacy tests, independent differential comparisons, package negatives/mutants and strict rejection |

All use Rust 1.98.1. Current indexed modern lanes use the same `7a9e9cc6`
capture commit. The Intel supplement remains at its original capture identities;
no production crate, manifest or lockfile changed between its two commits.
The existing family-native indexes point to the new raw JSON records. Their
historical schema version numbers and path prefixes remain unchanged by design.

## Additional retained records

The four hardened-batch runtime records are retained separately for
[AMD](../hardened-batch-native/amd-x86_64-v02449.json),
[Intel](../hardened-batch-native/intel-x86_64-v02449.json),
[Arm Linux](../hardened-batch-native/aws-aarch64-v02449.json) and
[Apple M2](../hardened-batch-native/apple-m2-aarch64-v02449.json).
All four pass the existing runtime-capture schema and result validator.

- [Intel Linux supplement](intel-linux-supplement.tar.gz): SHA-256
  `3aadc10d00fc29e42f70b408d0600e5c887368e553bdaec830f9043a519ef108`.
- [Arm Linux strict tests](arm-linux-strict.tar.gz): SHA-256
  `90bae357c366ed13a17bf3ba5c599efecffbfc02c93f195991f93f0b67966182`.
- [Windows MSVC runtime](windows-msvc-runtime.tar.gz): SHA-256
  `4acdf5e08d995aab91f6b06e25924997edddf0e3df0e35f8489f5c3160faba4b`.
  Its `steps.json` records each command, flags, exit code and log SHA-256;
  all 60 log hashes were validated after download. This is a Windows-specific
  runtime record, not a substituted Linux capture or a new release gate.

Both Linux strict package campaigns reject 79 export/ownership probes and 16
accelerated cleanup/output/quarantine mutants, with debug/release adapter tests.
Windows packaged batching rejects 43 compiled mutants, 137 ownership probes
and 16 substitution/conversion probes. ParallelHash comparisons exercise one,
two and three workers and four scheduled/streaming layouts in all three modes.

The initial Arm run stopped before collection on an invalid feature spelling in
the temporary CPU probe; the corrected resumed run passed. Intel's first run
stopped at the stale SHA-1 result-count check; its corrected resumed run passed.
Failed attempts are not positive evidence. Raw logs retain their context.

## Limits and next steps

Native dedicated x86 SHA512 is **not** qualified: Intel and AMD feature probes
reject that capability. SDE remains the dedicated-instruction execution lane.
Apple and Windows reject strict protected sessions; Windows support is planned
for v0.24.50 and macOS for v0.24.51. Ordinary/scoped native success does not
silently expand the strict protected-platform set.

Original capture claims such as `owner_review=pending` or no register-erasure
claim remain untouched: this review accepts native functional consistency only.
The [pentest ledger](../../security/pentest/v0.24.49.md) separately records F1's
opaque-kernel emitted-code closure and retained caller/platform limitations.
Final release verification and GitHub approval remain required before tagging.
