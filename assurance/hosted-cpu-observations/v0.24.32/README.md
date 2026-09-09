# v0.24.32 hosted CPU native observations

Project/operator-owned native checks completed on 2026-09-09 against
reviewed commit `0c6cee491a525106a8ac4a328b8f9d8cfc11a0d2`.
The owner supplied a clean SAST retest of signed v0.24.31 through that commit.
No production source, dependency, feature or backend admission changed during
collection. These observations are not independent verification or certification.

| Lane | Reported CPU | Hosted raw kernels | Disposition |
| --- | --- | --- | --- |
| Apple macOS ARM64 | M2, owner-labelled | 3 | Native Arm SHA-256, SHA-512 and Keccak execution passed |
| AWS Arm Linux | Neoverse-V1 | 3 | Native Arm SHA-256, SHA-512 and Keccak execution passed |
| AWS Intel Linux | Xeon Platinum 8488C | 0 | Required rejection and preferred portable fallback passed |
| Local AMD Linux | Ryzen 9 9950X3D | 0 | Required rejection and preferred portable fallback passed |

All four used Rust 1.98.1, compiler commit
`48a229ceaefd4985c50990b14116b6d856af0985`, LLVM 22.1.8 and
`scripts/cpu/check-hosted-execution.py`. The Mac used Python 3.13. The checker
ran extracted-package debug/release consumers, CPU/hosted tests, strict fixture
Clippy, feature-off import rejection, ten raw-input classification negatives and
fourteen compiled lifecycle/selection regressions. This command did not use
QEMU, evidence cfgs or injected target features. It is not the separate QEMU
operational no-op/KAT mutation campaign, timing analysis, Miri or Kani.

Both AWS guests had two CPUs and approximately 4 GB RAM. Their initial attempts
failed before tests because `cc` was missing. Standard system build tools were
installed, then clean-source retries completed with exit status zero and the
final `NATIVE_CAPTURE: PASS` marker. The linker prerequisite does not introduce
a foreign cryptographic implementation. Remote and downloaded retry-log hashes
matched. Neither failed attempt counts as PASS evidence.

The Mac was run locally by the owner; no remote Mac access occurred. Its short
log has the complete five-line checker summary. Exact commit, architecture and
compiler output were supplied separately in the conversation. There is no
captured Mac process exit status or whole-worktree cleanliness output,
measured-binary archive or authenticated runner
attestation. The printed final mutation summary is reached only after the
preceding positive checks, but the summary does not independently attest execution.

[observations.json](observations.json) preserves privacy-filtered summaries,
compiler/CPU metadata, original local-log checksums, and the exact source map
checked at collection. The map and review-manifest digest refer to **0c6cee49**,
not subsequent documentation/evidence commits. Imported source hashes were
recomputed against that checkout. Full AWS/local logs stay gitignored under
`target/hosted-cpu-native-v0.24.32`; private login paths and host details are not
included in this archive. These are derived records, not unchanged original logs.

## Limits and release disposition

The collection step is complete for these four lanes. It does not prove behavior
under heterogeneous scheduling, CPU hotplug, hypervisor migration or a defective
OS. The platform feature-ABI assumptions in the hosted contract remain necessary.
No side-channel validation, independent cryptographic review, FIPS validation,
register/spill erasure or hardened execution is established. PublicData remains
a caller classification, not proof that bytes are non-secret. Intel/AMD fallback
does not demonstrate acceleration on those platforms, nor change static support.

Final local release checks, green GitHub/CodeQL and explicit owner tag approval
are still required. This internal milestone publishes no crates.
