# Brynja 0.24.17 Release Notes

Status: pentest, native observations and local release checks passed; awaiting green GitHub/CodeQL

## Summary

This internal milestone completes final SP 800-185 execution acceptance. It
reruns the unchanged v0.24.16 consumer contract, compares sequential,
caller-scheduled and optional std ParallelHash, and provides a bounded,
commit-bound native capture command. Production cryptographic source and CPU
admissions are unchanged. The facade advances to 0.24.17; no crate is published.

The SP 800-185 family is **Fully implemented** after final native dispositions
and local release checks passed. This is not a claim of independent review,
FIPS validation, accelerated keyed execution or secure TLS availability.

## Deliverables

- Preserve all eight v0.24.16 consumer Rust files and representative input;
  bind them separately from the updated facade-version Cargo metadata.
- Add a package-external hosted fixture with no registry or git dependency.
  Rerun fourteen identities, official examples and hardened profiles.
- Compare 540 ParallelHash outputs across all four identities, byte and bit
  inputs, sequential/caller-scheduled/threaded modes and bounded worker counts.
- Check 24 typed failure outcomes and unchanged public destinations. Retain
  existing injected launch/panic/join/cleanup executor tests for internal faults.
- Exercise four compiled corruption regressions in addition to frozen-source,
  report, lane, dirty-tree and compiler-override rejection tests.
- Run the hosted consumer on the CI OS lanes and twelve-version Rust matrix;
  keep bare-metal acceptance attached to the original no_std consumer.
- Add opt-in comparative benchmarks and privacy-minimized native JSON reports,
  always pending review, never automatically accepted as admission evidence.

## Verification and release handoff

Run `python3 scripts/sp800185/check-execution-acceptance.py` and
`python3 scripts/sp800185/test-execution-acceptance.py`. The full repository
gate retains official vectors, independent differential campaigns, KMAC/shared
cleanup codegen, package contents, source policies and dependency isolation.

See [the reproducible procedure and closure checklist](../docs/sp800185-final-acceptance.md)
for exact native commands, benchmark limitations and required dispositions.
The owner-supplied review of v0.24.16 through c58711b reports no Critical, High,
Medium or Low findings; the permanent pentest report records PASS. Separate
native reports and local release evidence also passed; those results are not
inferred from the security assessment. Green GitHub/CodeQL and explicit tag
authorization remain required.

- Four archived AMD, Intel, AWS ARM and Apple M2 observations bind the same
  f264a03 source, Rust 1.98.1 and original capture policy. Each passed 540
  comparisons, 24 failure cases, worker/candidate tests, twelve benchmark rows
  and the bounded tag-timing check. RISC-V has an explicit no-native-run limit.
- Complete repository, Rust 1.90.0–1.98.1, bare-metal, supplemental QEMU,
  official/differential, cleanup/codegen, standards, tooling and dependency
  checks passed. All seven full Miri groups, AddressSanitizer and 25 Kani
  proofs passed; remaining Miri groups ran in isolated parallel caches.
- Documentation/status policy now requires the completed family row while
  preserving independent-review/FIPS disclaimers. The frozen portable fixture
  and native captures keep their original pre-review status text.
- Correct misleading SHA-3 README prose: only implementation acceptance was
  completed at v0.24.11, not independent cryptographic review or FIPS validation.
- Publish-policy validation and dry-run select zero crates, including changed
  support crates. Published facade remains 0.20.0; internal facade is 0.24.17.

No new cryptographic primitive, secret owner, unsafe boundary, production
dependency, provider effect or backend integration is introduced. Existing
register/spill/cache/dump/swap/abort and caller-owned-copy limits remain.
