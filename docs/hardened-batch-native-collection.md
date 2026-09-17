# Hardened multibuffer runtime collection

The standalone collector runs existing v0.24.48 development checks sequentially
on one native lane. It does not add or change a release/tag gate, admit a backend,
approve a pentest, or replace the existing release workflow.

Supported lanes are `amd-x86_64`, `intel-x86_64`, `aws-aarch64` and
`apple-m2-aarch64`. The operator must establish native execution and stable CPU
capabilities. CPU enumeration checks the complete AVX/AVX2 or NEON bundle; it is
not a live-migration monitor or independent cloud-provider authentication.

From a clean committed checkout, inspect the plan without running it:

```sh
python3 scripts/cryptography/capture-hardened-batch-native.py amd-x86_64 target/hardened-batch-runtime.json --list
```

For collection, use the matching lane and a new output path:

```sh
python3 scripts/cryptography/capture-hardened-batch-native.py amd-x86_64 target/hardened-batch-runtime.json --attest-native
```

Use Python 3.11 or newer and Rust 1.98.1. Prepare locked dependencies for the
workspace and the `hardened-sha256-batch`, `hardened-sha512-batch`,
`hardened-keccak-batch`, `parallelhash-batch-oracle` and `hardened-batch-bench`
fixtures before collection; execution stays offline. Use an otherwise idle host.
Do not edit the checkout or run competing benchmarks during the capture.

Fourteen steps cover:

- Six feature-owning crates' optimized native library suites, with required
  SIMD switches, exact named passing tests and actual Keccak execution markers.
- Five independent-oracle drivers: narrow/wide SHA-2, Keccak, threaded and local
  scheduled/streaming ParallelHash; all portable/preferred/required campaigns.
- Two comparative timing drivers, retaining all workload rows and slower results.
- Extracted-package acceptance, ownership/conversion negatives and compiled
  cleanup/dispatch mutations.

The JSON retains each command, successful status and raw output, together with
the Git commit/tree, compiler/host, CPU description, feature bundle, Python
version and UTC start/end timestamps. Checkout and platform identity are checked
before and after execution. Known Cargo/Rust target/wrapper overrides and loader
overrides are removed; the repository, installed tools and on-disk configuration
remain trusted. This is not hostile-machine attestation or a signed receipt.

A command failure, timeout, missing/duplicated result, wrong route or changed
checkout prevents a completed artifact. Existing files are never overwritten.
The subprocess timeout is not a process-tree containment guarantee; after an
interrupted run, check for leftover build/test processes before collecting anew.

The record always says owner review is pending, native execution is operator
self-attested, and independent review/FIPS validation are absent. Miri, Kani,
sanitizers, the compiler-cleanup matrix and independent pentest are explicitly
outside this runtime bundle and retain their separate evidence requirements.
Do not treat one successful lane as complete v0.24.48 qualification.

Regression tests use synthetic records only:

```sh
python3 scripts/cryptography/test-hardened-batch-native.py
```
