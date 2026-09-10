# Brynja Script Inventory

The script tree is part of Brynja's security and release boundary. Scripts are
grouped by the capability or assurance domain they own so reviewers can find a
complete check, policy, fixture driver, and regression suite without searching
one growing flat directory.

Only two executable entry points live directly in this directory:

- `scripts/checks.sh` runs impact-selected expensive checks and the cheap repository baseline.
- `scripts/tag_gate.sh vX.Y.Z` adds tag-only, online, matrix, SBOM, release,
  impact-selected local Miri, AddressSanitizer, and required local proof gates.

Start with `python3 scripts/release/run-verification.py plan --check`. Uncertain
scope stops before expensive work and requires owner approval tied to the exact
plan; public checkpoints still run everything. See [focused assurance](../docs/focused-assurance.md).

The repository gate first runs `cargo fetch --locked` to prepare the exact
workspace dependencies for its offline package consumers. Even a dependency-free
leaf can trigger workspace lockfile resolution during packaging. Run
`python3 scripts/repository/test-offline-bootstrap.py --cold-cache` to reproduce
the missing-cache failure and verify the locked bootstrap with a fresh Cargo
home; ordinary CI runs only the cheap ordering/lock regression tests.

`inventory.toml` is the machine-readable directory register.
`repository/check-script-layout.py` rejects unknown root files, unknown or
nested categories, duplicate basenames, missing categories, and unsupported
file types. `repository/check-tracked-build-artifacts.py` rejects every tracked
file beneath a Cargo `target/` directory, regardless of workspace depth.

## Evidence-build environment safety

Evidence cfgs belong only to individual dedicated script invocations. Never
export `brynja_cpu_evidence` or `brynja_sha1_cpu_evidence` flags into persistent
shell/workspace/CI environments: Cargo propagates compiler flags to dependencies.
Do not deploy evidence binaries. Legacy SHA-1 additionally requires the opt-in
`cpu-evidence` feature and its own cfg; `cpu`, all features, or the shared cfg
alone never admit it. `cfg(test)` is not an admission key either: executable
SHA-1 kernel tests use the same two-key gate. See
[contributor guidance](../.github/CONTRIBUTING.md).

## Directories

`cpu/check-acceleration-availability.py` validates the v0.24.30 contract-only
kernel/family inventory. Its companion tests compile selection-model mutants;
they do not execute or authorize CPU kernels. See the
[availability contract](../docs/acceleration-availability.md).

`cpu/check-static-execution.py` tests the opt-in raw static authority from
normal extracted packages, including default-off imports and compiled failure
mutants. `--native-x86` requires the operator to confirm the SHA/AVX2 platform
contract; `--qemu` adds supplemental Arm execution. See the
[static execution contract](../docs/static-cpu-execution.md). The dedicated
Miri group is `scripts/zeroization/check-zeroization-miri.sh --group static_cpu`.

| Directory | Ownership |
| --- | --- |
| `assurance/` | Shared bounded runners, mutation and differential harnesses, bare-metal checks, and Kani orchestration |
| `ci/` | Rust-version and pinned CI-tool installation and freshness checks |
| `constant-time/` | Constant-time source, emitted-code, evidence, and regression checks |
| `cpu/` | Reusable CPU capability, admission, dispatch, evidence, and runner infrastructure |
| `cryptography/` | Cross-algorithm API-profile, secret-state closure, and composition checks |
| `foundations/` | Provider, entropy, clock, pending-operation, FIPS-state, security-outcome, and security-event contracts |
| `hash/` | Cross-family hash final acceptance and closure policy |
| `legacy-hash/` | Frozen SHA-1/MD5 consumer, final batch/lifecycle acceptance, historical native-source bindings and isolated implementation claims |
| `pki/` | DER and canonical ASN.1 policy and regression checks |
| `protocols/` | Protocol framing and state-machine assurance scripts |
| `release/` | Explicit closing-patch checkpoint register, release selection, pentest freshness, SBOM, GitHub controls, and historical release gates |
| `repository/` | Workspace, source, documentation, shell, cryptography-origin, status, and script-layout policy |
| `sanitization/` | Sanitization dependency admission and optimized-code checks |
| `sha1/` | Isolated legacy SHA-1 portable/CPU policy, differential, package, compiler, QEMU and native-capture checks |
| `sha2/` | SHA-2 source policy, public acceptance, CPU code generation, QEMU, and native capture scripts |
| `sha3/` | SHA-3/SHAKE source policy, differential evidence, and frozen public acceptance scripts |
| `sp800185/` | Combined portable and hosted SP 800-185 acceptance, parallel execution comparisons, frozen-contract policy and reviewed native capture |
| `tuplehash/` | TupleHash/TupleHashXOF source policy, mutation, package, and differential evidence |
| `standards/` | RFC/local authority lifecycle observation, protocol surfaces, and normative requirement generation and validation |
| `zeroization/` | First-party zeroization source, compiler-artifact, stage-aware local pre-tag Miri, and sanitizer evidence |

Algorithm-specific scripts stay with their algorithm. Reusable machinery does
not: for example, SHA-2 instruction checks belong in `sha2/`, while CPU feature
authority and evidence-bundle validation remain in `cpu/` so SHA-3, AES, and
later implementations use one reviewed mechanism.

## Adding Or Moving A Script

General SHA-512/t value/IV checks are in `sha2/check-general-sha512-t.py`
and `sha2/test-general-sha512-t.py`. The independent prime-root IV oracle is
`sha2/sha512_t_iv_oracle.py`; `--write` deliberately refreshes its fixed corpus
for review, while normal invocation compares it. These are parameter/public
digest and IV checks, not evidence for the future general message hasher.


1. Choose the owning directory in `inventory.toml`; add a new category there
   first if the responsibility is genuinely distinct.
2. Keep helper modules beside the checks that import them. Do not create a
   second implementation of shared assurance logic inside an algorithm folder.
3. Update `checks.sh`, `tag_gate.sh`, workflows, documentation, policy hashes,
   evidence indexes, and every internal caller in the same commit.
4. Preserve historical pentest reports: paths recorded in an old report describe
   the reviewed historical commit and are not rewritten.
5. Run `python3 scripts/repository/check-script-layout.py`,
   `python3 scripts/repository/test-script-layout.py`, and `scripts/checks.sh`.

Moving a file does not by itself change a cryptographic result, but path-bound
policy and evidence must be refreshed. If implementation code or fixture
semantics change during a move, all affected cryptographic evidence must be
rerun under the normal exact-commit rule.

## Miri Profiles And Future Sharding

Every internal tag runs one bounded Miri smoke case for each registered group
and the complete suite for every group affected by changes since the previous
signed tag, including downstream groups. Semantic dependency changes select
affected consumers; local version/hash-binding-only changes do not invalidate
unchanged implementations. Unknown runtime/compiler impact fails closed to the
full suite. Every public stage that can publish to crates.io always runs all
groups. See [focused assurance](../docs/focused-assurance.md) for exact rules.

The current groups are `core`, `sanitization`, `sha2`, `sha3`, `kmac`,
`tuplehash`, `parallelhash`, `sha1`, `md5`, `legacy`, `acceleration`
(the isolated, dependency-free contract model), and `static_cpu`
(the raw static authority lifecycle and downstream fixture).
`zeroization/check-zeroization-miri.sh --group GROUP` is a shard entry point so
the groups can later run concurrently on isolated headless workers. Shard
results are not yet accepted by the tag gate: a future aggregator must bind
every result to the same commit, pinned Miri toolchain, group inventory, runner
hash, configuration, and successful exit before distributed evidence can
replace the local complete run. Missing, duplicate, stale, or mixed evidence
must fail closed.

The v0.157.0 assurance milestone will adapt `base64-ng`'s existing operator
model: an ignored SQLite session records detached local and SSH job state,
supports progress checks and retries, clones the exact clean commit remotely,
retrieves each result, and unlocks aggregation only after local validation.
That database is orchestration state, never evidence; exact-source bundles and
the complete validated aggregate are the release boundary.

MD5 batch/SIMD assurance is grouped under `scripts/md5/`: the `check-md5-cpu.py`
entry point runs production rejection, packaged batch consumers and native-capture
regressions. `check-md5-cpu-qemu.sh` and `check-md5-cpu-codegen.sh` cover forced
Arm correctness and compiler endpoints. `capture-md5-cpu-native.py` collects
exact-commit non-authorizing native observations. Never persist
`--cfg brynja_md5_cpu_evidence` or deploy its evidence binaries.
