# Brynja Script Inventory

The script tree is part of Brynja's security and release boundary. Scripts are
grouped by the capability or assurance domain they own so reviewers can find a
complete check, policy, fixture driver, and regression suite without searching
one growing flat directory.

Only two executable entry points live directly in this directory:

- `scripts/checks.sh` runs the ordinary complete repository gate.
- `scripts/tag_gate.sh vX.Y.Z` adds tag-only, online, matrix, SBOM, release,
  stage-aware local Miri, full AddressSanitizer, and required local proof gates.

`inventory.toml` is the machine-readable directory register.
`repository/check-script-layout.py` rejects unknown root files, unknown or
nested categories, duplicate basenames, missing categories, and unsupported
file types. `repository/check-tracked-build-artifacts.py` rejects every tracked
file beneath a Cargo `target/` directory, regardless of workspace depth.

## Directories

| Directory | Ownership |
| --- | --- |
| `assurance/` | Shared bounded runners, mutation and differential harnesses, bare-metal checks, and Kani orchestration |
| `ci/` | Rust-version and pinned CI-tool installation and freshness checks |
| `constant-time/` | Constant-time source, emitted-code, evidence, and regression checks |
| `cpu/` | Reusable CPU capability, admission, dispatch, evidence, and runner infrastructure |
| `cryptography/` | Cross-algorithm API-profile, secret-state closure, and composition checks |
| `foundations/` | Provider, entropy, clock, pending-operation, FIPS-state, security-outcome, and security-event contracts |
| `hash/` | Cross-family hash final acceptance and closure policy |
| `pki/` | DER and canonical ASN.1 policy and regression checks |
| `protocols/` | Protocol framing and state-machine assurance scripts |
| `release/` | Release selection, pentest freshness, SBOM, GitHub controls, and historical release gates |
| `repository/` | Workspace, source, documentation, shell, cryptography-origin, status, and script-layout policy |
| `sanitization/` | Sanitization dependency admission and optimized-code checks |
| `sha2/` | SHA-2 source policy, public acceptance, CPU code generation, QEMU, and native capture scripts |
| `sha3/` | SHA-3/SHAKE source policy, differential evidence, and frozen public acceptance scripts |
| `standards/` | RFC/local authority lifecycle observation, protocol surfaces, and normative requirement generation and validation |
| `zeroization/` | First-party zeroization source, compiler-artifact, stage-aware local pre-tag Miri, and sanitizer evidence |

Algorithm-specific scripts stay with their algorithm. Reusable machinery does
not: for example, SHA-2 instruction checks belong in `sha2/`, while CPU feature
authority and evidence-bundle validation remain in `cpu/` so SHA-3, AES, and
later implementations use one reviewed mechanism.

## Adding Or Moving A Script

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
signed tag, including downstream groups. Root manifests, the lockfile, release
Rust, the zeroization matrix, or Miri-control changes fail closed to the full
suite. Every public stage that can publish to crates.io always runs all groups.

The current groups are `core`, `sanitization`, `sha2`, `sha3`, and `kmac`.
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
