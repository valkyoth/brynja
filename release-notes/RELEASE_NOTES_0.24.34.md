# Brynja v0.24.34

Status: in progress; not ready for pentest, tag or publication.

## Verification workflow first

- Select expensive repository, compiler-matrix, sanitizer, Miri, Kani and
  native/QEMU campaigns by changed inputs and affected consumers.
- Explain selected and reused suites; retain a cheap repository-wide baseline.
- Stop an uncertain scope before expensive execution. Correct the classification
  or obtain explicit owner approval for the exact plan fingerprint.
- Keep full public crates.io checkpoints automatic. An unapproved uncertain
  scope is incomplete verification, never a successful or skipped release gate.
- Include SHA-2's nested consumer and disabled optional-dependency lock subsets
  without accepting changed package pins or unknown edges.
- Bind approval to the commit, baseline, changed inputs and build/verifier
  environment; reject stale tokens and unreviewed compiler/analysis overrides.

## Workflow-pass verification

Planner and dispatcher regression tests, selected/full Miri shell traces,
selected/full Kani shell traces, semantic dependency-scope negative fixtures,
repository policy tests, workspace native tests, Clippy, documentation and SBOM
checks passed. Unchanged cryptographic Miri/Kani/sanitizer campaigns were not
rerun for this tooling-only pass. This is not the final v0.24.34 release check.

## Remaining implementation

SHA-2 hardened accelerated owners remain pending. The workflow work does not
enable secret-bearing CPU execution, change any cryptographic implementation,
or satisfy that milestone's implementation/acceptance requirements.

The facade advances to 0.24.34; support versions and dependency pins remain
unchanged. All publication flags remain false; the next public checkpoint is
v0.25.2. Independent cryptographic verification and FIPS validation stay absent.
