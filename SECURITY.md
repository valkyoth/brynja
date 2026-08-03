# Security Policy

Brynja is security-sensitive protocol, cryptographic, PKI, platform, and
release infrastructure. Releases through version 0.3.3 are planning and
scaffolding evidence only and are not supported for securing traffic.

## Routine Checks

```bash
scripts/checks.sh
scripts/check-rust-version-matrix.sh
scripts/check_latest_tools.sh
python3 scripts/check-protocol-surfaces.py
python3 scripts/check-requirements.py
cargo deny check
cargo audit
scripts/generate-sbom.sh --check
```

GitHub CodeQL Default setup should be enabled. Do not add an advanced CodeQL
workflow while Default setup is active.

## Tag And Release Gates

Every completed roadmap version passes the complete automated tag gate in a
signed commit, waits for green GitHub and CodeQL, and receives an immutable
signed tag only after explicit user authorization. Development milestones
between public checkpoints require no scheduled pentest report and publish no
crate.

Every scheduled or exceptional public checkpoint requires one matching
permanent report at `security/pentest/vX.Y.Z[-rc.N].md`. The report's
`Baseline` is the preceding public tag, and `Scope` names the backwards-looking
change range from that tag through the current candidate. Thus v0.15.0 reviews
all changes after v0.10.0 through v0.15.0; v0.20.0 reviews all changes after
v0.15.0 through v0.20.0. The report is kept current throughout findings,
fixes, and retests, and the implementation and PASS report may be committed
together.

That candidate commit is pushed and allowed to complete GitHub CI. If CI
requires a change, the code and report are updated and committed together, then
CI runs again. The public-checkpoint tag is created only after the user
explicitly confirms that GitHub and CodeQL are green. The gate requires a clean worktree, a report committed at
`HEAD`, `Status: PASS`, `Open-Findings: 0`, and `Retest: PASS`. Once a report
exists, a later repository-changing commit is rejected unless it also updates
the report.

Ordinary CI may validate a current committed remediation candidate with
`Status: RETEST REQUIRED`, `Open-Findings: 0`, and `Retest: PENDING`. This
state allows the checks needed before external retest to become green but is
not release authorization. The dedicated public release path always uses the
strict PASS gate. An off-cycle security assessment may add a report to a
development milestone, but does not itself authorize crates.io publication or
replace the next cumulative checkpoint assessment.

The report format and disclosure rules are documented in
[`security/pentest/README.md`](security/pentest/README.md).

## Security Change Classification

Commit subjects must describe the artifact that changed. A subject beginning
with `fix:` or presenting itself as a pentest-code remediation is reserved for
a commit that changes `crates/**/*.rs`. Documentation, standards,
requirements, evidence, release-governance, tests, and tooling-only changes
use an accurate `docs:`, `chore(scope):`, or `test(scope):` subject even when
they close a pentest finding. The permanent pentest report records the finding
and result without turning a traceability or policy correction into an implied
shipped-code security fix.

Signed historical release commits are not rewritten. This classification
policy applies prospectively, and any historical ambiguous subject is
disclosed in the owning permanent pentest report. The local and CI checks
enforce this classification against each new `HEAD`.

## Dependency Policy

Third-party Cargo crates are forbidden. A future exception requires a dedicated
adapter package, current-version, license, maintenance, and security review,
explicit features, no hidden std or native-code expansion, adversarial tests,
SBOM and policy evidence, a replacement plan, and a versioned audit gate.

## Reporting

Do not publish exploitable details before a fix is available. Use GitHub private
vulnerability reporting or the repository's private security channel.
