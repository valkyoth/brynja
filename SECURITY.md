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

## Release Gate

Every release requires one matching permanent report at
`security/pentest/vX.Y.Z[-rc.N].md`. When implementation stops, the user
pentests the release candidate and the report is kept current throughout
findings, fixes, and retests. The implementation and PASS report may be
committed together.

That candidate commit is pushed and allowed to complete GitHub CI. If CI
requires a change, the code and report are updated and committed together, then
CI runs again. The tag is created only after the user explicitly confirms that
GitHub is green. The gate requires a clean worktree, a report committed at
`HEAD`, `Status: PASS`, `Open-Findings: 0`, and `Retest: PASS`. Once a report
exists, a later repository-changing commit is rejected unless it also updates
the report.

Ordinary CI may validate a current committed remediation candidate with
`Status: RETEST REQUIRED`, `Open-Findings: 0`, and `Retest: PENDING`. This
state allows the checks needed before external retest to become green but is
not release authorization. The dedicated release and tag paths always use the
strict PASS gate.

The report format and disclosure rules are documented in
[`security/pentest/README.md`](security/pentest/README.md).

## Dependency Policy

Third-party Cargo crates are forbidden. A future exception requires a dedicated
adapter package, current-version, license, maintenance, and security review,
explicit features, no hidden std or native-code expansion, adversarial tests,
SBOM and policy evidence, a replacement plan, and a versioned audit gate.

## Reporting

Do not publish exploitable details before a fix is available. Use GitHub private
vulnerability reporting or the repository's private security channel.
