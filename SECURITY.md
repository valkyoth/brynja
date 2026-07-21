# Security Policy

Brynja is security-sensitive protocol, cryptographic, PKI, platform, and
release infrastructure. Version 0.1.0 is scaffolding only and is not supported
for securing traffic.

## Routine Checks

```bash
scripts/checks.sh
scripts/check-rust-version-matrix.sh
scripts/check_latest_tools.sh
cargo deny check
cargo audit
scripts/generate-sbom.sh --check
```

GitHub CodeQL Default setup should be enabled. Do not add an advanced CodeQL
workflow while Default setup is active.

## Release Gate

Every release requires a matching permanent PASS report under
`security/pentest/` naming the exact reviewed commit. The implementation
stops before pentest; findings are fixed and all evidence rerun before the
report commit. Tags and publishing occur only when explicitly requested.

## Dependency Policy

Third-party Cargo crates are forbidden. A future exception requires a dedicated
adapter package, current-version, license, maintenance, and security review,
explicit features, no hidden std or native-code expansion, adversarial tests,
SBOM and policy evidence, a replacement plan, and a versioned audit gate.

## Reporting

Do not publish exploitable details before a fix is available. Use GitHub private
vulnerability reporting or the repository's private security channel.

