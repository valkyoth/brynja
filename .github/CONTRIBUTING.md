# Contributing To Brynja

Brynja is security-sensitive transport, cryptographic, and PKI infrastructure.
Contributions must keep changes small, explicit, tested, and honest about what
is implemented.

## License

Brynja is licensed under MIT OR Apache-2.0. Unless explicitly stated otherwise,
contributions are provided under the same dual license.

## Development

Follow the [component completion rule](../docs/assurance/component-completion.md):
agree the component's finite checks, implement, verify, record, close, move on.
Starting another component does not reopen completed work. Inspect and run named
assessments with [brynja-verify](../docs/assurance/brynja-verify.md); status commands
never execute tests. Use the pinned toolchain. The current finite CI list is:

```bash
scripts/checks.sh
cargo deny check
cargo audit
```

Do not add third-party dependencies to production cryptographic crates, unsafe
Rust, implicit std/alloc use, a modern-to-historical dependency edge, or Rust
files over 500 lines. The standalone `tools/brynja-verify` developer workspace
has separately locked and audited tool dependencies; these do not enter
production package graphs. Report
exploitable issues privately as described in SECURITY.md.

For release, follow the [scoped handoff](../docs/release/scoped-release.md): clean
pentest/retest, finite final checks, push, green exact-candidate GitHub, publish.
Publishing does not restart verification. Fix CI problems at their actual scope.

## Non-production CPU evidence builds

Never persist `--cfg brynja_cpu_evidence` or `--cfg brynja_sha1_cpu_evidence`
in shell profiles, workspace `.cargo/config.toml`, shared CI job/workflow
environments, or reusable build images. `RUSTFLAGS` and
`CARGO_ENCODED_RUSTFLAGS` apply to dependencies as well as the selected crate.
Use only the dedicated evidence scripts, with invocation-local flags and
separate outputs; never deploy their binaries or copy their environment into
application builds. A green evidence job is not backend admission.

Legacy SHA-1 requires BOTH its `cpu-evidence` feature and the distinct
`brynja_sha1_cpu_evidence` cfg, including in executable unit tests. `cfg(test)`
alone grants no execution permission. Its hosted adapter enables
only `cpu`. The older shared `brynja_cpu_evidence` cfg cannot enable SHA-1,
even with all features. This safeguard is not a sandbox against intentional
build changes, and does not change the older modern-backend evidence gates.
