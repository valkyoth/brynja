# Contributing To Brynja

Brynja is security-sensitive transport, cryptographic, and PKI infrastructure.
Contributions must keep changes small, explicit, tested, and honest about what
is implemented.

## License

Brynja is licensed under MIT OR Apache-2.0. Unless explicitly stated otherwise,
contributions are provided under the same dual license.

## Development

Use the pinned toolchain and run:

```bash
scripts/checks.sh
cargo deny check
cargo audit
```

Do not add third-party Cargo crates, unsafe Rust, implicit std/alloc use, a
modern-to-historical dependency edge, or Rust files over 500 lines. Report
exploitable issues privately as described in SECURITY.md.

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
