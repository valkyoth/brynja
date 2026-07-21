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

