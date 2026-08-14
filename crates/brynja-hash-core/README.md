<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://crates.io/crates/brynja">Crates.io</a>
  |
  <a href="https://docs.rs/brynja">Docs.rs</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md">Release Plan</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md">Threat Model</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <a href="https://github.com/valkyoth/brynja">
    <img src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja security-first Rust cryptography and secure protocols overview">
  </a>
</p>

# brynja-hash-core

Small allocation-free `no_std` interfaces shared by Brynja fixed-output hash
implementations. This crate contains no algorithm, runtime dispatch, I/O, or
protocol code.

## Cryptography Verification Status

This crate does not implement cryptographic or protocol code. Only a named
independent reviewer and linked review evidence can change an implementing
component's status. Interface tests are not independent verification.

## Interfaces

- `Update` absorbs a complete byte slice or reports the implementation's
  closed error without partial acceptance.
- `FixedOutput` consumes an incremental state and returns its
  algorithm-specific digest value.

See the [full project documentation](https://github.com/valkyoth/brynja) and
[verification inventory](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md).

Licensed under either Apache-2.0 or MIT, at your option.
