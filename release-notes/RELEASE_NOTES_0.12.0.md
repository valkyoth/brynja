# Brynja v0.12.0 Development Milestone

Status: implementation in progress

Brynja v0.12.0 is the current development line for the constant-time
foundation. This initial commit opens the milestone, advances the `brynja`
facade to 0.12.0, and selects no crate for crates.io publication. It does not
claim that any v0.12.0 constant-time primitive is implemented or tag-ready.

## Initial Direction And Documentation Work

- broaden the shared project header from TLS alone to first-party Rust,
  `no_std` cryptography and secure protocols while retaining TLS 1.0.0 as the
  first production target;
- define future reusable hash-family and MAC leaf crates without admitting or
  implementing them before their roadmap milestones;
- retain `brynja-crypto` as the protocol-facing provider, policy, and
  composition layer above those leaf crates; and
- add the updated project image and keep the root and published facade README
  identical.

## Current Limits

The constant-time equality, choice, mask, conditional-selection,
conditional-swap, fixed-width secret-operation, and compiler-barrier scope is
not implemented by this initial milestone commit. Brynja remains incomplete,
must not secure application traffic, has no independent cryptographic or
protocol verification, and is not FIPS 140-3 validated.

## Release Process

v0.12.0 is an internal development milestone in the cumulative range after
v0.10.0 through v0.15.0. It will select no crates for crates.io publication and
receives no scheduled pentest unless a material exceptional trigger applies.
Only after the full planned scope is implemented, documented, verified,
committed, and green in GitHub and CodeQL may the signed `v0.12.0` tag be
created.
