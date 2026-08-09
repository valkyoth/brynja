# Brynja v0.11.1 Development Milestone

Status: implemented; awaiting hosted checks and signed tag

Brynja v0.11.1 completes the review-only sanitization adapter admission stop in
the cumulative release train ending at v0.15.0. It advances the `brynja`
facade to 0.11.1, selects no crate for crates.io publication, and adds no
production dependency.

## Admission Decision

The latest stable first-party package on 2026-08-09 is
`sanitization 2.0.3`. Brynja records its crates.io archive SHA-256, release
source commit, externally reviewed code commit, MIT OR Apache-2.0 license, Rust
1.90 MSRV, `no_std` behavior, feature graph, inherited unsafe boundary, target
evidence, advisory result, upstream pentest, and residual limits.

The exact admitted manifest disables default features and selects no feature.
Its activated runtime graph contains only `sanitization`; `zeroize`, derive,
serde, subtle, and every other third-party crate remain absent. Offline checks
enforce the committed decision and production-graph absence. An independent
unpublished fixture tests the candidate wrapper without entering the Brynja
workspace. The tag gate also queries crates.io, validates the immutable package
archive, and rebuilds the fixture matrix, so a newer release or checksum drift
fails closed and requires re-review.

The post-implementation security review found that the first candidate API
accepted arbitrary fallible-source error payloads and discarded them without
zeroization. The remediated boundary accepts only the payload-free Brynja-owned
`SourceFailure`; compile-fail tests reject rich errors for construction and
replacement, and the admission validator rejects a return to a generic error.
The affected fixture was never part of the production dependency graph.
The repository-owner retest of signed remediation commit
`cd1c881d2eb6c9aa925f1527a326330c1cf3b80a` passed with zero open findings.

## Frozen Boundary

The decision permits v0.11.2 to conditionally implement one separately
selected `brynja-sanitization` package with adapter-owned fixed-size wrappers.
Applications must depend on it explicitly. It cannot become a facade feature,
default, all-features shortcut, provider dependency, modern or legacy engine
dependency, implicit conversion, or orphan-rule workaround.

The same adapter serves modern and legacy applications; a separate
`brynja-legacy-sanitization` package is rejected. Brynja's v0.11.0
complete-owned-region primitive remains mandatory and authoritative for
protocol secrets. The adapter remains outside `brynja-fips-module` and cannot
satisfy, inherit, or imply a FIPS SSP-destruction or validation claim.

## Verification And Limits

The isolated no-default-features candidate compiled on all ten supported Rust
releases from 1.90.0 through 1.97.1 and all nine promised desktop, mobile, BSD,
and bare-metal targets; WASM compiled as a weaker compatibility target. Cargo
metadata, the isolated lock, cargo-audit, cargo-deny, package bytes, upstream
MIR/LLVM/assembly, Miri/Kani, target tiers, and the upstream PASS pentest were
reviewed. Cross-compiled targets remain compile-only unless upstream native
evidence says otherwise.

Cleanup after abort, forced termination, `mem::forget`, prior moves, spills,
registers, caches, DMA, dumps, swap, hibernation, privileged reads, and physical
attacks remains outside the claim. The upstream review is not independent
verification of Brynja and is not FIPS validation.

## Release Process

v0.11.1 is an internal development tag with an exceptional committed PASS
pentest report and no crates.io publication. After the signed release-candidate
commit passes the complete local gate and GitHub and CodeQL are green, the
immutable signed `v0.11.1` tag may be created. All changes remain in the
backwards-looking v0.10.0-through-v0.15.0 cumulative pentest scope.
