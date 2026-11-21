# v0.28.1 candidate — portable GHASH package acceptance

This internal successor to v0.28.0 adds a [downstream consumer](../assurance/ghash-public-api/README.md)
and a reproducible offline archive check. The package test deliberately does
not rely on unpublished supporting-crate features being available on crates.io.
The facade patch version advances; the cryptographic implementation, API,
dependencies and Rust 1.90.0 minimum do not change.

The [verification record](../docs/VERIFICATION_STATUS.md#portable-ghash-package-acceptance-v0281)
describes which operations run on the host and which targets only compile.
Existing limitations on raw GHASH, timing and memory clearing still apply.
No GCM, GHASH hardware acceleration, public package upload or release
authorization is part of these changes. Candidate review, final gate and
exact-commit GitHub checks precede tagging.

Working-tree preflight (2026-11-21): all 32 scoped commands passed,
including the archive consumers, release/registry regressions, SBOM,
dependency policy and advisory scan. All eight GHASH verifier entries
were current on their scoped inputs. These are local results, not a
commit-bound pentest, final gate or GitHub result.

The [candidate pentest disposition](../docs/assurance/ghash-package-review.md)
records the follow-up tooling fixes and remaining limits. No release gate or
cryptographic API was added.
