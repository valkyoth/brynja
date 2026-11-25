# v0.29.3 — Paired AES-GCM and GMAC (internal candidate)

Callers can opt into `aes-gcm-execution` or `gmac-execution`
through either `brynja-crypto` or the facade. The new owners require an
admitted AES-NI/PCLMUL pair on Linux or Windows x86-64, or an AES/PMULL
pair on Linux ARM64 or Apple Silicon; the ordinary owners still use portable code.
All three AES key widths are available. There is no RISC-V pair,
no implicit affinity change and no automatic fallback.

Use a compatible AES/SSE2 (x86) or AES/NEON (Arm) build. Arm timing remains
unresolved. Require the pair before supplying a key;
choose a portable owner only on pre-key unavailability, not after a failed
self-test or interrupted operation. Keep sending nonce ranges durable and
separate GCM and GMAC keys as before.

The [verification checklist](../docs/assurance/aead-accelerated-development.md)
ties each claim to its own check: native interruptions, Go/NIST archive
replays, linked instruction inspection, and a scoped timing observation on
one AMD host. Neither compiler crossed the predeclared timing threshold;
that does not qualify other workloads, compilers or machines.
The two compiler endpoints also passed native functional and packaged
vector checks on Apple Silicon, AWS Linux ARM64, and a Windows x64 MSVC
guest using the host processor. These runs did not measure timing.

This is an internal development milestone, not a crates.io publication or
an announcement of a signed release.

The facade candidate is 0.29.3; the supporting crates retain their internal
versions. No crate is selected for publication. The finite gate checks both
new features in its existing crypto test and lint jobs; it does not collect
timing or replay the full native qualification campaign. A scoped review
of the committed candidate, final gate and exact-commit GitHub/CodeQL
results are still needed before tagging.

Local candidate preflight passed the CI-selected commands, including the API
profile and normative-requirement checks, plus SBOM comparison, dependency
policy and both lockfile audits. The versioned archives passed the native
vector/linked checks again after the facade bump. Both compiler endpoints
also compiled the paired facade features for Cortex-M (no native execution).
Timing was replayed from the retained records, not remeasured. These are
working-tree results, not approval of a commit.
