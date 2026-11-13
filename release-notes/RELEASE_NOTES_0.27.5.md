# v0.27.5 candidate — AES public API usability acceptance

Internal candidate; no crates.io publication is selected. Existing final
checks, a clean committed candidate, exact-commit green GitHub/CodeQL and
explicit tag authorization remain separate. These notes are not release approval.

## Scope

The candidate adds public-consumer coverage, not another AES implementation.
Portable archive/checkout consumers now require 21 named tests per configuration.
Three new tests cover all key widths, six deterministic public inputs and all
four combinations of operation-local/cached encryption and decryption owners.
They decrypt the actual encrypted result after clearing the first key owner,
borrow secret output without an unowned copy, and verify cleanup and canaries.
Frozen known answers remain independent: round trips alone are not an oracle.

Twelve forced-accelerated composition registrations cover both compiler
endpoints, direct/facade APIs, native static AES-NI, ARM QEMU static and ARM
QEMU hosted execution. Each runs debug/release with exact test and backend
populations; the adapter cannot silently use portable AES. ARM emulation is
not a native observation or timing measurement.

Paired API probes now require 223 positive/negative pairs per host compiler
endpoint and 110 per archive-only no_std route/endpoint. New cases reject wrong
key/storage lengths and wrong block widths for all six accelerated owners'
encryption, decryption and explicitly acknowledged public encryption methods.
Valid twins must compile before the exact expected negative diagnostic counts.

The [usage guide](../docs/aes-usage.md) connects these tested examples to the
feature, authority, storage, output and error contracts. The
[acceptance record](../docs/assurance/aes-usability-acceptance.md) maps existing
AESAVS, differential, final-linked and platform observations to their actual
scope. No production AES arithmetic, dispatch, provider API or dependency changes.

## Explicit limits and owner decision

On 2026-11-13 the owner agreed to finish usability acceptance while deferring
further accelerated timing investigation. The existing public discussion and
recorded results remain available for future work. This is not a timing pass:
all original alarms, noise flags, declarations and executable identities remain
unchanged. The investigation has not established a portable-AES defect; portable
finite screens retain their own host/build scope, not a universal guarantee.
No fresh timing experiment is required or launched for this milestone.

RISC-V remains an evidence-only QEMU candidate, unadmitted through ordinary
static and hosted routes. No native support, physical-fault resistance,
power/EM protection, whole-program constant time or complete spill/register
erasure is inferred. No HSM or military profile is required. Newly demonstrated
defects remain subject to assessment; timing deferral does not waive them.

## Candidate and release process

Only the facade version advances to 0.27.5; supporting crates retain their
internal-train versions. Consumer pins/lockfiles and the SBOM follow the facade.
The existing 30 finite check commands and timeouts are unchanged. Under the
existing internal-milestone policy, this tests/tooling/documentation scope does
not select a scheduled pentest or publication; an exceptional trigger still
requires review. No review PASS record is fabricated from prior AES audits.

Version-only edits can invalidate verifier fingerprints. Earlier checks retain
their true source snapshots and are not relabelled as fresh executions. Do not
rerun historical native, proof or timing campaigns merely to obtain a green
status display or create a tag.

All 30 working-tree preflight checks passed on 2026-11-13 after refreshing the
generated roadmap closure row and rerunning the sandbox-blocked advisory check
with permission. This is not commit-bound release approval. The existing final
gate still requires a review disposition and has not been changed; the current
handoff retains candidate commit and owner retest before that gate and GitHub.
