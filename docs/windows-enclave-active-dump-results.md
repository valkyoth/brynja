# Active Rust-worker full-dump observations

Status: v0.24.50 **research observations, not Windows strict qualification**.
The [experiment design](windows-enclave-active-dump-design.md) defines the exact
pause points and limits. No production code, release policy or previously signed
enclave image changed.

On 2026-09-29 the prepared Azure Windows Server 2025 VBS development host ran the
actual Rust host and enclave result exchange at source commit
`536c1de5d225ad40851ad3087aaf1628751f136f`. An instrumented copy of the fixed host
callback triggered WER at event 2 (before public export) or event 3 (after the
public empty-message digest reached ordinary host staging, before acceptance of
the second offer). The original enclave DLL and Rust host static library were
reused; this adds only a separate diagnostic executable and capture harness.

## Results

| Capture | Full dump size | Ordinary control | Public staging | Enclave window/reservation bytes included |
| --- | ---: | --- | --- | ---: |
| [Before export](../assurance/windows-protection-observations/active-host-dump-event-2-536c1de5.json) | 10,187,181 | All 8,192 marker bytes | All 32 expected zero bytes | 0 / 0 |
| [Before export, repeat](../assurance/windows-protection-observations/active-host-dump-event-2-repeat-536c1de5.json) | 10,183,085 | All 8,192 marker bytes | All 32 expected zero bytes | 0 / 0 |
| [After public staging](../assurance/windows-protection-observations/active-host-dump-event-3-536c1de5.json) | 10,191,325 | All 8,192 marker bytes | Exact independent SHA-256 empty-message digest | 0 / 0 |
| [After public staging, repeat](../assurance/windows-protection-observations/active-host-dump-event-3-repeat-536c1de5.json) | 10,183,133 | All 8,192 marker bytes | Exact independent SHA-256 empty-message digest | 0 / 0 |

Each child checked the first operation's epoch/slot/status and reached the
checkpoint only after the host had rechecked all 16 owned-window pages as locked.
Each exited with the required fail-fast status `0xc0000602`. Each dump was a valid
full-memory dump from that child, not an absent/truncated file or unrelated crash.
The 64 KiB owned window and full 256 MiB enclave reservation were analyzed
separately. Ordinary public staging was deliberately included; it is not protected
output and is never described as such.

The [post-campaign cleanup check](../assurance/windows-protection-observations/active-host-dump-cleanup-536c1de5.json)
found zero remaining temporary application policies, capture directories or crash
children. The parent removed its raw dumps and copied executables. **No raw
process dump was downloaded or committed.** The saved local artifact archive
contains only experiment binaries, generated sources, build records and redacted
observations; its SHA-256 is
`a06f8f8d948146dddea8d46fc08d4baaeb2608dd29fd094576d7236c109ecc5c`.
It is preserved outside `target/` under the ignored Windows recovery directory.

## Verification and interpretation

All 22 source bindings in every observation match the capture commit and current
source bytes. The three Rust archive hashes, instrumented callback hash and native
executable hash match the preserved artifacts. The native executable built with
MSVC `/W4 /WX`; no new signing or platform configuration change was required
beyond the temporary per-application WER keys. Previous development-signing
limitations still apply.

Six new regression tests and eight existing minidump-parser tests passed on both
Linux and native Windows. The existing 14 enclave-dump and nine WER tests passed
locally, as did the host bridge suite, script inventory, documentation links,
first-party crypto boundary and unsafe policy. Tests reject missing/wrong/partial
controls, phase confusion, malformed dumps, zero-filled bytes misreported as
absence, overlapping/invalid addresses, wrong exits, timeout and credential
inheritance. No full release sweep was run.

These results extend dump observations from a synthetic allocation to the active
Rust worker and host exchange. They establish absence from **this WER dump path
at these two checkpoints**, not absence from all snapshot mechanisms or proof that
all secret-bearing values live within the enclave reservation. They do not prove
caller-frame, TLS, register or transition-stack secrecy; all data here is public.
Fail-fast deliberately skips destructors, so no post-abort erasure is claimed.

The next unresolved design work remains secret-input handling and protected
persistent output ownership, along with full worker/runtime coverage and
production deployment/signing. Windows strict remains unavailable; this evidence
does not change its API, admission policy or Linux guarantees.
