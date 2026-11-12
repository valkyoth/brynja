# DIT-required shared-address screen: finite declaration

Declared 2026-11-12, before any measurement in this experiment. This is the
replacement value-timing screen described in [the prospective policy](aes-value-timing-policy.md),
not a rerun that can erase historical alarms. No publication gate is added.

## Frozen inputs and prerequisites

Use only the four direct-route executables in the
[preparation record](../../assurance/aes-native-observations/v0.27.3/dit-timing-preparation-20261112.json).
Do not rebuild them. Their raw kernels and the selected historical-alarm
caller/timer paths have undergone the [bounded review](aes-dit.md).
All four controls have already passed independent OpenSSL preflights for
each executable; the two cross-built Linux executables also passed native
preflight on this host. This is not a claim of reviewing every campaign caller.

The [Linux manifest](../../assurance/aes-native-observations/v0.27.3/dit-finite-linux-declaration-20261112.json)
and [Apple manifest](../../assurance/aes-native-observations/v0.27.3/dit-finite-apple-declaration-20261112.json)
bind executable/probe/collector hashes, policy/parser hashes, review checkpoint,
host, compiler, affinity and new output directories. The Mac baseline probes
were separately built from the pinned source, with no ISA flags, on both
compilers; both returned `AES_DIT_HOST_BUNDLE_PASS`. Timing executables were
not changed. Probe support alone is not an instruction-timing proof.

## Complete finite schedule

On each host, perform **four rounds**, each with Rust **1.90.0 then 1.99.1**,
each compiler in this exact control order:

1. `separate-values`
2. `shared-values`
3. `separate-identical`
4. `shared-identical`

That is 32 fresh processes per host, 64 total, and 2,496 campaign observations.
No process launches run concurrently on the same host. Independent hosts may
collect concurrently. Linux inherits CPU 0 affinity from the collector; Apple
uses normal OS scheduling with no affinity claim. Leave ASLR and OS scheduling
policies unchanged. No intentional sleep, layout shift or adaptive ordering.
Four launches per arm is a bounded multi-layout screen, not enough to establish
generality across layouts, hosts, compilers or all possible inputs.

Each invocation is exactly `[retained-binary, "measure", control]` with
`PATH=/usr/bin:/bin`, `LANG=C`, `LC_ALL=C`, `TZ=UTC` and no inherited overrides.
Every process retains 39 campaigns, 8,192 pairs each, 256 warmups and four
operations per duration under the original unmodified timer/corpus.
Timeout is 180 seconds per measurement, 15 seconds per baseline probe.
Run both baseline probes successfully before starting measurements on that host.
Check both executable and probe hashes before and after every launch.

## Failures, retention and interpretation

The collector is a trusted experiment utility, not a security sandbox. It
cannot resume or overwrite an existing destination and makes no statistical
decisions. Raw stdout, stderr, exit status, timeout/error, command and UTC times
are retained per launch, with hashes. A process failure does not retry or skip
later planned arms. A changed binary/probe, failed capability check or host
mismatch aborts collection; incompleteness is never a pass. Operational
interruption must be reported rather than silently restarting the experiment.

Analyze every launch independently with the frozen strict parsers: exact
authority/control markers, complete population/order, positive durations,
unchanged absolute Welch/paired cutoff 4.5 and CV limit 1.0. Zero variance is
inconclusive. No trimming, pooling, multiple-testing adjustment, offset
subtraction, best-launch selection, threshold change or retry-to-pass.

Every `shared-values` **and** `shared-identical` campaign in every launch must
have zero alarms and zero noise flags for the screen to pass. A primary alarm
is a signal to investigate, not proof of a secret-dependent library defect.
A negative-control alarm/noise prevents a pass; it must not be subtracted away.
Separate-control statistics are address/context diagnostics, **not timing
passes**. All their alarms/noise remain visible; malformed samples, stderr,
failed processes or timeouts in any arm fail the completed screen.

Keep raw files on the builders and local ignored `target/` storage; commit only
the bounded per-launch/campaign summary and hashes, not hundreds of megabytes
of raw data. Existing earlier declarations, results and alarms remain intact.
Even a clean screen would not prove physical side-channel resistance, general
constant-time execution, register/spill erasure or timing of the whole API under
DIT. DIT is scoped to raw AES operations, and shared addresses do not remove all
execution-history or scheduling effects.
