# Apple AES observations — results, 2026-11-11

All four [declared observations](aes-apple-measurement-declaration.md) completed
once on Apple M2 Pro, macOS 27.2.1 (26B131). **The MSRV timing observation is
inconclusive; it is not a pass.** Current Rust's four controls passed the
declared screen. Neither result resolves earlier ARM alarms or establishes
whole-program constant-time behavior.

## Collection and replay

Eight native correctness-only configurations passed first: both compiler
endpoints, direct/facade imports, performance/timing fixtures. Each performance
fixture requires four Rust tests and 48 vector/clearing cases; each timing
fixture requires ten tests and 936 OpenSSL comparisons. The runner changes
passed all 931 integrated tooling/registry tests locally and 57 targeted tests
on Linux and macOS. Setup corrections are retained in the
[development ledger](aes-acceleration-development.md#apple-measurement-runner-and-prerequisites-2026-11-11).

Local replay verified the declaration, captured source files for all 21
packaged crates against local source, common package hashes, generated fixture
hashes, baseline probes, complete test populations and retained binary hashes.
It reproduced every performance/timing summary from raw output and independently
rechecked the two timing binaries' 1,872 oracle comparisons using local OpenSSL.
The observations retain 864 performance samples, 2,555,904 AES timing pairs
(5,111,808 timed samples), and 32,768 timer/copy diagnostic pairs. Warmup is
additional. No sample was discarded, replaced or adjusted; no measurement was
repeated. Non-pass exit status and diagnostics are retained.

## Timing outcome

Each row covers 39 campaigns, with 8,192 pairs and 1,024 operations per sample.
The threshold remains 4.5 for both absolute t statistics; the declared noise
policy is unchanged.

| Rust | Control | Alarms | Noise-inconclusive campaigns |
| --- | --- | ---: | ---: |
| 1.90.0 | separate-values | 0 | 1 |
| 1.90.0 | shared-values | 0 | 0 |
| 1.90.0 | separate-identical | 0 | 0 |
| 1.90.0 | shared-identical | 0 | 0 |
| 1.99.1 | separate-values | 0 | 0 |
| 1.99.1 | shared-values | 0 | 0 |
| 1.99.1 | separate-identical | 0 | 0 |
| 1.99.1 | shared-identical | 0 | 0 |

The noisy case is 1.90.0, `separate-values`, AES-256 cached `public-key`.
Fixed/random mean batch durations were 12,737.906/13,013.932 ns and maxima were
202,042/2,071,791 ns. Class CV values were 0.2453/1.7637, exceeding the limit
of one in the random class. Absolute Welch/paired t values were 1.0785/1.0984.
The long delay is retained; its cause is not established, and the low t values
do not convert this campaign into a pass. The complete MSRV observation exited
2 after collecting all four arms; current exited 0.

Timer/copy diagnostics had no alarms or noise flags. They are not subtracted
from AES durations and do not qualify AES by themselves.

## Performance diagnostics

Selected median encrypt-operation durations in ns, from nine batches of 64
operations each:

| Rust | AES bits | Accelerated raw | Accelerated cached | Portable cached |
| --- | ---: | ---: | ---: | ---: |
| 1.90.0 | 128 | 309.89 | 26.03 | 10080.73 |
| 1.90.0 | 192 | 211.59 | 26.05 | 12152.34 |
| 1.90.0 | 256 | 250.64 | 26.70 | 14095.05 |
| 1.99.1 | 128 | 309.91 | 27.34 | 10246.09 |
| 1.99.1 | 192 | 212.23 | 27.34 | 12341.16 |
| 1.99.1 | 256 | 251.95 | 27.34 | 14319.67 |

All encrypt/decrypt/public cases were faster than their corresponding portable
cases in these observations. Raw-owner construction alone generally was not:
it does no AES operation. Cached construction/clearing was approximately
300–400 ns accelerated versus 2,384–3,740 ns portable. Every case remains in
the compact record; there is no performance pass threshold. These are tiny
single-block observations, not bulk-throughput or application-latency claims.
The unpinned host also prevents treating key-width or compiler differences as
controlled microarchitectural comparisons.

## Bounded measured-code inspection

The [code record](../../assurance/aes-native-observations/v0.27.3/apple-timing-code-20261111.json)
binds both measured Mach-O binaries to the existing exact-byte review: three
complete round bodies and three complete expansion bodies per compiler. Local
LLVM 23.1.4 also captured the AES-256 cached-public timer candidates. The
correctness-only formatting specialization is separate from the measured
1,024-iteration specialization; the record retains both excerpts.

Manual inspection of the measured MSRV timer identifies clock boundaries
`0x100003288`/`0x100003344`, count initialization at `0x100003298`, the public
encrypt call at `0x1000032e4`, and decrement/termination at
`0x1000032c8`/`0x1000032cc`. Current uses `0x100005cfc`/`0x100005dac`,
`0x100005d0c`, `0x100005d5c`, and `0x100005d40`/`0x100005d44`. Successful
iterations bypass error formatting; there is no mode-string dispatch in these
timer bodies. Clock/runtime implementation and scheduling remain outside this
bounded review.

The actual callees at `0x10000e84c` and `0x10000d730` check authority generation,
state, backend and schedule extent before staging the block. They call the
matched AES-256 round body, copy the result and invoke the 16-byte volatile
clear before returning success. This is a representative timer/callee inspection,
not qualification of every specialization or arbitrary downstream inlining.
It does not establish why any older experiment alarmed.

## Retention and limits

- [Complete compact observations](../../assurance/aes-native-observations/v0.27.3/apple-measurements-20261111.json)
  include all campaigns, source/package/binary identities, host context and hashes.
- Remote scratch: `/Users/builduser/brynja-aes-measurement-0273.Mj3QOdsr`.
- Retrieved bundle: `target/aes-apple-measurements-20261111/observations.tar.gz`,
  SHA-256 `b8d4455256fdada2e6306869ed0b37eb727b37be95de34fec8d1bab97b6ee62f`.
- Full local disassembly hashes: MSRV
  `f6e93c4d43ac3c1cb38c595c20d1620ccf295293f7b2c2f1110650c57b718ed0`,
  current `b6281f52f9e4256636b6bd0b3c67db9d3c0b3320945dd14acc90e71e75ebd0d7`.

The source is the uncommitted development tree based on
`56a1b7805c9517fbdb5e3c28b137ea8c9108cf7e`, not a clean tagged receipt. These
records are unauthenticated local observations, not verification-runner current
passes or certification evidence. Large raw artifacts remain outside Git.

macOS placement was explicitly unpinned. Core-class selection, migration,
frequency/power policy and other system activity are uncontrolled. No other
task builds, measurements or bulk transfers were run on the Mac during sampling.
These limits cannot be used to dismiss a signal without evidence. The
[acceptance inventory](aes-acceleration-acceptance.md) still requires disposition
of retained timing alarms/noise and appropriately bounded measured-code review.
No physical protection, spill erasure or HSM requirement follows from this work.
