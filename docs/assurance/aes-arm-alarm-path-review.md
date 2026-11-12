# Retained ARM timing-alarm paths — 2026-11-11

This is an offline review of the **original alarm-producing binaries**, not a
new timing experiment or a timing pass. No production code, thresholds or
recorded populations were changed. The four non-noise alarm campaigns remain
unexplained and open.

## Identity and automated checks

The [compact capture record](../../assurance/aes-native-observations/v0.27.3/alarm-path-code-review-20261111.json)
binds three retained GNU/Linux AArch64 executables to their original identity
records, fixture hashes and binary hashes. The sources are the
[original experiment](aes-accelerated-fixed-random-results.md) and
[address/value controls](aes-timing-address-controls-results.md). Reconstructed
generated fixtures matched the recorded hashes. No binary was rebuilt or run
to collect measurements during this review.

The existing round and expansion inspectors matched all six complete bodies in
each executable: 18 bodies in total, with 3,915 rejected instruction mutations.
The inspectors' AArch64 ELF mapping uses their existing
`aarch64-unknown-linux-musl` entry; here that establishes only the inspected ISA
and executable-body mapping. These are GNU binaries, and this does **not**
transfer musl ABI, loader or whole-program qualification to them.

Full disassemblies and 11 hashed function excerpts are retained locally under
`target/aes-alarm-path-review-20261111/`. The compact record identifies each
excerpt, complete symbol body, source observation and binary by hash. That
directory is a local artifact, not a committed artifact archive. The following
caller-path findings are manual, bounded inspection, distinct from automated
exact-body matching.

## Four reported paths

Addresses below refer only to the specific executables named in the record.
They are not stable source-level API identifiers.

| Recorded campaign | Timer interval and operation | Inspected success path |
| --- | --- | --- |
| Original Rust 1.90.0, AES-256 cached public-block | Start `e470`, stop `e814`; four operations | Cached construction precedes the timer. Public mode selection at `e504..e520`; authority, generation, backend and 240-byte schedule checks precede the input load at `e6f4`. Encrypt direction is zero; `e74c` calls the matched round body at `1125c`. Public copy and 16-byte scratch clearing follow; schedule clearing is after the timer. |
| Original Rust 1.99.1, AES-192 cached decrypt-block | Start `973c`, stop `9d68`; four operations | Public mode-prefix comparison at `97e4`, decrypt selection at `97f4..9810`; `9920` calls the secret-output method at `f828` with decrypt direction one. That method clears the destination, checks authority and the 208-byte schedule, stages the block, calls the matched round body at `10138`, copies 16 bytes and clears scratch. The returned secret owner is cleared within the timed loop. |
| Original Rust 1.99.1, AES-256 cached public-block | Start `a6f0`, stop `ad1c`; four operations | Public prefix comparison at `a798`; authority and 240-byte schedule checks precede block staging at `a888`. `a9d4` calls the matched round body at `10238` with encrypt direction zero. Public copy at `a9e4` and 16-byte scratch clearing at `a9e8` follow. |
| Address-controls Rust 1.99.1, separate-values AES-256 cached public-key | Start `a6f0`, stop `ad1c`; four operations | Corresponding public-mode, authority, staging and cleanup path, but `a9d4` calls the matched round body at `107a4`. Construction is outside the timer; the key-equivalent cached schedule is consumed inside it. This executable is not byte-identical to the original current binary. |

The `bcmp` calls above compare the public mode string with the literal prefix
`public-`; they do not compare plaintext or key bytes. The inspected measuring
paths skip hexadecimal formatting under the public observation flag. Loop
bounds, schedule lengths, direction selection and authority-state decisions
are public metadata, not indexes derived from block or schedule contents.

The clearing helpers at `ffb4`, `f094` and `f600`, and copy helpers at `ffc8`,
`f0ac` and `f618`, were inspected in full. They use public length/offset loops
and base-plus-offset memory accesses. No content-dependent branch or memory
index was identified in those helpers or the inspected successful operation
paths. This is not a proof about instruction latency, speculative behavior,
all error paths, system calls, the loader, or arbitrary consumers.

## Disposition

The retained non-noise signals are unchanged:

| Campaign | Welch statistic | Paired statistic |
| --- | ---: | ---: |
| Original MSRV AES-256 cached public-block | 40.096 | 46.240 |
| Original current AES-192 cached decrypt-block | 5.035 | 5.048 |
| Original current AES-256 cached public-block | 8.943 | 12.926 |
| Address-controls current AES-256 cached public-key | 23.827 | 28.781 |

The review confirms that these short timing windows include public mode
selection, authority checks, staging and cleanup as well as AES. Those are
possible measurement confounders, **not an established explanation** for the
signals. Matching AES bodies and finding no secret-dependent branch in the
bounded paths does not establish data-independent execution time. Conversely,
the statistical alarms alone do not identify a cryptographic defect.

Later batch controls change the measured specialization; the replacement ARM
host changes the environment. Green results on those controls, Intel or Apple
cannot clear these records. Apple MSRV and the earlier noisy AMD populations
also retain their separately documented inconclusive status.

The next useful step is a focused review of the retained measurement design,
raw populations and these exact paths. Another experiment would need a finite,
predeclared hypothesis and decision rule; repeating until green is not a
resolution. Independent review may identify a justified harness correction or
a production defect, but neither is established here. Broader measured-path
coverage also remains distinct from this four-campaign inspection.

The [acceptance inventory](aes-acceleration-acceptance.md) therefore remains
open. Any decision to narrow the named capability or accept unresolved timing
qualification requires the owner's explicit agreement. This document adds no
publication gate, HSM requirement or claim of physical side-channel resistance.
