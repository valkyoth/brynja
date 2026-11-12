# Intel AES measurement results — 2026-11-11

The four observations in the [frozen declaration](aes-intel-measurement-declaration.md)
completed once, in their declared order, on the AWS Intel Xeon 6975P-C.
No production code, fixture, threshold or sample population changed. These are
unauthenticated development observations, not certification or a release gate.

## Retention and replay

The [measurement record](../../assurance/aes-native-observations/v0.27.3/intel-measurements-20261111.json)
contains compiler, package, fixture, binary and raw-log hashes, host metadata,
all summaries and exit statuses. The retained local archive is
`target/aes-intel-measurements-20261111/observations.tar.gz`, SHA-256
`5bf0d9057ab4a32f38f208c9847377d2b0cee4e7d7bcc73c73dd65183df26b82`.
It includes the frozen declaration, launch script, logs, binaries and raw samples;
the large archive is not a committed artifact. Source provenance remains the
uncommitted working tree and package hashes in the
[native Intel record](../../assurance/aes-native-observations/v0.27.3/intel-native-20261111.json).

Before collection, both Python runner suites passed (13 performance and 30
timing tests). Eight native correctness configurations passed: both fixtures,
Rust 1.90.0/1.99.1 and direct/facade routes. Each observation also passed its
own exact-binary tests/preflight. Offline replay checked the exact populations,
all binary/package/fixture identities, raw performance and timing summaries,
and timing preflight against local OpenSSL. No sample was filtered, subtracted,
retried or replaced.

## Timing

Both compiler observations used direct static `X86AesNi`, GNU x86_64,
opt3/fat-LTO/cgu1/overflow/abort and the fixed 1024-operation batch.
All four controls (`separate-values`, `shared-values`, `separate-identical`,
`shared-identical`) passed the declared statistical screen on each compiler:
zero alarms and zero noise-inconclusive campaigns in all eight arms.
This covers 39 campaigns per arm, 8192 pairs per campaign: **2,555,904 AES
pairs**. The four timer/copy diagnostic populations also had zero alarms and
zero noise-inconclusive outcomes, with **32,768 pairs** retained separately.
Their durations were not subtracted from AES samples.

These results do not resolve the earlier short-batch AMD/ARM alarms or noise.
They describe this separately declared Intel experiment only. Statistical
non-detection is not a constant-time proof, and the host is not a controlled
physical-observation laboratory.

## Performance

Both observations retained all 432 samples (864 total), covering all 48 cases
under the unchanged unwind-profile performance policy. Illustrative median
nanoseconds per secret encryption operation are below; raw owners include
operation-local expansion, while cached operations exclude schedule creation.

| Compiler | AES bits | Raw accelerated | Cached accelerated | Cached portable |
| --- | ---: | ---: | ---: | ---: |
| 1.90.0 | 128 | 133.78 | 17.66 | 8559.80 |
| 1.90.0 | 192 | 147.42 | 18.11 | 10266.27 |
| 1.90.0 | 256 | 176.50 | 19.11 | 11964.02 |
| 1.99.1 | 128 | 134.45 | 18.47 | 8770.11 |
| 1.99.1 | 192 | 141.69 | 18.67 | 10488.67 |
| 1.99.1 | 256 | 169.48 | 18.94 | 12214.72 |

All encrypt/decrypt/public-operation cases were faster than their portable
counterparts in these observations. Raw-owner construction/clearing alone was
slower: approximately 29–34 ns accelerated versus 22–27 ns portable, because
that case does not perform an AES operation. Cached construction/clearing was
approximately 191–250 ns accelerated versus 1999–3078 ns portable. All cases,
including those costs, remain in the record; there is no speed pass threshold.
These tiny single-block measurements are not bulk throughput or application
latency claims, and public output has different clearing costs from secret
output.

## Bounded emitted-code inspection

The [code record](../../assurance/aes-native-observations/v0.27.3/intel-timing-code-20261111.json)
binds both actual measured binaries to the existing exact-byte reviews:
three round bodies and three expansion bodies per compiler, with 465 round
and 570 expansion mutation rejections per binary. Local LLVM 23.1.4 inspected
the retained ELF binaries; this is distinct from the earlier lifecycle review.

Manual inspection additionally covered the AES-256 cached-public timer in
each measured binary. MSRV starts its clock at `0x14256`, loads 1024 at
`0x1426f`, calls `Aes256ExpandedKey::encrypt_block_public` at `0x142ae`,
decrements/tests the counter at `0x1428e`/`0x14291`, and ends timing at
`0x14338`. Current uses `0x18216`, `0x1822f`, `0x1827f`,
`0x1825e`/`0x18261`, and `0x182dc`, respectively. Each successful iteration
reaches the next operation without string dispatch or formatting; error
formatting remains on the failure branch. Excerpt hashes are retained.

The initial offline excerpt selector assumed generic type names that MSRV
legacy mangling does not retain. It stopped rather than issuing a code record.
The selector was corrected after identifying the actual callee and counted
loop, and current demangler angle-bracket formatting was accommodated. Only
offline inspection was repeated; neither binary nor measurement was rerun.
This representative caller inspection and the exact kernel reviews do not
constitute a complete proof of all timer specializations or downstream callers.

## Limits and next work

Measurements pinned logical CPU 0; its SMT sibling was CPU 2. Governor and
boost telemetry were unavailable. No frequency or SMT settings were tuned,
and no other task jobs or artifact transfers ran on the host during collection.
VM scheduling, cache state, SMT and compiler specialization limit inference.
Hosted x86 remains unavailable; advertised VAES is not admitted or qualified.

Apple Mach-O body/caller/admission/cleanup review, broader declared platform
qualification and explicit disposition of earlier timing alarms remain open.
No physical power/EM/fault resistance, spill erasure or arbitrary-consumer
guarantee follows from this result.
