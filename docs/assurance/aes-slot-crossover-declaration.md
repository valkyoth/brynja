# ARM class/address crossover — frozen declaration, 2026-11-12

Frozen before the first `crossover-measure` invocation. This is a finite
diagnostic experiment, not a replacement for the four earlier non-noise ARM
alarms. Results belong in a separate record; do not revise this declaration
in response to outcomes.

## Prerequisites and identities

The [design](aes-slot-crossover-design.md) and
[linked-path review](aes-slot-crossover-linked-review.md) apply. Their SHA-256
values at declaration are respectively
`2b0cf27c8f4a95532cb9c047915b85982341b8158cda27f025f0b0e760441db1`
and `6b297f113d84360b6d95ae498bd4c5dcbb6d7570f656986ae06288d54f99e570`.
The [correctness record](../../assurance/aes-native-observations/v0.27.3/crossover-fixture-correctness-20261111.json)
binds the packaged sources and the exact executables. Neither is rebuilt for
this experiment. Both share generated fixture SHA-256
`f759f123e4e319fbf9d0476aeeebf0ffe9e09884117a796b48f51642bfb0df13`.

| Run order | Compiler | Restored executable | SHA-256 |
| --- | --- | --- | --- |
| 1 | 1.90.0 | `msrv` | `0050c9f0eb43abe2fb1899d55333e32ee5bebe5a08ac5cad683094ac9ce639b8` |
| 2 | 1.99.1 | `current` | `453e4171a40f00763d635e7245f90293f0e26cbe36e0f5e3f87999db218e4934` |

The new host is `ubuntu@13.49.18.65`, hostname `ip-172-31-29-51`, four-core
Neoverse-V2 AArch64 with AES/PMULL advertised, Linux `7.0.0-1014-aws`.
The owner confirmed ED25519 fingerprint
`SHA256:YiDOyfhwOf+3je2sRxQGdD2mr+Tu0x4rsMBSo1nzmPk`.
This is a fresh instance, not the old host with an assumed unchanged identity.
Restore directory: `/home/ubuntu/brynja-aes-crossover-0273-9G4pbevM`.

Runtime is Ubuntu glibc 2.43; libc SHA-256 is
`7b17086ce95b15145e6c2c5f8146395f80e2df1af2636fbf78e90c546a70df06`,
loader SHA-256 is
`7cdd4ce693d93790bf088dca2e86857f758335b6010d913e086fa384e7704a46`.
Changing the host/runtime is a limitation, not a causal explanation for old
signals. No virtual-machine exclusivity or physical qualification is claimed.

Both restored binaries completed correctness-only preflight on this host.
All 576 cells per binary were independently validated locally against OpenSSL.
Preflight bundle SHA-256:
`9303f4f58ab24cd3cc9f3cd49cd6089e93c3f07090815ad770b09cebdcb0dd40`.
The 17 crossover parser/control regression tests pass. No crossover timing
population has been collected at declaration.

## Exact finite execution

Run only the two binaries above, in that order, once each. Pin CPU 0, the
lowest allowed logical CPU (allowed set checked as 0–3). From the restore
directory, each command is:

```sh
env -i PATH=/usr/bin:/bin LANG=C OPENSSL_CONF=/dev/null \
  timeout --kill-after=5s 600s taskset -c 0 ./msrv crossover-measure
env -i PATH=/usr/bin:/bin LANG=C OPENSSL_CONF=/dev/null \
  timeout --kill-after=5s 600s taskset -c 0 ./current crossover-measure
```

Each binary visits cached AES-192 decrypt-block, AES-256 public-block and
AES-256 public-key in that order, with `values` then `identical` for each.
Each control has 256 warmup rounds and 8,192 retained rounds, four class/slot
cells per round, four operations per cell duration. Total: 393,216 retained
durations across both compilers. Corpus IDs are 22, 37, 36; the separate order
seed and all eight balanced patterns are unchanged from the tested design.

The collector is retained locally as
`target/aes-crossover-native-20261112/collect.sh`, SHA-256
`0ed2724fdd06ee9ea5b39549f816ed728c8763971a1db7fb84034fc33fd9e3b7`.
It exclusively creates `observation/`, refusing a repeat; copies this
declaration and itself; records host/load/loader context, timestamps, exit
status, complete stdout/stderr and before/after binary checks. It continues
to the second declared compiler after a nonzero first exit, but stops if a
binary identity changes. Failures/partial output remain retained. No run is
replaced after timeout, error, noise or alarm. Do not change CPU, binary,
timeout, environment or population in response to results.

## Fixed analysis and interpretation

Use the existing parser `scripts/aes/aes_timing_slot_crossover.py` (SHA-256
`d4dc90b6d1d24f7a86c7b30a130e9034408ffc3d78a296abf282596a2c8a7535`)
with `scripts/aes/check-aes-fixed-random.py` (SHA-256
`08bb7ae4cd54255837eaf931ed59a272bb44c3714a481e4dd916bd4b26a956f9`).
Check full population, authority/completion, order and actual slot addresses.
Report all four conditional comparisons per control, their Welch and paired
statistics, CV, signed means, interaction, order patterns and chronological
eighths. Alarm threshold stays 4.5; noise CV threshold stays 1.0. No sample
filtering, overhead subtraction, comparison selection or overall timing-pass
claim is allowed. A failed or malformed invocation remains a failed
observation, not a source of selected valid samples.

Slot-only effects can support a layout contribution in this fixture only.
Class effects at both slots remain unresolved. Identical-input label effects
indicate a harness/order/environment confound. Mixed effects or noise are
inconclusive. Absence of detected signals means non-reproduction, not clearance
of old alarms or proof of universal constant-time behavior. The production API,
release gate and deployment requirements are unchanged.
