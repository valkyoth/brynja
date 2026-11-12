# Fourth ARM alarm: exact-binary identical-input check — 2026-11-12

Frozen before measurement. This bounded diagnostic tests whether the retained
address-controls executable can reproduce a label offset with equal inputs.
It does not replace the historical observation or establish constant time.

## Artifacts and environment

Original Rust 1.99.1 address-controls executable SHA-256:
`4b98b2d41e709b455a104729f442b07c3ec2349d18d827b19ca06d404373dbee`.
Identical-input diagnostic copy SHA-256:
`17fa3db6bd1e7d3631f1319b2b7db6c7f90fc6fe3b21a0857d46972185be6b4f`.
Only the three corpus STP instructions at offsets/addresses `b894`, `b8ac`,
`b8bc` change their source registers to XZR. They store the 48 bytes of
generated key/block input; PRNG arithmetic and order-bit store remain unchanged.
File size, layout, timers, AES bodies and every other byte are unchanged.
This is not a production patch or a newly compiled measurement binary.

Use owner-confirmed Neoverse-V2 host `13.49.18.65`, SSH ED25519 fingerprint
`SHA256:YiDOyfhwOf+3je2sRxQGdD2mr+Tu0x4rsMBSo1nzmPk`, separate directory
`/home/ubuntu/brynja-fourth-alarm-0273-yQVXwUOb`. The original host is unavailable;
no claim of identical historic runtime or physical-machine conditions follows.
No concurrent verification workload is scheduled on this host for collection.

Collector SHA-256:
`1ce3ad576dc0a8679ee252468c20a0f0ebdfeb9aad5cfbc66af92a2581f38f67`.
The collector and identities are copied to the remote directory before sampling.
Each phase exclusively creates its destination and refuses to replace it.
Binary hashes are checked before and after each invocation.

## Prerequisites and fixed run list

Run `preflight separate-values` once for each binary. Strictly validate the
original's 234 vectors against OpenSSL and the patched preflight's complete
234-vector population against the original fixed-class vectors. Both classes
must agree in all 117 pairs, and the fixed-class results must be unchanged.
Do not measure if either preflight fails.

Measurement command, with equal-length binary basenames `original` / `ident000`:

```text
setarch aarch64 -R taskset -c 0 /home/ubuntu/brynja-fourth-alarm-0273-yQVXwUOb/BINARY measure separate-values
```

Environment is exactly `PATH=/usr/bin:/bin`, `LANG=C`, `OPENSSL_CONF=/dev/null`,
and `P` containing the declared number of ASCII `x` bytes. ASLR is disabled
only for the child invocation, not globally. Pin to allowed CPU 0.

Four repetitions, each with padding lengths 0, 16, 32, 48 in that order.
For repetition index `r` and padding index `p`, run original then identical
when `(r+p)` is even, otherwise identical then original. Total **16 pairs /
32 process launches**, 16 per binary, with balanced binary order per padding.
Each launch retains all 39 original campaigns, 8,192 pairs, four operations per
duration, 256 warmups, and the unchanged original seed/order. The extra
campaigns are retained because filtering them would change the exact binary.
Do not append runs after outcomes. Timeout is 60 seconds per launch; a process
failure, stderr, timeout or identity mismatch stops the experiment, with its
partial output preserved and no replacement invocation.

## Analysis and decision boundary

Primary diagnostic is AES-256 cached public-key, the exact fourth-alarm
campaign. Keep all other campaigns as context. Parse every raw sample with the
unchanged original policy and control marker validation. Policy SHA-256:
`08bb7ae4cd54255837eaf931ed59a272bb44c3714a481e4dd916bd4b26a956f9`;
control parser SHA-256:
`a0a6d763131fa1ede09fd7c3a4873f57b9c36d530ed2f0e0a519b7fb8e503c03`.

Retain each run's untrimmed means, Welch and paired statistics, CVs, alarms
and noise flags (threshold 4.5, CV 1.0, zero-variance inconclusive). Report
untrimmed mean differences for both binaries by padding and across all runs.
No trimming, pooling into a new acceptance test, p-value combination,
noise-based omission, threshold change or adaptive stopping is permitted.

An identical-input alarm demonstrates label/context discrimination without
different AES input values in this exact executable copy. Similar original
and identical-input offsets support a harness explanation; they do not prove
statistical equivalence or exclude a smaller simultaneous value effect. If
neither occurs, report the check as inconclusive rather than expanding it.
This finite check cannot prove the precise microarchitectural cause, transfer
the old host environment, or create a general timing pass. Preserve all
historical data and record the result separately from this declaration.
