# GHASH PMULL: order-control follow-up

## Protocol fixed before collection (2026-11-22)

This is a new diagnostic, not a rerun or a release gate. The [original
AWS observation](ghash-acceleration.md#accelerated-arm-timing-screen-protocol-declared-before-collection)
tied the first label to the pair index's parity. Its latest-compiler
identical-input alarm remains recorded, regardless of this result.

Run exactly one new process per compiler (1.90.0, then 1.100.0), on the
lowest available CPU of the native Linux Neoverse-V2 with PMULL. Require
a known product and a real native block before timing. Keep the three
campaigns, 64 warm-up pairs and 2,048 measured pairs per campaign. Time
16 updates plus finish and clearing; do not include input staging or printing.
Use the same key and block storage for both labels. In every four-pair
group choose one of each first label at even indices and one of each at
odd indices, using a deterministic stream independent of the input stream.

Primary comparisons: label 0 minus label 1 within each pair. Retain the
original rule: alarm at absolute paired t >= 4.5 or a constant nonzero
difference. Separately report mean first-minus-second duration for even
and odd pairs, descriptive only. No trimming, subtraction, retries,
follow-up launch selection or threshold adjustment. A clean new control
cannot validate the old launch. This is a different binary; it cannot
isolate code layout, CPU frequency, scheduling or prove constant time.

To reproduce, from the checkout use
`python3 scripts/ghash/check-pmull-order.py prepare NEW_BUNDLE`. Transfer
the bundle and the scripts `check-pmull-order.py`, `check-pclmul-screen.py`,
and `check-portable-host.py` (keep the three scripts together). On the
native machine run `python3 check-pmull-order.py measure BUNDLE NEW_RESULTS`.
Run `python3 check-pmull-order.py replay RESULTS` anywhere for analysis only.
Collection never replaces an existing results directory.
