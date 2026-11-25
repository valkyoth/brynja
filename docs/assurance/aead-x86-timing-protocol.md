# v0.29.3 paired x86 timing observation — collection protocol

Collect once per compiler (1.90.0 then 1.100.0), on this Linux AMD Ryzen 9
9950X3D, pinned to the lowest permitted logical CPU. Use an offline release
example built against unpacked local Cargo archives, direct import, default
features off, both composition features enabled, `+aes,+sse2`. Require the
native pair. Neither CPU pinning nor timing instrumentation applies to the library.

For each AES width (128, 192, 256), use fixed synthetic keys, separate between
GCM and GMAC, 12-byte IVs, 16-byte tags and 33-byte data. Exercise four contrasts:

- GCM disjoint seal: all-zero vs all-ones plaintext, fixed AAD.
- GCM disjoint open: reject a valid tag altered in its first vs last byte.
- GMAC generation: all-zero vs all-ones AAD.
- GMAC verification: reject a valid tag altered in its first vs last byte.

Run an identical-input control before each contrast (both classes take the first
value). Sending owners always consume successive counters: the control uses
identical **caller data**, not identical IVs. Balance class order in adjacent
pairs. Use the same input addresses for both classes, with material staged
before the clock starts. Preflight against portable owners before sampling.
Time four public API calls per sample, including checking the result, but not
key import, pair admission, corpus preparation, allocation or output logging.
Finally run one timer sensitivity control with an intentional 256-step serial
work difference. It tests the timer/analysis, not the cryptography.

For each of the 25 campaigns collect 32 warm-up pairs (not analysed), then
1,024 measured pairs with deterministic, balanced AB/BA order. Retain every
measured duration and its order. For each endpoint flag any absolute paired
or Welch t-score >= 4.5 in the 24 ordinary campaigns. Require the positive
control to cross 4.5 in the expected direction (class B slower) in both scores.
No trimming, retries to pass, post-hoc threshold changes or extra hosts to
replace a result. An alarm, failed control, or incomplete run stays visible;
do not interpret it as proof of leakage or absence of leakage.

Scope: one host, one launch per compiler, one public message size, verification
rejections and sending operations only. No inference about varying secret keys,
successful opens, general IVs, other tag lengths, profiles, workloads or ARM.
