# Portable AES fixed-versus-random host experiment

This is a separately registered v0.27.2 experiment, not a replacement for the
earlier zero-versus-FF screens, a release gate, or a constant-time certificate.
It copies `timing.rs` unchanged into the archive-only public consumer. Only the
direct portable API is selected; the facade is covered by separate functional
acceptance. No production AES code or dependency is added.

## Policy fixed before collection

- AES-128/192/256; 39 campaigns per compiler. Each width has six operation
  contrasts for each of ephemeral/cached owners (secret encrypt/decrypt and
  public encrypt, varying key or block separately), plus cached expansion.
- Each campaign has 256 warmup pairs and **8,192 measured pairs**, four repeated
  operations per class per pair. No adaptive stopping, sample rejection,
  trimming, cropping or retries-to-pass. Each measured duration is retained.
- The fixed class is all-zero in the varied field. The other field is 0x37.
  The random class uses fresh, reproducible public pseudorandom bytes for each
  pair. These are synthetic fixtures, not cryptographic randomness or secrets.
  SplitMix64 seed is `0x0272f17ed00d0001 XOR campaign_index`; six little-endian
  words supply key/block bytes and a seventh word chooses AB/BA order. Warmups
  consume the same sequence before measured samples. Campaign indices follow
  width, owner, then mode order in the fixture. There is no seed search.
- All input generation, class selection and cached-operation expansion happen
  outside the timer. Ephemeral measurements include key construction, expansion,
  operation and Drop. Cached block measurements exclude schedule construction
  and its Drop, but include secret-output Drop. Cached-import measures expansion
  and schedule Drop, not encryption. Public encryption includes explicit output
  publication. These are public API timings, not isolated round-instruction costs.
- The complete corpus is prepared first; integer results are buffered per
  campaign. Formatting and output occur between campaigns, not inside or
  between paired measurements. The monotonic `Instant` duration is nanoseconds;
  timer/loop overhead remains in the observation. Outputs reach `black_box`.
- Analyze all measured samples with first-order Welch's two-population statistic
  and a paired-difference statistic. **Either absolute t >= 4.5 raises an alarm**.
  A constant nonzero pair difference also alarms, including a singular
  denominator. No multiple-comparison correction is used: alarms prompt
  investigation, not an assertion of exploitability. The additional paired
  statistic makes pair-local effects visible; it does not eliminate dependence
  between observations or substitute for independent review.
- A class with zero sample variance, or a standard-deviation/mean ratio above
  **1.0**, makes the observation inconclusive, never passing. Report class
  means, maxima, variation and both statistics. Noise is not removed from the
  data. No higher-order, cache-state, power or EM claim is made.
- Native Linux host only, pinned to the lowest available logical CPU. Record
  CPU information, microcode where available, SMT siblings, governor, boost,
  initial load, target, exact `rustc -vV` and executable SHA-256. The runner does
  not disable SMT/boost or claim an isolated CPU. Virtualization, scheduling,
  frequency changes, thermal effects and other host activity remain limitations.
- Named compiler endpoints: 1.90.0 and 1.99.1. Explicit host target; opt-level 3,
  fat LTO, one codegen unit, overflow checks, panic abort. Other profiles require
  their own observation. Test harness unit checks use their normal unwind build.
- Before measurement, the exact executable's three sample positions per campaign
  (first/middle/last) and both classes must agree with one absolute OpenSSL oracle,
  itself preflighted with FIPS 197 examples. Both languages independently generate
  the same corpus. Archive graphs and the four harness tests must pass first.
  Binary/oracle hashes are checked after collection. Host, oracle and its shared
  libraries are trusted; hashes establish identity, not authenticity.
- A failed/partial run never receives a completion marker. The runner prints
  collected samples before analysis, including available timeout output. Keep
  the verifier's raw log and failed result. No rerun may erase or supersede an
  alarm without documenting the investigated cause and changed experiment.

The statistical approach is informed by the
[dudect implementation](https://github.com/oreparaz/dudect/blob/master/src/dudect.h),
but this is not dudect and does not reproduce its cropping, higher-order tests
or sample policy. Passing finite timing experiments is not a proof of constant
time; emitted-code review and the rest of the qualification matrix remain separate.

## Commands

```sh
brynja-verify run aes packaged-fixed-random-msrv
brynja-verify run aes packaged-fixed-random-current
python3 scripts/aes/test-aes-fixed-random.py
```

These registrations currently name Linux x86_64. The underlying runner also
accepts a native Linux AArch64 host, but no AArch64 result is implied by an x86_64
run or a cross-build. Register the native configuration separately when available.
The runner installs/uploads nothing. Remove ambient compiler, Python, OpenSSL
and loader overrides explicitly if present; it rejects rather than silently
ignores them. For example, `env -u LD_LIBRARY_PATH brynja-verify run ...` removes
only that override without claiming that shared libraries are measured.
