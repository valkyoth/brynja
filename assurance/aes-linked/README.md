# Packaged final-linked portable AES fixture

`linked.rs` is copied unchanged beside the frozen public consumer fixture into
an isolated workspace. All first-party dependencies resolve to byte-checked
Cargo archives. `direct` and `facade` select the normal public import routes;
neither enables an accelerated backend or changes production AES.

The executable checks the original FIPS 197 Appendix C AES-128/192/256 examples
with both key-owner forms, both secret-output directions and explicit public
encryption: 18 operations. Caller-owned key/schedule storage and secret output
clearing are asserted. Inputs pass through `black_box` to inhibit constant
folding; this is a fixture measure, not a constant-time or erasure guarantee.

The runner builds Rust 1.90.0 and 1.99.1 release binaries with opt-level 3, fat
LTO, one codegen unit, overflow checks, no stripping and abort/unwind profiles.
It inspects and executes those exact binaries, recording their identities.
See [the bounded final-link review](../../docs/assurance/aes-linked-review.md)
for the machine-code scope and unfinished work. The pre-existing public API
fixture is not edited or replaced by this additional executable.
