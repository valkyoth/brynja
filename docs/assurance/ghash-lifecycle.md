# GHASH caller-storage lifecycle

The [public-API tests](../../crates/brynja-crypto/tests/ghash_lifecycle.rs)
place the key, input block, workspace and output in disjoint regions of one
live allocation, with sentinel bytes around the writable regions. A public
test subkey equal to the field identity makes the completed result known and
nonzero. Tests inspect caller storage after its exclusive borrow ends; they
do not read an object after its lifetime.

| Exit path | Workspace afterwards | Output afterwards |
| --- | --- | --- |
| Cancel after a partial update and a rejected over-budget append | Zero | Previous bytes unchanged |
| Consume with a partial final block | Zero | Previous bytes unchanged |
| Unwind in caller code with a partial block pending | Zero | Previous bytes unchanged |
| Successful finish | Zero while the result is still readable | Known intermediate, then zero on explicit clear or Drop |
| Unwind in caller code while a completed result is readable | Zero | Zero |

Every path also checks the key, input and sentinels for changes. Each unwind
case checks for its own payload so a failed assertion or an unrelated panic
does not count as exercising the intended exit.

Use `brynja-verify run ghash miri-lifecycle` or
`brynja-verify run ghash asan-lifecycle` for the registered Linux x86-64 runs.
Both use the repository's pinned evidence nightly and an unwinding test
profile. The byte assertions test clearing; ASan/LSan alone would not detect
a valid live buffer that was simply left uncleared. Neither those checks nor
Miri establish register/spill erasure, cleanup on abort or forgotten owners,
or side-channel resistance.
