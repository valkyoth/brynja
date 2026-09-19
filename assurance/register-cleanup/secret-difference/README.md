# Borrowed comparison development fixture

Compiles the actual first-party byte-difference boundary. Exhaustive truth-table,
immediate register/flags snapshots and guarded byte-edge tests cover x86 Linux
and emulated AArch64 Linux. Shared inputs may alias; output cannot overlap them.
The companion `../check_secret_difference.py` inspects emitted code and rejects
compiled algorithm/cleanup mutants. Other target compilation is not native
execution evidence. This does not claim caller/spill/interruption erasure,
independent verification or FIPS validation. No release gate is changed.
