# Focused assurance from v0.24.20

The long Miri suite is selected by impact, not by whether a version number or
lockfile byte changed. This is an execution policy, not independent verification.
The normal repository gate, workspace tests, Clippy, documentation, security
policies, dependency checks and emitted-code checks remain mandatory. The
currently bounded AddressSanitizer and Kani suites remain required local checks;
this change targets the long interpreted Miri campaigns, not removal of cheap
regression coverage. Hosted CI retains its bounded checks and CodeQL Default.

| Change | Miri execution |
| --- | --- |
| Public crates.io checkpoint | Every registered full group |
| Documentation, local version-only pins | Smoke for each registered group |
| MD5 or SHA-1 source | Changed primitive plus legacy consumer; smoke elsewhere |
| SHA-3 source | SHA-3, KMAC, TupleHash, ParallelHash; smoke elsewhere |
| Shared core or unknown runtime/compiler impact | Full affected closure, or all groups if classification is uncertain |
| Isolated new consumer fixture | That fixture's full group; smoke on unchanged dependencies |
| Registry dependency version/checksum/edge | Consumers reached through both old and new lock graphs; unknown consumers force all groups |

`scripts/zeroization/check-tag-miri.sh internal` selects the nearest signed
ancestor tag at HEAD, including dirty candidate work. The selector includes
staged, unstaged, deleted, renamed and nonignored untracked files. Invalid or
unsigned/nonancestor baselines, unreadable/symlinked inputs, unsupported lock
schemas, ambiguous package identities and unknown Rust/native source fail
closed to full coverage. Full coverage still means the documented registered
campaigns, not every possible input or a mathematical correctness proof.

Lockfile classification ignores **local package versions only**, retaining
registry versions/checksums and dependency edges. Both graphs are traversed so
removed dependencies cannot hide consumers. Local-path manifest version pins
are metadata only when all other fields are identical; registry manifest
versions are not exempt. Three enumerated consumer policy files may update
only their exact facade-version literals without invalidating crypto evidence.
Named source-digest maps and TOML hash inventories can rebind hashes without
rerunning unrelated owners: the changed source paths are independently selected,
and mandatory source-policy gates still verify the bindings. Map keys, control
flow, test-vector literals and non-digest values do not receive this exemption.

Changes to named full-group bodies select those groups. Updated smoke cases
run as smoke, which every focused invocation already requires. KMAC smoke
checks secret-output lifetime; TupleHash smoke checks abandoned-item failure,
not their much larger domain-separation campaigns. Those campaigns remain in
the unchanged full groups. Shared execution-helper
or unrecognized runner changes remain full-suite triggers. Adding registered
groups does not invalidate old groups. Reviewed coverage-orchestration changes
run their full structural and executable regression tests, not every old hash
input. Miri/sanitizer nightly-pin-only updates run smoke under the new verifier;
previous full evidence remains explicitly tied to its old verifier and is not
silently relabelled. The next public checkpoint renews the complete evidence.
Production compiler changes remain a full-suite trigger.

The registry and dependent-consumer map must be extended when a new algorithm
or construction is introduced. Unknown native/Rust files are never assumed
unrelated. Exceptional pentests, independent-review limits and the committed
report -> green GitHub/CodeQL -> owner-approved signed tag flow are unchanged.

Inspect and test selection without launching Miri:

```sh
python3 scripts/zeroization/miri_scope.py --base v0.24.19
python3 scripts/zeroization/test-miri-scope.py
python3 scripts/zeroization/test-scope-inputs.py
```

For this acceptance-only candidate the full group is `legacy`; the underlying
SHA-1/MD5 implementations have not changed. Old primitives receive smoke
coverage. A future edit to either primitive expands the selected closure.
