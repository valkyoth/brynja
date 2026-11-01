# brynja-verify

Standalone local developer runner and evidence-status tracker. Not a production
crate, crypto implementation, certification or release gate.

```sh
cargo install --path tools/brynja-verify --locked
brynja-verify md5
brynja-verify run md5 known-answers
```

The first command after installation scans status only. The second explicitly
runs one registered check. `full-check` is also a status-only scan.

Status output groups configurations under their test/harness command and
category, with outcome/freshness counts and latest member execution dates.
Miri profiles stay separate. `list COMPONENT [CATEGORY]` lists individual IDs;
`show COMPONENT ID` shows their exact commands, dates, sources and history.
Grouping changes neither execution selection nor stored evidence.

See the [everyday guide](../../docs/assurance/brynja-verify.md) for all commands,
registry format, history, limitations and troubleshooting. The runnable registry
has 27 portable harness checks, 48 scoped sanitizer commands, 4,933 existing
Miri configurations, nine bounded Kani proof groups, 350 compiler compatibility
checks and 320 component fixture/script checks. Use `md5 --category kani`
to inspect proof status without execution. Miri profiles overlap: select one exact task
or `--category miri-routine`, `miri-extended` or `miri-existing-full`. Use
`run md5 --needed --category asan` to select just MD5 sanitizers. The full existing
inventory is also visible with `list COMPONENT [CATEGORY]` and
`show COMPONENT ID`, including native/hosted/proof entry points and saved history.
All catalog assessments now have scoped runnable bindings or explicit manual
dispositions. Registration is not execution or a current-pass claim.
One hundred twelve owner-approved manual diagnostics retain their commands and history but
are not unfinished checks or implicit runs. Supporting entry points and retired
history are also reference-only. No assessment bindings remain unresolved;
historical inputs that cannot be mapped reliably still remain historical.
