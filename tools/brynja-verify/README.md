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

See the [everyday guide](../../docs/assurance/brynja-verify.md) for all commands,
registry format, history, limitations and troubleshooting. The catalog has 27
portable harness checks across nine hash/MAC components. Native, hosted and
proof assessments retain their existing catalog and historical evidence; a
portable check is not a claim to complete those assessments.
