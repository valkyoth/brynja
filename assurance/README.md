# Assurance Harness And Bare-Metal Matrix

Status: v0.4.0 implementation stop; pentest required

This directory freezes the first-party assurance boundary before protocol or
cryptographic implementation begins. It is infrastructure evidence, not proof
that TLS exists or is secure.

`policy.toml` defines bounded deterministic mutation, raw-stdin differential
adapters, OS-less compilation targets, and exact external-tool source pins.
`evidence.json` is generated from that policy and the scripts, workflows, and
Cargo manifests that enforce it.

The harness protocol sends one bounded raw byte string to a child process on
standard input. A differential adapter returns exactly one canonical JSON
object:

```json
{"class":"accept","output":"00ff"}
```

`class` is `accept`, `reject`, or `unsupported`; `output` is lowercase
even-length hexadecimal. Adapters run without a shell, under a timeout and
input/output caps. A nonzero exit, timeout, malformed result, excess output, or
difference between implementations fails closed. Campaigns must use at least
two independently maintained implementations and record exact executable
hashes separately.

Harness input is public test data, never a secret. The runners do not claim to
provide an OS sandbox: every campaign launcher must independently deny network
access and unwanted filesystem, process, and device capabilities.

Repository assurance probes are bounded as well: local Rust target discovery
and each remote Git tag query have an explicit 30-second timeout. Expiration
fails the check instead of leaving development or release automation hanging.

Mutation order is deterministic and deduplicated. The runner covers the empty
case, original input, every bounded truncation, byte deletion, bit flip, and
zero/`0xff` insertion until the policy case limit. A failing case is identified
by SHA-256 and replay index; the runner does not persist input automatically.

The bare-metal matrix builds the complete workspace with all features for:

- `thumbv7em-none-eabi`;
- `riscv32imac-unknown-none-elf`; and
- `x86_64-unknown-none`.

These are OS-less compile claims only. They do not provide entropy, time,
transport, storage, allocation, interrupts, startup code, or an Aesynx support
claim.

The tool entries are source-policy pins. Ordinary builds do not download or
execute them, and no tool may enter a repository Cargo manifest. The owning
later milestone must independently verify installation, executable hashes,
configuration, evidence, limitations, and current upstream status before
making any assurance claim.

Run:

```bash
python3 scripts/check-assurance.py
python3 scripts/test-assurance.py
scripts/check-bare-metal.sh
```
