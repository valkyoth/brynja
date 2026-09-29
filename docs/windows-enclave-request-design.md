# Public request snapshot enclave experiment

This v0.24.50 research step extends the scoped hardened SHA-256 owner experiment
with bounded host input and explicit public output. It is **not** a confidential
host-to-enclave channel. Windows strict remains unsupported. Production crypto,
release policy and existing native experiment sources are unchanged.
The [native observations](windows-enclave-request-results.md) retain normal
results, rejected mutations and the unexpected raw-read termination code.

The fixed wire is 1072 bytes: six little-endian u64 fields followed by a 1024-byte
inline payload. Fields are version (1), operation (1 publish, 2 discard), input
length (0..1024), opaque host destination, destination width, and public-output
flag. Publish requires width 32, nonzero non-overflowing destination and exactly
`0x5055424c4943`. Discard requires destination, width and flags all zero. No request
field is a Rust reference. The public-output flag is a caller assertion, not
provenance verification, authentication or authority to declassify actual secrets.

Before entry, the C scaffold restricts direct containing-process access and never
relaxes it. Microsoft documents that the explicit
[copy-in](https://learn.microsoft.com/en-us/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclavecopyintoenclave)
and [copy-out](https://learn.microsoft.com/en-us/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclavecopyoutofenclave)
APIs remain usable with
[restricted host access](https://learn.microsoft.com/en-us/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclaverestrictcontainingprocessaccess).
Only S_OK is accepted. The complete fixed request is copied once into private
storage; all subsequent parsing and hashing uses that snapshot. This does not
promise that a racing host cannot change bytes *during* the initial copy; any
resulting snapshot is untrusted and validated. A fixed diagnostic callback changes
host header/payload after copy to prove the original source is not reread.

Snapshot, existing in-place SHA-256 workspace and digest destination must fit
entirely in the locked, guarded 64 KiB live window. The workspace is checked clear
after its scope; the secret digest owner is dropped and checked clear after export
or discard. Snapshot/output clearing is checked before outer-window clearing.
All reported ranges must be disjoint. Opaque workspace inspection retains the
previous exact-layout checks, not a general raw-object inspection permission.

Copy-out explicitly releases a public digest only. Copy-out failure can have
partially modified the host destination: no atomicity, rollback or confidential
output guarantee is claimed. Discard exports no digest. Diagnostics disclose
public input length, status, and storage geometry. Fatal abort and compiler/caller
copies remain outside this step's cleanup observations.

Local tests cover every permitted length, malformed fields, partial copy failure,
discard, output cleanup, and mutations that reread the snapshot, omit clearing or
omit the public-output flag check. The native runner additionally checks Python
hashlib results, host-buffer canaries, copy errors, overlapping public output,
restriction state, page-lock handshake and teardown. A separate raw-host-read
negative image is expected to crash under restricted access; a crash is never
reported as successful cleanup. All results remain OBSERVATIONS_ONLY.

This remains a single-worker scaffold with diagnostic exports, not a sealed
production ABI. It has no authenticated request channel, persistent result handle,
replay defense, concurrent caller guarantee, full worker/runtime/TLS dump coverage
or production signing. Those remain separate work before Windows strict support.
