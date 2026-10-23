"""Source-bound non-unwinding premises, not authenticated review approval."""
import hashlib

import hmac_execution_construct_contracts as clearing
from hmac_engine_codegen import require

ROOT = clearing.ROOT
PREFIX = 'crates/brynja-crypto-cpu-std/src/'
# Reviewed production (not cfg(test)) paths: join is one C-ABI pthread_join;
# attribute destruction is C-ABI pthread_attr_destroy or process::abort;
# Mapping.clear is guarded slice construction plus clear_owned_region. Darwin
# also checks its owner PID through non-unwinding C-ABI getpid. None calls a
# user callback, allocates, or performs fallible indexing/arithmetic. Rust may
# conservatively emit invoke, but these exact callees cannot Rust-unwind.
# Pin module routing too. Drift reopens this premise, not an automated approval.
INPUTS = {
    'lib.rs': 'bf49ce9a1c7420df5be6fcae6a93ff16d1d6631e436e2f2982df16b8dccfc26e',
    'protected_memory/mod.rs': '7e9f07881101f924f7ff50ace53b096ebf202f9d670a9e8ddb9639ca710e791e',
    'protected_memory/platform.rs': '35e77466f3e2400ae70de5aed806d14ea4c5d8ea6f59bf8e89099313fcd3bf7e',
    'protected_memory/platform/thread.rs': 'ad5929a5b0f283aa57ef2b7c5801fb86e5ede6bbdee48f3d1b72cb8549797ed9',
    'macos_resident/mod.rs': 'ede8bee6c35de32fcd6c7e97b472c61382c36ed527d1fb329e0391f7123c7508',
    'macos_resident/resource.rs': 'f55aedc8daafffc90bbf3f668d107cd6014820be32522e3708bdb073af8d1912',
    'macos_resident/resource/darwin.rs': 'a32e1624f4e8bdcc4b129db19e26af37ae88096fb417caeeaac51c8d2aaa8d04',
    'macos_resident/resource/darwin/thread.rs': '0a5d3e71e6938fa0a46e10b486e58e1f6b61229a4496bef1238c4b37a2d87a59',
}


def validate(root=ROOT):
    clearing.validate(root)
    for name, digest in INPUTS.items():
        require(hashlib.sha256((root / (PREFIX + name)).read_bytes()).hexdigest() == digest,
                'hosted non-unwinding resource premise changed: ' + name)
