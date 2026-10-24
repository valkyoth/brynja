"""Reviewed descriptor declarations and thin resident-wrapper premises."""
import hashlib
import re

import legacy_hmac_engine_codegen as shared

inventory = shared.load('hmac_inventory')
ROOT, require = inventory.ROOT, shared.require
PREFIX = 'crates/brynja-legacy-hmac-std/src/'
MEMORY = 'crates/brynja-crypto-cpu-std/src/macos_resident/memory.rs'
# ResidentBytes::{clear,as_bytes_mut} are direct calls to their single Mapping.
# Mapping's implementation is already pinned by hmac_hosted_contracts. This pin
# is a review/drift premise, not independent authentication or native evidence.
MEMORY_SHA = 'c79f810ea45d43ce73319a033a9b3bd64853d98eac0c90bee45ac0ca765eabc8'


def declarations(apple):
    stack, buffer = ('ResidentStack', 'ResidentBytes') if apple else ('ProtectedStack', 'ProtectedBytes')
    resource = 'macos_resident' if apple else 'protected_memory'
    return {
        ('mod.rs', 'Session', 'struct'): f'''stack:{stack}, staging:{buffer}, output:{buffer}, bytes:usize,
            limits:Limits, identity:PhantomData<fn()->A>, #[cfg(test)] fault:tests::Fault,''',
        ('mod.rs', 'Buffers', 'struct'): f"output:&'a mut {buffer}, staging:&'a mut {buffer}, keep:bool,",
        ('sha1_compiled.rs', 'Sha1CompiledSession', 'struct'):
            'inner:Session<Sha1>, backend:Sha1Backend, quarantined:bool, #[cfg(test)] fault:tests::Fault,',
        ('md5_compiled.rs', 'Md5BatchSession', 'struct'): f'''stack:{stack}, staging:{buffer}, output:{buffer},
            backend:Md5Backend, bytes:usize, limits:Md5BatchLimits, quarantined:bool, #[cfg(test)] fault:tests::Fault,''',
        ('types.rs', 'Request', 'struct'): "pub key:&'a[u8], pub chunks:&'a[&'a[u8]], pub tail:Bits<'a>,",
        ('types.rs', 'Bits', 'struct'): "pub bytes:&'a[u8], pub valid_bits:u8,",
        ('types.rs', 'Error', 'enum'): f'''Resource({resource}::Error), InvalidLimits, InvalidTagPolicy, WorkLimit,
            InvalidBits, OutputLength, Cancelled, Mac(brynja_legacy_hmac::Error), Invariant, Quarantined,''',
        ('md5_compiled/types.rs', 'Md5BatchInput', 'struct'): "pub key:&'a[u8], pub message:Bits<'a>,",
        ('md5_compiled/worker.rs', 'Parameters', 'struct'): 'pub backend:Md5Backend, pub bytes:usize, pub budget:usize,',
    }


def validate(root=ROOT):
    for directory in ('strict_execution', 'macos_resident'):
        for (file, name, kind), expected in declarations(directory == 'macos_resident').items():
            source = inventory.rust.scrub((root / (PREFIX + directory + '/' + file)).read_text())
            _, body = inventory.rust.declaration(source, name, {kind})
            compact = lambda text: re.sub(r'\s+', '', text)
            require(compact(body) == compact(expected), 'legacy launch descriptor declaration drift: ' + name)
    require(hashlib.sha256((root / MEMORY).read_bytes()).hexdigest() == MEMORY_SHA,
            'legacy hosted resident wrapper premise changed')
