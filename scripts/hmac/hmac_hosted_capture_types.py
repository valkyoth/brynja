"""Source declaration premises for non-secret launch descriptor classifications."""
import re

import hmac_inventory as inventory

require = inventory.require
ROOT = inventory.ROOT
PREFIX = 'crates/brynja-crypto-cpu-std/src/'


def compact(text):
    return re.sub(r'\s+', '', text)


def declarations(directory):
    apple = directory.startswith('macos_resident')
    storage = ('Mapping', 'Mapping') if apple else ('ProtectedStack', 'ProtectedBytes')
    return {
        ('mod.rs', 'Session', 'struct'): f'''
            stack:{storage[0]}, staging:{storage[1]}, output:{storage[1]},
            policy:TagPolicy, bits:usize, limits:Limits, _algorithm:PhantomData<fn()->A>,
            #[cfg(test)] fault:tests::Fault,
        ''',
        ('compiled.rs', 'CompiledSession', 'struct'):
            'inner:Session<A>, kernel:Kernel, quarantined:bool,',
        ('types.rs', 'Request', 'struct'):
            "pub key:&'a[u8], pub chunks:&'a[&'a[u8]], pub tail:Bits<'a>,",
        ('types.rs', 'Bits', 'struct'): "pub bytes:&'a[u8], pub valid_bits:u8,",
        ('types.rs', 'TagPolicy', 'enum'): 'Full, Bytes(usize),',
    }


def validate(root=ROOT):
    for directory in ('strict_hmac', 'macos_resident/hmac'):
        for (file, name, kind), expected in declarations(directory).items():
            source = inventory.rust.scrub((root / (PREFIX + directory + '/' + file)).read_text())
            _, body = inventory.rust.declaration(source, name, {kind})
            require(compact(body) == compact(expected), 'hosted capture declaration drift: ' + name)
