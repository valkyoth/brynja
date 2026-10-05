"""Offline saved-image reduction/retirement review, not a general concurrency proof."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_publication_review as publication
from windows_enclave_frame_geometry import require

slot = publication.slot
caller = publication.caller
C_OBJECT = 'fdd82832930eff919311de11e4603ab01ec64c65752dd477e544b5908782db37'
CLOSURE = '_RNCNvCsk1CFy3R4N16_20parallel_wave_bridge4root0B3_'
BODIES = {
    'root': ('PrivateWaveRoot', 3656, '3eacddc25809852748e8d5a91008e91e5be0e1e3afd4e38aad7d161ac162a625'),
    'dispatch': (CLOSURE, 1516, '0a8afb66a0f4973f33d4f4b8c19a3eef09f474be56d6b9b5918a0b4bd54cc613'),
    'retire': ('PrivateSchedulerRetire', 318, '5542b7d575c7eb0333067a2587fcd85b0a0c330470cbe8b2a269e0559ad29c30'),
}
REFERENCES = {
    'root': 'e0d76aadd91072680d284bbc5e19b7e52a6299fd2fface697aa161e8dd01ea98',
    'dispatch': 'fe3bd7689c39b7d1dcfa9f017c028e0bef7a3176197c5f002284b82fe03b0981',
    'retire': '4bd3b2c218626eb5cdb4625b2673fead1c9289fc141ae2eadd74dc06da312c98',
}
CALLS = {
    'root': {0x886: CLOSURE, **dict.fromkeys((0x8e2, 0x91f, 0x95c, 0x999), slot.BODIES['absorb'][0]),
             **dict.fromkeys((0xab4, 0xd5e), slot.BODIES['drop4'][0]),
             0xc77: 'PrivateSchedulerRetire', 0xd7a: publication.BODIES['option_drop'][0],
             0xe38: publication.BODIES['drop'][0], 0xe42: 'PrivateWaveAbort'},
    'dispatch': {0x1b9: 'PrivateWaveDispatch', 0x1c6: publication.BODIES['join'][0], 0x5e6: 'PrivateWaveAbort'},
    'retire': {0x139: 'PrivateWaveAbort'},
}
# These landmarks explain the manual review; whole-body/reference pins cover
# intervening instructions too. They are not a general machine-code verifier.
ANCHORS = (
    ('root', 0x8de, '4531c9'), ('root', 0x900, '41b901000000'),
    ('root', 0x93d, '41b902000000'), ('root', 0x97a, '41b903000000'),
    ('root', 0xa60, '4803842408120000'), ('root', 0xa6e, '4c03a42400120000'),
    ('root', 0xa7c, '483b8424f8110000'), ('root', 0xa8a, '4c3ba424f0110000'),
    ('root', 0xa98, '48898424081200004c89a42400120000'),
    ('root', 0xaa8, '488d8c24c0010000c5f877'),
    ('root', 0xc29, '81e1f000060081f900000400'),
    ('root', 0xc3b, '80bc24d401000000'),
    ('root', 0xc51, '8b9424d001000048c1e220f0480fb111'),
    ('root', 0xc67, 'c68424d4010000018b8c24d0010000'),
    ('root', 0xc7b, '4883f801'),
    ('dispatch', 0x1ca, '4883fe01'),
    ('dispatch', 0x1e8, '81e2f000060081fa00000400'),
    ('dispatch', 0x202, '4139c8410f95c04108d0'),
    ('dispatch', 0x212, 'c1e80883e00f41b00139c8'),
    ('dispatch', 0x30b, '81e1f000060081f900000400'),
    ('dispatch', 0x32a, '81e1f000060081f900000400'),
    ('retire', 0x79, '48bb0000000001000000'),
    ('retire', 0x88, '48be00000000ffffffffbff000f7ff'),
    ('retire', 0xcd, '4823cf4881f900000200'),
    ('retire', 0xf0, '488bca488bc24823cef0480fb10d00000000'),
    ('retire', 0x105, '0f94c185c9'),
)
BRANCHES = (
    *[('root', offset, b'\x0f\x85', 0xd52) for offset in
      (0x88c, 0x89c, 0x8b1, 0x8e8, 0x925, 0x962, 0x99f, 0x9ba, 0x9d7,
       0x9e7, 0xa04, 0xa12, 0xa2f, 0xa3d, 0xa5a)],
    ('root', 0xa68, b'\x0f\x82', 0xd52), ('root', 0xa76, b'\x0f\x82', 0xd52),
    ('root', 0xa84, b'\x0f\x87', 0xd52), ('root', 0xa92, b'\x0f\x87', 0xd52),
    *[('root', o, b'\x0f\x85', 0xe2f) for o in (0xc35, 0xc43, 0xc61, 0xc7f)],
    ('root', 0xc97, b'\x0f\x82', 0x525), ('root', 0xe3c, b'\xe9', 0xd7e),
    ('dispatch', 0x1ce, b'\x0f\x85', 0x2a1),
    ('dispatch', 0x20c, b'\x0f\x85', 0x2a1), ('dispatch', 0x21d, b'\x0f\x85', 0x2a4),
    ('dispatch', 0x317, b'\x74', 0x338), ('dispatch', 0x336, b'\x75', 0x2f0),
    ('retire', 0xd7, b'\x75', 0x10c), ('retire', 0xdf, b'\x75', 0x10c),
    ('retire', 0xee, b'\x75', 0x10c), ('retire', 0x10a, b'\x75', 0x118),
    ('retire', 0x114, b'\x73', 0x138), ('retire', 0x116, b'\xeb', 0xa0),
)


def check_bodies(bodies):
    require(set(bodies) == set(BODIES), 'complete retirement body population')
    for name, (_, size, digest) in BODIES.items():
        require(len(bodies[name]) == size and hashlib.sha256(bodies[name]).hexdigest() == digest,
                'reviewed retirement body: ' + name)


def check_references(refs):
    require(set(refs) == set(REFERENCES), 'complete relocation population')
    for name, rows in refs.items():
        serialized = json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()
        require(hashlib.sha256(serialized).hexdigest() == REFERENCES[name], 'complete relocation identity')


def check_instructions(bodies, refs):
    require(set(bodies) == set(refs) == set(BODIES), 'complete instruction inputs')
    for name, calls in CALLS.items():
        for offset, symbol in calls.items():
            require([r for r in refs[name] if r['offset'] == offset] ==
                    [dict(offset=offset, symbol=symbol, addend=0, trailing=0)], 'reviewed call reference')
            require(bodies[name][offset-1:offset+4] == b'\xe8\0\0\0\0', 'complete direct call')
    for name, offset, hexcode in ANCHORS:
        code = bytes.fromhex(hexcode)
        require(bodies[name][offset:offset+len(code)] == code, 'retirement instruction landmark')
    for name, offset, opcode, target in BRANCHES:
        width = 4 if len(opcode) == 2 or opcode == b'\xe9' else 1
        field = offset + len(opcode)
        require(bodies[name][offset:field] == opcode and
                field+width+int.from_bytes(bodies[name][field:field+width], 'little', signed=True) == target,
                'retirement branch destination')


def retirement_ready(word, generation):
    """Model the reviewed C predicate, not its atomic interleavings."""
    require(type(word) is int and 0 <= word < 1 << 64 and
            type(generation) is int and 0 <= generation < 1 << 32, 'bounded gate inputs')
    mask = (word >> 12) & 15
    return (word >> 32) == generation and mask != 0 and word & 0xfff700f0 == 0x20000 and \
        word & 15 == mask and (word >> 8) & 15 == mask


def inspect(data, native, image, mutate=False):
    require(hashlib.sha256(native).hexdigest() == C_OBJECT, 'original native object')
    pub = publication.inspect(data, image)
    slots = slot.inspect(data, image)
    objects = {name: native if name == 'retire' else data for name in BODIES}
    bodies, refs = {}, {}
    for name, (symbol, _, _) in BODIES.items():
        bodies[name], refs[name] = caller.function(objects[name], symbol)
    check_bodies(bodies)
    check_references(refs)
    check_instructions(bodies, refs)
    records = {n: slot.binding.bind(objects[n], image, s[0]) for n, s in BODIES.items()}
    known = {r['entry']: r['rva'] for r in [*records.values(), *pub['entries'].values(), *slots['entries'].values()]}
    known['PrivateWaveAbort'] = pub['fastfail_rva']
    for record in records.values():
        for symbol, target in record['reference_targets'].items():
            if symbol in known: require(target == known[symbol], 'closed reviewed call edge')
    # Inlined normal/error join paths clear the very same publication globals.
    rows, _ = caller.pe.linked(image)
    for name, starts in (('root', (0xba6,)), ('dispatch', (0x33b, 0x458))):
        for start in starts:
            for index, expected in enumerate(publication.store_refs('join')):
                offset = start + index*11
                actual = [r for r in refs[name] if r['offset'] == offset]
                require(actual == [expected | {'offset': offset}], 'inlined join global identity')
                require(bodies[name][offset-3:offset+8] == b'\x48\xc7\x05' +
                        expected['addend'].to_bytes(4, 'little', signed=True) + bytes(4), 'inlined zero store')
                field = slot.binding.mapped(rows, records[name]['rva']+offset, 4)
                address = records[name]['rva']+offset+8+int.from_bytes(field, 'little', signed=True)
                require(address == pub['zero_stores'][index]['rva'], 'same linked store address')
    count = 0
    if mutate:
        for name, code in bodies.items():
            for index in range(len(code)):
                changed = bytearray(code)
                changed[index] ^= 1
                try: check_bodies(bodies | {name: bytes(changed)})
                except ValueError: count += 1
                else: raise AssertionError('accepted retirement body mutation')
    return dict(schema=1, date='2026-10-05', status='AUTHOR_SELECTED_REDUCTION_RETIREMENT_REVIEW',
                object_sha256=slot.OBJECT, native_object_sha256=C_OBJECT, image_sha256=slot.IMAGE,
                entries=records, instruction_landmarks=len(ANCHORS), branch_landmarks=len(BRANCHES),
                body_byte_mutations_rejected=count, inlined_metadata_zero_stores=33,
                slot_addresses_from_root_rsp=[448,536,624,712],
                normal_reuse_order=['dispatch joins', 'ordered reduction', 'drop four slots',
                                   'Rust generation retire', 'native generation retire', 'next input copy'],
                native_readers_block_retirement=True, native_retirement_poll_budget=1 << 32,
                native_run_added=False, arbitrary_exception_cleanup_qualified=False,
                whole_image_qualified=False, release_gate_changed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('object', 'native_object', 'image'): parser.add_argument(name, type=Path)
    parser.add_argument('--mutate', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = inspect(args.object.read_bytes(), args.native_object.read_bytes(), args.image.read_bytes(), args.mutate)
    sources = ('windows_enclave_retirement_review.py', 'test-windows-enclave-retirement-review.py',
               'windows_enclave_publication_review.py', 'windows_enclave_slot_review.py',
               'windows_enclave_caller_binding.py', 'windows_enclave_caller_unwind.py',
               'windows_enclave_caller_handlers.py', 'windows_enclave_caller_object.py',
               'windows_enclave_wrapper_binding.py', 'windows_enclave_frame_geometry.py')
    result['source_sha256'] = {n: hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest()
                               for n in sources}
    text = json.dumps(result, indent=2)+'\n'
    if args.output: args.output.write_text(text, encoding='utf-8')
    else: print(text, end='')
