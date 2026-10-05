"""Selected saved-root normal returns, not whole-image or exception qualification."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_retirement_review as retirement
import windows_enclave_terminal_review as terminal
from windows_enclave_frame_geometry import require

slot = terminal.slot
caller = retirement.caller
INPUT = '_RNvMs1_Cs8LdeoEVKasr_14parallel_inputNtB5_10InputFrame6finish'
BODIES = {
    'root': retirement.BODIES['root'],
    'input': (INPUT, 186, '3f7246352fece17beb28a90a7f38d47e3682d031d73210a1d4839738da9726be'),
    'complete': ('PrivateSchedulerComplete', 76, '64ce43b550ffa94bbfe71b41a2fddc87ed07426c7f52ca0fac6c64ded4563470'),
    'output': ('PrivateInputOutput', 162, '27d5aabb9ecccb446b6446634dbd56cf9cd0bb658a52d16e07ce7b956bf6782f'),
    'region': ('PrivateWaveRootRegion', 51, '86bf48ae24ea669091c1255e988a9384dafa08f5c6c6cb0f0390845a32377d23'),
}
REFERENCES = {
    'root': retirement.REFERENCES['root'],
    'input': 'c6d4d5c4b218a6291b17c2dea08718df697ddf264092935adb0255c987b6b5a9',
    'complete': '568d23e999bf82edbeb5cba42c573fa12785c07dfd8c607b90b3162310722c01',
    'output': '083626736c2853e0768c410014d9026327f23e50d3d06a4391d913132552431c',
    'region': 'd5cc04690a03c682957641d1e4fd4dd2f35dba27a69ff68bb8b7dd4f254cb210',
}
CALLS = {
    'root': {0xca6: INPUT, 0xcbb: terminal.WAVES+'6finish', 0xccd: 'PrivateSchedulerComplete',
             0xcf5: 'memcpy', 0xd02: 'PrivateWaveRootRegion', 0xd2d: terminal.WAVES+'13declassify_to',
             0xd87: terminal.DESTRUCTOR, 0xdfc: 'PrivateInputOutput', 0xe26: terminal.DROP,
             **dict.fromkeys((0x20f, 0x21c, 0x229, 0x259, 0x266, 0x273, 0xde7, 0xe19), slot.CLEAR)},
    'input': dict.fromkeys((0x2d, 0x3e, 0x4f, 0x73, 0x84, 0x95), slot.CLEAR),
    'output': {0x77: 'EnclaveCopyOutOfEnclave'},
}
# Whole-body/relocation pins cover intervening instructions; these landmarks
# make the manually reviewed normal/error paths explicit, not a disassembler.
ANCHORS = (
    ('root', 0x24d, '4531f6'), ('root', 0x277, '4c89f0'), ('root', 0x28d, 'c3'),
    ('root', 0xc9d, '488d8c2458120000'), ('root', 0xcaa, '3cff'),
    ('root', 0xcb2, '488d8c24000a0000'), ('root', 0xcbf, '3cff'),
    ('root', 0xcd1, '4883f801'), ('root', 0xcdb, '4c8db424c0010000488d94242827000041b800040000'),
    ('root', 0xd06, '4883f801'), ('root', 0xd0c, '4c8b4424684983c00749c1e803'),
    ('root', 0xd19, '488d8c24000a0000488d9424c00100004d89c6'),
    ('root', 0xd31, '3cff'), ('root', 0xd39, '4531f6'),
    ('root', 0xdf0, '488d8c24c00100004c89f2'),
    ('root', 0xe00, '4531f64883f801410f94c6'),
    ('root', 0xe0b, '488d8c24c0010000ba00040000'),
    ('root', 0xe1d, '488d8c24000a0000'),
    ('input', 0x8, '80b9c814000001'), ('input', 0x11, 'f60601'),
    ('input', 0x16, '488b86c0140000483b4618'),
    *[('input', o, h) for o, h in ((0x23,'488d4e40ba80000000'),
      (0x31,'488d8ec0000000ba00040000'), (0x42,'488d8ec0040000ba00100000'),
      (0x69,'488d4e40ba80000000'), (0x77,'488d8ec0000000ba00040000'),
      (0x88,'488d8ec0040000ba00100000'))],
    ('input', 0x53, '48c7060000000048c786c014000000000000b0ff'),
    ('input', 0x99, '48c7060000000048c786c014000000000000b001'),
    ('input', 0xad, 'c686c8140000024883c4205ec3'),
    ('complete', 0x3, '4881f900400000'),
    ('complete', 0x1a, '488bd148c1e220483bc2'), ('complete', 0x2d, '493bc8'),
    ('complete', 0x32, 'b90100000033c0'), ('complete', 0x41, '410f94c1498bc1c333c0c3'),
    ('output', 0x14, '83f802'), ('output', 0x19, '4881fa00040000'),
    ('output', 0x2d, '83f801'), ('output', 0x53, 'bb0100000033c0'),
    ('output', 0x69, '4c8bc2488bd1'), ('output', 0x7b, '85c0'),
    ('output', 0x86, '33c04883c4205bc3'), ('output', 0x8e, 'b902000000488bc3'),
    ('region', 0x9, '4881fa00000100'), ('region', 0x2a, 'b801000000c333c0c3'),
)
BRANCHES = (
    *[('root', o, b'\x0f\x85', 0xd7e) for o in (0xcac, 0xcc1, 0xcd5)],
    ('root', 0xd0a, b'\x75', 0xd7e), ('root', 0xd33, b'\x0f\x84', 0xdf0),
    ('root', 0xd3c, b'\xe9', 0xe0b), ('root', 0xdeb, b'\xe9', 0x24d),
    ('root', 0xe2a, b'\xe9', 0x250),
    *[('root', o, b'\x0f\x84', 0x24d) for o in (0xd97, 0xda0, 0xdd3)],
    ('input', 0xf, b'\x75', 0x69), ('input', 0x14, b'\x74', 0x69),
    ('input', 0x21, b'\x75', 0x69), ('input', 0x67, b'\xeb', 0xad),
    ('complete', 0xa, b'\x77', 0x49),
    *[('complete', o, b'\x75', 0x49) for o in (0x24, 0x30)],
    *[('output', o, op, 0x86) for o, op in
      ((0x17,b'\x75'),(0x20,b'\x77'),(0x30,b'\x75'),(0x39,b'\x74'),
       (0x42,b'\x72'),(0x51,b'\x77'),(0x62,b'\x75'))],
    *[('output', o, b'\x74', 0x8e) for o in (0x67, 0x7d)],
    *[('region', o, op, 0x30) for o, op in
      ((7,b'\x74'),(0x10,b'\x77'),(0x19,b'\x72'),(0x28,b'\x77'))],
)


def check_bodies(bodies):
    require(set(bodies) == set(BODIES), 'root-return body population')
    for name, (_, size, digest) in BODIES.items():
        require(len(bodies[name]) == size and hashlib.sha256(bodies[name]).hexdigest() == digest,
                'root-return body identity: ' + name)


def check_references(refs):
    require(set(refs) == set(REFERENCES), 'root-return reference population')
    for name, rows in refs.items():
        encoded = json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()
        require(hashlib.sha256(encoded).hexdigest() == REFERENCES[name], 'root-return references')


def check_instructions(bodies, refs):
    require(set(bodies) == set(refs) == set(BODIES), 'root-return instruction population')
    for name, calls in CALLS.items():
        for offset, symbol in calls.items():
            require([r for r in refs[name] if r['offset'] == offset] ==
                    [dict(offset=offset, symbol=symbol, trailing=0, addend=0)], 'root-return call')
            require(bodies[name][offset-1:offset+4] == b'\xe8\0\0\0\0', 'root-return call bytes')
    for name, offset, hexcode in ANCHORS:
        code = bytes.fromhex(hexcode)
        require(bodies[name][offset:offset+len(code)] == code, 'root-return instruction landmark')
    for name, offset, opcode, target in BRANCHES:
        width = 4 if len(opcode) == 2 or opcode == b'\xe9' else 1
        field = offset + len(opcode)
        require(bodies[name][offset:field] == opcode and
                field+width+int.from_bytes(bodies[name][field:field+width], 'little', signed=True) == target,
                'root-return branch destination')


def bind_leaf(native, image, name, root):
    """Only the two pinned no-frame C helpers, anchored by the reviewed root."""
    require(name in ('complete', 'region'), 'selected no-frame helper')
    symbol, size, digest = BODIES[name]
    code, refs = caller.function(native, symbol)
    require(len(code) == size and hashlib.sha256(code).hexdigest() == digest, 'leaf body identity')
    encoded = json.dumps(refs, sort_keys=True, separators=(',', ':')).encode()
    require(hashlib.sha256(encoded).hexdigest() == REFERENCES[name], 'leaf relocation identity')
    require(root['image_sha256'] == hashlib.sha256(image).hexdigest(), 'same anchor image')
    start = root['reference_targets'][symbol]
    rows, functions = caller.pe.linked(image)
    mapped = [r for r in rows if r['rva'] <= start and
              start+size <= r['rva']+min(len(r['code']), r['virtual_size'])]
    require(len(mapped) == 1 and mapped[0]['flags'] & 0xa0000020 == 0x20000020,
            'complete unique nonwritable executable leaf')
    require(not any(a < start+size and start < b for a,b,_ in functions), 'no overlapping runtime entry')
    linked = slot.binding.mapped(rows, start, size)
    slot.binding.exact(code, linked, [r['offset'] for r in refs])
    targets = {}
    for ref in refs:
        field = ref['offset']
        target = start+field+4+ref['trailing']+int.from_bytes(linked[field:field+4], 'little', signed=True)
        base = target-ref['addend']
        width = 8 if ref['symbol'] == 'scheduler_state' or ref['addend'] in (288,296) else 4
        storage = [r for r in rows if r['rva'] <= target and target+width <= r['rva']+r['virtual_size']]
        require(len(storage) == 1 and storage[0]['flags'] & 0xa0000000 == 0x80000000,
                'complete unique writable nonexecutable global')
        require(ref['symbol'] not in targets or targets[ref['symbol']] == base, 'consistent leaf global')
        targets[ref['symbol']] = base
    return dict(entry=symbol, rva=start, size=size, reference_targets=targets,
                image_sha256=root['image_sha256'], local_stack_bytes=0, unwind_entry=False)


def close_edges(records):
    known = {r['entry']: r['rva'] for r in records}
    globals_ = {}
    for record in records:
        for symbol, target in record['reference_targets'].items():
            if symbol in known: require(target == known[symbol], 'root-return callee identity')
            if symbol in ('scheduler_state', 'scheduler_completed', 'input_copies', 'slots'):
                require(symbol not in globals_ or globals_[symbol] == target, 'root-return shared global')
                globals_[symbol] = target
    return globals_


def inspect(data, native, image, mutate=False):
    prior = retirement.inspect(data, native, image)
    owner = terminal.inspect(data, image)
    objects = {n: data if n in ('root', 'input') else native for n in BODIES}
    selected = {n: caller.function(objects[n], s[0]) for n,s in BODIES.items()}
    bodies = {n:s[0] for n,s in selected.items()}
    refs = {n:s[1] for n,s in selected.items()}
    check_bodies(bodies)
    check_references(refs)
    check_instructions(bodies, refs)
    records = {n: slot.binding.bind(objects[n], image, BODIES[n][0]) for n in ('root','input','output')}
    for name in ('complete', 'region'): records[name] = bind_leaf(native, image, name, records['root'])
    globals_ = close_edges([*records.values(), *prior['entries'].values(), *owner['entries'].values()])
    count = 0
    if mutate:
        for name, code in bodies.items():
            for index in range(len(code)):
                changed = bytearray(code)
                changed[index] ^= 1
                try: check_bodies(bodies | {name: bytes(changed)})
                except ValueError: count += 1
                else: raise AssertionError('accepted root-return byte mutation')
    return dict(schema=1, date='2026-10-05', status='AUTHOR_SELECTED_OUTER_ROOT_RETURN_REVIEW',
                object_sha256=slot.OBJECT, native_object_sha256=retirement.C_OBJECT, image_sha256=slot.IMAGE,
                entries=records, shared_globals=globals_, body_byte_mutations_rejected=count,
                instruction_landmarks=len(ANCHORS), branch_landmarks=len(BRANCHES),
                copied_input_clear_bytes=[128,1024,4096], public_staging_clear_bytes=1024,
                input_finish_fixed_frame_bytes=40, native_output_fixed_frame_bytes=40,
                public_output_is_transactional=False, failed_export_reservation_is_reusable=False,
                sdk_output_target_rva=records['output']['reference_targets']['EnclaveCopyOutOfEnclave'],
                sdk_output_semantics_reconciled=False, cross_image_qualified=False,
                native_run_added=False, arbitrary_exception_cleanup_qualified=False,
                whole_image_qualified=False, release_gate_changed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('object', 'native_object', 'image'): parser.add_argument(name, type=Path)
    parser.add_argument('--mutate', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = inspect(args.object.read_bytes(), args.native_object.read_bytes(), args.image.read_bytes(), args.mutate)
    sources = ('windows_enclave_root_return.py', 'test-windows-enclave-root-return.py',
               'windows_enclave_retirement_review.py', 'windows_enclave_terminal_review.py',
               'windows_enclave_caller_binding.py', 'windows_enclave_caller_handlers.py',
               'windows_enclave_caller_object.py', 'windows_enclave_wrapper_binding.py')
    result['source_sha256'] = {n: hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in sources}
    text = json.dumps(result, indent=2)+'\n'
    if args.output: args.output.write_text(text, encoding='utf-8')
    else: print(text, end='')
