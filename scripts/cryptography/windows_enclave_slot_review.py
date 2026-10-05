"""Review the saved scheduler's four slot bodies, not a general cleanup proof.

An offline author aid: exact object/image identities precede instruction checks.
No release gate, runtime policy, exception guarantee or native result is added.
"""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_caller_handlers as binding
from windows_enclave_frame_geometry import Frame, Window, require

OBJECT = '54e093b8c256fee820f349d75d1758f803e26c2cc8c1d4d0e22b4f5a420a46b8'
IMAGE = '285805852dd6d2f8b5dd91cc1515216e00d500475e3a51d73fa6657fd3fc66ee'
SLOT = '_RNvMs_NtCs2u1vj83u0E8_14parallel_waves24parallel_concurrent_slotNtB4_4Slot'
CLEAR = '_RNvNtCsjNKEhcqdpKw_11brynja_core22secret_memory_volatile23zeroize_region_volatile'
STATE_DROP = '_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueNtCscBEH4D3OuJh_22sha3_accelerated_state5StateECs2u1vj83u0E8_14parallel_waves'
STATE = '_RNvMs2_CscBEH4D3OuJh_22sha3_accelerated_stateNtB5_5State'
BODIES = {
    'run': (SLOT+'3run', 586, 'f9efe61e6356fdd82e9caf4965975ff10b194f7cdaf42f901389511aa84f56ea'),
    'funclet': ('?dtor$28@?0?'+SLOT+'3run@4HA', 92, '27b106b155b345a7a9dbb63c3a9ab4b189b68a52d92406fbac6595c3f52e4a81'),
    'absorb': (SLOT+'6absorb', 117, '079843e6d846240dd97c6a7a9a28f3da09ae542c13115d429941f2485daeb464'),
    'drop4': ('_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueANtNtCs2u1vj83u0E8_14parallel_waves24parallel_concurrent_slot4Slotj4_ECsk1CFy3R4N16_20parallel_wave_bridge',
              101, 'c251fd3ac6f06d14247a50c3174636e64002d7a16b0415b6dcc1d1efc0b64a2e'),
}
CALLS = {
    'run': {0xd3: '_RNvMNtCs2u1vj83u0E8_14parallel_waves5stateNtB2_5State4leaf',
            0x101: 'memcpy', 0x14a: STATE+'10finish_xof', 0x170: STATE_DROP,
            0x1ae: STATE+'7squeeze', 0x1d2: 'memcpy', 0x1e7: STATE_DROP, 0x22b: CLEAR},
    'funclet': {0x31: STATE_DROP, 0x43: CLEAR},
    'absorb': {0x4c: STATE+'6update', 0x63: CLEAR},
    'drop4': dict.fromkeys((0x12, 0x24, 0x3c, 0x54), CLEAR),
}
# Offsets are in the actual COFF function, not an assembly-text approximation.
ANCHORS = (
    ('run', 0xc, '4881ec18080000488dac24800000004883e4e0'),
    ('run', 0xef, '488d9321040000488d4b4141b8af030000'),
    ('run', 0x105, 'c5fc1083d8070000c5fc1183f8030000488b83f807000048898318040000'),
    ('run', 0x1c0, '488d8b20040000488d534041b8e0030000'),
    ('run', 0x210, '41c645500140b6ff'),
    ('run', 0x21e, '498d4d10ba40000000c5f877'),
    ('run', 0x22f, '41c6455002'),
    ('funclet', 0x23, '83bbf0030000ff'),
    ('funclet', 0x35, '488b7338488d4e10ba40000000'),
    ('funclet', 0x47, 'c6465002'),
    ('absorb', 0x5a, 'ba400000004889f9'),
    ('absorb', 0x67, 'c6465002'),
    ('drop4', 0x8, '4883c110ba40000000'),
    ('drop4', 0x16, 'c6465002488d4e68ba40000000'),
    ('drop4', 0x28, 'c686a800000002488d8ec0000000ba40000000'),
    ('drop4', 0x40, 'c6860001000002488d8e18010000ba40000000'),
    ('drop4', 0x58, 'c6865801000002'),
)
BRANCHES = (
    ('run', 0x3e, b'\x0f\x85', 0x21e), ('run', 0x52, b'\x0f\x85', 0x21e),
    ('run', 0x5f, b'\x0f\x85', 0x21e), ('run', 0x69, b'\x0f\x85', 0x21e),
    ('run', 0x7a, b'\x0f\x83', 0x21e), ('run', 0x8e, b'\x0f\x85', 0x21e),
    ('run', 0x9b, b'\x0f\x80', 0x21e), ('run', 0xa8, b'\x0f\x82', 0x21e),
    ('run', 0xbc, b'\x0f\x85', 0x21e), ('run', 0x174, b'\xe9', 0x21e),
    ('run', 0x1f9, b'\x75', 0x21e), ('run', 0x203, b'\x75', 0x21a),
    ('run', 0x20e, b'\x75', 0x21e), ('run', 0x218, b'\xeb', 0x234),
    ('funclet', 0x2a, b'\x74', 0x35),
    ('absorb', 0xd, b'\x75', 0x6b), ('absorb', 0x15, b'\x75', 0x6b),
    ('absorb', 0x1b, b'\x75', 0x6b), ('absorb', 0x28, b'\x74', 0x5a),
)


def check_bodies(bodies):
    require(set(bodies) == set(BODIES), 'complete reviewed slot population')
    for name, (_, size, digest) in BODIES.items():
        require(len(bodies[name]) == size and hashlib.sha256(bodies[name]).hexdigest() == digest,
                'reviewed slot body: '+name)


def check_instructions(bodies, references):
    require(set(bodies) == set(references) == set(BODIES), 'complete slot inputs')
    for name, calls in CALLS.items():
        refs = references[name]
        require(len(refs) == len(calls) and {r['offset']: r['symbol'] for r in refs} == calls,
                'exact named slot call population')
        for ref in refs:
            require(ref['trailing'] == ref['addend'] == 0 and
                    bodies[name][ref['offset']-1:ref['offset']+4] == b'\xe8\0\0\0\0',
                    'complete direct slot call')
    for name, offset, hexcode in ANCHORS:
        code = bytes.fromhex(hexcode)
        require(bodies[name][offset:offset+len(code)] == code, 'slot instruction anchor')
    for name, offset, opcode, target in BRANCHES:
        width = 4 if len(opcode) == 2 or opcode == b'\xe9' else 1
        field = offset+len(opcode)
        require(bodies[name][offset:field] == opcode and
                field+width+int.from_bytes(bodies[name][field:field+width], 'little', signed=True) == target,
                'slot reviewed branch destination')


def geometry(window):
    body = Frame.enter(window, window.high-32, 168)
    leaf = Frame.enter(window, body.current, 136)
    run = Frame.enter(window, leaf.current, 2136, 32)
    root = Frame.enter(window, body.current, 11160, 32)
    absorb = Frame.enter(window, root.current, 56)
    drop4 = Frame.enter(window, root.current, 40)
    spans = [run.slot('working state, including compiler-moved value', 64, 992),
             run.slot('construction/drop-move temporary state', 1056, 992),
             run.slot('saved slot pointer', 56, 8),
             run.slot('saved parent frame pointer', 2056, 8),
             run.slot('nonvolatile register pushes', -64, 64, 'entry')]
    return dict(frames={n:f.current-window.high for n,f in
                       (('run',run),('absorb',absorb),('drop4',drop4))}, spans=spans,
                root_slot_cv_offsets=[16+88*i for i in range(4)],
                root_slot_dead_offsets=[80+88*i for i in range(4)], cv_clear_bytes=64,
                unknown_callees=[run.unknown_callee('state/finish/squeeze/drop/memcpy'),
                                 absorb.unknown_callee('state update'), drop4.unknown_callee('volatile clear')],
                root_slot_placement_measured=False, temporary_copies_individually_erased=False,
                maximum_transitive_depth_qualified=False, exception_dispatch_qualified=False)


def inspect(data, image, mutate=False):
    require(hashlib.sha256(data).hexdigest() == OBJECT and hashlib.sha256(image).hexdigest() == IMAGE,
            'reviewed object and image before parsing')
    selected = {n:binding.obj.select(data, spec[0]) for n,spec in BODIES.items()}
    bodies = {n:row[3] for n,row in selected.items()}
    refs = {n:row[4] for n,row in selected.items()}
    check_bodies(bodies)
    check_instructions(bodies, refs)
    records = {n:binding.bind(data,image,spec[0]) for n,spec in BODIES.items()}
    require(any(r['symbol'] == BODIES['funclet'][0] and r['target_rva'] == records['funclet']['rva']
                for r in records['run']['metadata']), 'parent names this exact funclet')
    for symbol in (CLEAR, STATE_DROP):
        require(len({r['reference_targets'][symbol] for r in records.values()
                     if symbol in r['reference_targets']}) == 1, 'shared cleanup target identity')
    count = 0
    if mutate:
        for name, code in bodies.items():
            for index in range(len(code)):
                changed = bytearray(code)
                changed[index] ^= 1
                try: check_bodies(bodies | {name:bytes(changed)})
                except ValueError: count += 1
                else: raise AssertionError('accepted changed slot body')
    return dict(schema=1,date='2026-10-05',status='AUTHOR_SELECTED_SLOT_LIFECYCLE_REVIEW',
                object_sha256=OBJECT,image_sha256=IMAGE,entries=records,
                reviewed_body_sha256={n:s[2] for n,s in BODIES.items()},
                instruction_anchors=len(ANCHORS),branches=len(BRANCHES),
                call_sites=sum(map(len,CALLS.values())),body_byte_mutations_rejected=count,
                geometry=geometry(Window(0,65536)),native_run_added=False,
                independently_verified=False,whole_image_qualified=False,release_gate_changed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('object', type=Path)
    parser.add_argument('image', type=Path)
    parser.add_argument('--mutate', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = inspect(args.object.read_bytes(), args.image.read_bytes(), args.mutate)
    sources = ('windows_enclave_slot_review.py', 'test-windows-enclave-slot-review.py',
               'windows_enclave_caller_handlers.py', 'windows_enclave_caller_object.py',
               'windows_enclave_wrapper_binding.py', 'windows_enclave_frame_geometry.py')
    result['source_sha256'] = {name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                               for name in sources}
    output = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(output,encoding='utf-8')
    else: print(output,end='')
