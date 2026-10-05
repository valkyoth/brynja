"""Selected saved-image state adapters; not a whole-image or engine proof."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_terminal_review as terminal
from windows_enclave_frame_geometry import require

cleanup = terminal.cleanup
slot = cleanup.slot
ENGINE = '_RNvMs0_NtCscBEH4D3OuJh_22sha3_accelerated_state6engineNtB5_6Engine'
CORE = '_RNvMs_CscBEH4D3OuJh_22sha3_accelerated_stateNtB4_4Core5clear'
DROP = '_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueNtCscBEH4D3OuJh_22sha3_accelerated_state4CoreEBD_'
BODIES = {
    'update': (slot.STATE+'6update',292,'a224e0e6421f43b15c1fa2edc395855ac3eb7b3d2e990ff7fe3f29d615b5522b'),
    'finish': (slot.STATE+'10finish_xof',303,'412985881ae706f23506eb117b82535e1b73fbe2b3505b13b404233b61affbc2'),
    'squeeze': (slot.STATE+'7squeeze',557,'5b4ce60192a59f27a2cc37f1492bb0186f441fefa446f79eacdfc0ef8b18030e'),
    'clear': (CORE,114,'62288c934acf20e0d2b336c68ea06efb2273f97ecab34f345f6813e4541ef09d'),
    'drop': (DROP,186,'478f021f93d5b4b1b46cb35fbd4a8aade6fe2f92f6ee4eb92a5bc10a218cb794'),
}
CALLS = {
    'update': {0x91:cleanup.MEMORY,0xab:slot.CLEAR,0xf2:ENGINE+'6absorb',0x116:cleanup.MEMORY},
    'finish': {0x9a:cleanup.MEMORY,0xb4:slot.CLEAR,0x11a:ENGINE+'6finish'},
    'squeeze': {0x9d:cleanup.MEMORY,0xb7:slot.CLEAR,0x11e:'memset',0x161:'memset',
                0x171:ENGINE+'4read',0x186:slot.CLEAR,
                0x1b8:'_RNvNtCsjNKEhcqdpKw_11brynja_core13secret_memory22apply_secret_byte_mask',
                0x1cb:'_RNvNtCsjNKEhcqdpKw_11brynja_core13secret_memory18copy_secret_region',
                0x1de:slot.CLEAR,0x1ee:CORE,0x1fd:slot.CLEAR,0x20e:DROP},
    'clear': {0x22:cleanup.MEMORY,0x3c:slot.CLEAR},
    'drop': {0x27:cleanup.MEMORY,0x48:slot.CLEAR,0x75:cleanup.MEMORY,0x7d:cleanup.SCRATCH,0x97:slot.CLEAR},
}
# Landmarks are independent of whole-body identity checks. They document the
# actual reviewed instructions, not a claim that byte pins prove semantics.
ANCHORS = (
    ('update',0x1c,'80b9c203000001'), ('update',0x51,'483b8e48020000'),
    ('update',0x77,'c6865b0300000148c7866802000000000000'),
    ('update',0x9e,'488d8ea8030000ba01000000'),
    ('update',0xca,'c686aa030000ffc686c203000003'),
    ('update',0xf6,'3cff'), ('update',0x11f,'40b7ff'),
    ('finish',0x20,'80b9c203000001'), ('finish',0xfd,'4885c0'),
    ('finish',0x106,'440fb686c0030000440fb68ec1030000'),
    ('finish',0xda,'b0038886c2030000'), ('finish',0x128,'40b7ffb002'),
    ('squeeze',0,'415741565657534881ec20040000'),
    ('squeeze',0x24,'80b9c203000002'), ('squeeze',0x59,'483b8e48020000'),
    ('squeeze',0x10a,'488d4c24204d89c641b80004000031d2'),
    ('squeeze',0x122,'4981fe01040000'), ('squeeze',0x12f,'4084ff'),
    ('squeeze',0x158,'41b80004000031d2'),
    ('squeeze',0x165,'488d5424204889f14d89f0'),
    ('squeeze',0x17b,'488d4c2420ba00040000'),
    ('squeeze',0x192,'418d47ff3c06'),
    ('squeeze',0x1a3,'488d04144883c01fb1084428f9b2ffd2ea4889c1'),
    ('squeeze',0x1bf,'4c8d4424204889d94989d1'),
    ('squeeze',0x1d3,'488d4c2420ba00040000'),
    ('squeeze',0x1f2,'488d4c2420ba00040000'),
    ('squeeze',0x212,'48c786b00300000200000040b7ff'),
    ('clear',8,'c6815b0300000148c7816802000000000000'),
    ('clear',0x2f,'488d8ea8030000ba01000000'),
    ('clear',0x5b,'c686aa030000ffc686c203000003'),
    ('drop',0x3b,'488d8ea8030000ba01000000'),
    ('drop',0x60,'c686aa030000ffc686c203000003'),
)
BRANCHES = (
    ('update',0x10,b'\x0f\x84',0xd8),
    *[('update',o,b'\x75',0x77) for o in (0x23,0x2c,0x35,0x58)],
    ('update',0xec,b'\x72',0x77), ('update',0xf8,b'\x74',0x11f),
    ('update',0x11a,b'\xe9',0x77), ('update',0x122,b'\xeb',0xd8),
    ('finish',0x14,b'\x0f\x84',0xe2),
    *[('finish',o,b'\x75',0x80) for o in (0x27,0x30,0x39,0x5f)],
    ('finish',0xf8,b'\x72',0x80), ('finish',0x100,b'\x0f\x85',0x80),
    ('finish',0x122,b'\x0f\x85',0x80), ('finish',0x12d,b'\xeb',0xdc),
    ('squeeze',0x18,b'\x0f\x84',0xe4),
    *[('squeeze',o,b'\x75',0x83) for o in (0x2b,0x34,0x60)],
    ('squeeze',0x3d,b'\x74',0x83), ('squeeze',0x100,b'\x72',0x83),
    ('squeeze',0x105,b'\x74',0x13e), ('squeeze',0x13a,b'\x74',0x165),
    ('squeeze',0x13c,b'\xeb',0x17b), ('squeeze',0x144,b'\x0f\x85',0x83),
    ('squeeze',0x179,b'\x74',0x18f), ('squeeze',0x18a,b'\xe9',0x83),
    ('squeeze',0x198,b'\x77',0x1bf), ('squeeze',0x19d,b'\x0f\x84',0x225),
    ('squeeze',0x1d1,b'\x74',0x1ea), ('squeeze',0x1e5,b'\xe9',0x83),
    ('squeeze',0x208,b'\x74',0x212), ('squeeze',0x220,b'\xe9',0xe4),
    ('squeeze',0x228,b'\xe9',0x17b), ('clear',0x2d,b'\x74',0x5b),
    ('drop',0x39,b'\x74',0x60), ('drop',0x88,b'\x74',0xaf),
)


def check_bodies(bodies):
    require(set(bodies)==set(BODIES),'state operation population')
    for name,(_,size,digest) in BODIES.items():
        require(len(bodies[name])==size and hashlib.sha256(bodies[name]).hexdigest()==digest,
                'state operation body: '+name)


def check_instructions(bodies,refs):
    require(set(bodies)==set(refs)==set(BODIES),'state operation instruction population')
    for name,calls in CALLS.items():
        require(len(refs[name])==len(calls) and {r['offset']:r['symbol'] for r in refs[name]}==calls,
                'state operation relocations')
        for r in refs[name]:
            require(r['addend']==r['trailing']==0 and
                    bodies[name][r['offset']-1:r['offset']+4]==b'\xe8'+bytes(4),'direct call shape')
    for name,offset,hexcode in ANCHORS:
        code=bytes.fromhex(hexcode)
        require(bodies[name][offset:offset+len(code)]==code,'state operation landmark')
    for name,offset,opcode,target in BRANCHES:
        width=4 if len(opcode)==2 or opcode==b'\xe9' else 1
        end=offset+len(opcode)+width
        require(bodies[name][offset:offset+len(opcode)]==opcode and
                end+int.from_bytes(bodies[name][end-width:end],'little',signed=True)==target,
                'state operation branch')


def inspect(data,image,mutate=False):
    previous=terminal.inspect(data,image)
    selected={n:slot.binding.obj.select(data,s[0]) for n,s in BODIES.items()}
    bodies={n:s[3] for n,s in selected.items()}
    check_bodies(bodies)
    check_instructions(bodies,{n:s[4] for n,s in selected.items()})
    records={n:slot.binding.bind(data,image,s[0]) for n,s in BODIES.items()}
    direct=cleanup.inspect(data,image)
    known={r['entry']:r['rva'] for r in [*records.values(),*direct['entries'].values()]}
    for record in [*previous['entries'].values(),*records.values()]:
        for symbol,target in record['reference_targets'].items():
            if symbol in known: require(target==known[symbol],'linked state operation edge')
    count=0
    if mutate:
        for name,body in bodies.items():
            for i in range(len(body)):
                changed=bytearray(body)
                changed[i]^=1
                try: check_bodies(bodies|{name:bytes(changed)})
                except ValueError: count+=1
                else: raise AssertionError('state operation byte mutation escaped')
    return dict(schema=1,date='2026-10-05',status='AUTHOR_SELECTED_STATE_ADAPTER_REVIEW',
                object_sha256=slot.OBJECT,image_sha256=slot.IMAGE,entries=records,
                body_byte_mutations_rejected=count,
                staging=dict(rsp_offset=32,bytes=1024,frame_allocation=1056,saved_register_bytes=40),
                terminal_squeeze_specialization=True,core_clear_wipes_scratch=False,
                scratch_cleared_by_core_drop=True,
                unreviewed_callees=sorted({s for calls in CALLS.values() for s in calls.values()}-known.keys()),
                whole_image_qualified=False,engine_internals_qualified=False,
                arbitrary_exception_cleanup_qualified=False,native_run_added=False,release_gate_changed=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('object',type=Path)
    parser.add_argument('image',type=Path)
    parser.add_argument('--mutate',action='store_true')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=inspect(args.object.read_bytes(),args.image.read_bytes(),args.mutate)
    sources=('windows_enclave_state_operations.py','test-windows-enclave-state-operations.py',
             'windows_enclave_terminal_review.py','windows_enclave_state_cleanup.py',
             'windows_enclave_slot_review.py','windows_enclave_caller_binding.py',
             'windows_enclave_leaf_binding.py','windows_enclave_caller_unwind.py',
             'windows_enclave_caller_handlers.py','windows_enclave_caller_object.py',
             'windows_enclave_wrapper_binding.py','windows_enclave_frame_geometry.py')
    result['source_sha256']={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in sources}
    text=json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
