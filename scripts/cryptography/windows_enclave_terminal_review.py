"""Saved ParallelHash finish/export/destructor review; not whole-image qualification."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_state_cleanup as cleanup
from windows_enclave_frame_geometry import require

slot = cleanup.slot
WAVES = '_RNvMs_NtCs2u1vj83u0E8_14parallel_waves25parallel_concurrent_wavesNtB4_5Waves'
ENCODED = '_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueNtNtCs2u1vj83u0E8_14parallel_waves24parallel_stream_encoding20SecretEncodedIntegerEBF_'
DROP = '_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueNtNtCs2u1vj83u0E8_14parallel_waves25parallel_concurrent_waves5WavesECsk1CFy3R4N16_20parallel_wave_bridge'
OP = '_RNvXNtCs2u1vj83u0E8_14parallel_waves25parallel_concurrent_wavesNtB2_9OperationNtNtNtCs8xEFJqa6dYS_4core3ops4drop4Drop4drop'
DESTRUCTOR = '_RNvXs0_NtCs2u1vj83u0E8_14parallel_waves25parallel_concurrent_wavesNtB5_5WavesNtNtNtCs8xEFJqa6dYS_4core3ops4drop4Drop4drop'
BODIES = {
    'finish': (WAVES+'6finish', 982, '54563c70af8d687ca21150e3f20af24c5501bf16dc56f8aaaaf8835de3303668'),
    'export': (WAVES+'13declassify_to', 188, '9e99659b71ba1c512341b04a9a58aee4305104c66284eccda0fa9447b66a8b65'),
    'operation': (OP, 71, 'c925c26c6ebd6a4b4ae46a7046beb88205148e0b6271803c39b4a98e6e27e700'),
    'destructor': (DESTRUCTOR, 66, 'a943c0a8e05423b6c2cd84d898c2ca4869ab12565b51c0ec40b7fd4dd015076e'),
    'drop': (DROP, 278, 'e553a739b5d893f016d5b1331b8ef2604c958d2f796228135494c0c0b1ccec90'),
    'encoded': (ENCODED, 40, '3c8b37874a299973f2066cd5712e147d830ff949c5ee4451c2d7da20df4c86e3'),
}
CALLS = {
    'finish': {**dict.fromkeys((0x96,0xa9,0x28d,0x29a,0x2cb),slot.CLEAR),
               **dict.fromkeys((0x1da,0x236),slot.STATE+'6update'),
               0x20a:'_RNvMNtCs2u1vj83u0E8_14parallel_waves24parallel_stream_encodingNtB2_20SecretEncodedInteger5right',
               0x26e:slot.STATE+'10finish_xof',0x358:slot.STATE+'7squeeze',
               0x2b2:slot.STATE_DROP,0x37b:slot.STATE_DROP,0x3ba:ENCODED,
               0x3d0:'_RNvNtNtCs8xEFJqa6dYS_4core9panicking11panic_const24panic_const_shr_overflow'},
    'export': {0x55:'memcpy',0x6a:slot.STATE_DROP,0x90:slot.STATE_DROP,0xa8:slot.CLEAR},
    'operation': {0x1e:slot.STATE_DROP,0x36:slot.CLEAR},
    'destructor': {0x19:slot.STATE_DROP,0x31:slot.CLEAR},
    'drop': {0x1b:slot.STATE_DROP,0x33:slot.CLEAR,0x7c:cleanup.MEMORY,0x96:slot.CLEAR,
             0xca:cleanup.MEMORY,0xd2:cleanup.SCRATCH,0xec:slot.CLEAR},
    'encoded': {0xe:slot.CLEAR,0x24:slot.CLEAR},
}
ANCHORS = (
    ('finish',0x21,'80b92008000001'),
    ('finish',0x2e,'498b842400080000493b8424f0070000'),
    ('finish',0x44,'498bbc2408080000493bbc24f8070000'),
    ('finish',0x283,'488d4dd0ba11000000'), ('finish',0x291,'ba010000004889f1'),
    ('finish',0x2b6,'49c78424b0070000ffffffffba000400004c89e1'),
    ('finish',0x2cf,'41c684242008000003'),
    ('finish',0x310,'4981f900200000'),
    ('finish',0x383,'48c780b0070000ffffffff'),
    ('finish',0x398,'80780904'), ('finish',0x39e,'80780801'),
    ('finish',0x3ac,'41c684242008000002488d4dd0'),
    ('export',0xb,'80b92008000002'), ('export',0x1d,'80780904'),
    ('export',0x23,'80780801'), ('export',0x35,'4883f8f8'),
    ('export',0x49,'4939c0'), ('export',0x4e,'4889d14889f2'),
    ('export',0x6e,'48c786b0070000ffffffff'),
    ('export',0x94,'48c786b0070000ffffffffba000400004889f1'),
    ('export',0xac,'c6862008000003'),
    ('operation',5,'f6c201'),
    ('operation',0x22,'48c786b0070000ffffffffba000400004889f1'),
    ('operation',0x3a,'c6862008000003'),
    ('destructor',0x1d,'48c786b0070000ffffffffba000400004889f1'),
    ('destructor',0x35,'c6862008000003'),
    ('drop',0x1f,'48c786b0070000ffffffffba000400004889f1'),
    ('drop',0x37,'c6862008000003'),
    ('encoded',8,'ba11000000'),
    ('encoded',0x12,'4883c611ba010000004889f14883c4205e'),
)
BRANCHES = (
    *[('finish',o,b'\x0f\x85',0x29e) for o in (0x28,0x3e,0x54,0x69,0x73)],
    ('finish',0x213,b'\x75',0x283), ('finish',0x23c,b'\x75',0x1e2),
    ('finish',0x275,b'\x74',0x2f3), ('finish',0x31b,b'\x0f\x87',0x283),
    ('finish',0x366,b'\x0f\x85',0x283), ('finish',0x39c,b'\x75',0x3c6),
    ('finish',0x3a6,b'\x0f\x85',0x283), ('finish',0x3c1,b'\xe9',0x2d8),
    *[('export',o,b'\x75',0x7f) for o in (0x12,0x21,0x27,0x4c)],
    ('export',0x39,b'\x77',0x7d), ('export',0x7b,b'\xeb',0x9f),
    ('operation',8,b'\x75',0x41), ('drop',0x49,b'\x0f\x84',0x10b),
)


def check_bodies(bodies):
    require(set(bodies)==set(BODIES),'terminal body population')
    for name,(_,size,digest) in BODIES.items():
        require(len(bodies[name])==size and hashlib.sha256(bodies[name]).hexdigest()==digest,
                'reviewed terminal body: '+name)


def check_instructions(bodies,refs):
    require(set(bodies)==set(refs)==set(BODIES),'terminal instruction population')
    for name,calls in CALLS.items():
        require(len(refs[name])==len(calls) and {r['offset']:r['symbol'] for r in refs[name]}==calls,
                'complete terminal call graph')
        for r in refs[name]:
            opcode=0xe9 if name=='encoded' and r['offset']==0x24 else 0xe8
            require(r['addend']==r['trailing']==0 and
                    bodies[name][r['offset']-1:r['offset']+4]==bytes([opcode])+bytes(4),'call/tail shape')
    for name,offset,hexcode in ANCHORS:
        code=bytes.fromhex(hexcode)
        require(bodies[name][offset:offset+len(code)]==code,'terminal instruction landmark')
    for name,offset,opcode,target in BRANCHES:
        width=4 if len(opcode)==2 or opcode==b'\xe9' else 1
        field=offset+len(opcode)
        require(bodies[name][offset:field]==opcode and
                field+width+int.from_bytes(bodies[name][field:field+width],'little',signed=True)==target,
                'terminal branch destination')


def inspect(data,image,mutate=False):
    prior=cleanup.inspect(data,image)
    selected={n:slot.binding.obj.select(data,s[0]) for n,s in BODIES.items()}
    bodies={n:s[3] for n,s in selected.items()}
    refs={n:s[4] for n,s in selected.items()}
    check_bodies(bodies)
    check_instructions(bodies,refs)
    records={n:slot.binding.bind(data,image,s[0]) for n,s in BODIES.items()}
    root=slot.binding.bind(data,image,'PrivateWaveRoot')
    known={r['entry']:r['rva'] for r in [*prior['entries'].values(),*records.values()]}
    for r in [root,*records.values()]:
        for symbol,target in r['reference_targets'].items():
            if symbol in known: require(target==known[symbol],'terminal-to-cleanup linked edge')
    count=0
    if mutate:
        for name,body in bodies.items():
            for offset in range(len(body)):
                changed=bytearray(body)
                changed[offset]^=1
                try: check_bodies(bodies|{name:bytes(changed)})
                except ValueError: count+=1
                else: raise AssertionError('terminal byte mutation escaped')
    return dict(schema=1,date='2026-10-05',status='AUTHOR_SELECTED_ROOT_OWNER_TERMINAL_REVIEW',
                object_sha256=slot.OBJECT,image_sha256=slot.IMAGE,entries=records,
                root_rva=root['rva'],body_byte_mutations_rejected=count,
                output_clear=dict(offset=0,bytes=1024),state_offset=1024,empty_state_tag_offset=1968,
                phase_offset=2080,dead_phase=3,retained_phase=2,encoded_clear_bytes=18,
                unreviewed_terminal_callees=sorted({s for calls in CALLS.values() for s in calls.values()}-known.keys()),
                whole_image_qualified=False,arbitrary_exception_cleanup_qualified=False,
                native_run_added=False,release_gate_changed=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('object',type=Path)
    parser.add_argument('image',type=Path)
    parser.add_argument('--mutate',action='store_true')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=inspect(args.object.read_bytes(),args.image.read_bytes(),args.mutate)
    sources=('windows_enclave_terminal_review.py','test-windows-enclave-terminal-review.py',
             'windows_enclave_state_cleanup.py','windows_enclave_slot_review.py',
             'windows_enclave_caller_binding.py','windows_enclave_leaf_binding.py',
             'windows_enclave_caller_unwind.py','windows_enclave_caller_handlers.py',
             'windows_enclave_caller_object.py','windows_enclave_wrapper_binding.py','windows_enclave_frame_geometry.py')
    result['source_sha256']={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in sources}
    text=json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
