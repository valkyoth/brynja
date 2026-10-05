"""Selected saved constructor/prefix review; author aid, not a release gate."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_engine_review as engine
from windows_enclave_frame_geometry import require

cleanup, slot = engine.cleanup, engine.slot
STATE = '_RNvMs2_CscBEH4D3OuJh_22sha3_accelerated_stateNtB5_5State'
PREFIX = '_RNvMNtCscBEH4D3OuJh_22sha3_accelerated_state23sha3_accelerated_prefixNtB2_6Prefix'
ENCODE = '_RNvNtCs58M5yX2Qwr5_16brynja_hash_sha38sp80018516left_encode_u128'
TABLE = 'switch.table.'+STATE+'7initial'
ZERO = 'anon.3a19b6b51e69661c8cb0ff666193b4ce.0'
KAT = (
    'bd1547306f80494dd598261ea65aa9ee84d5ccf933c0478af1258f7940e1dde7',
    '8c5bda0cd6192e7690fee5a0a44647c4ff97a42d7f8e6fd48b284e056253d057',
    'a9a6e6260d712103eb5aa93f2317d63530935ab7d08ffc64ad30a6f71b19059c',
    '05e5635a21d9ae6101f22f1a11a5569f43b831cd0347c82681a57c16dbcf555f',
    '8c3ee88a1ccf32c8b87c5a554fd00ecb613670957bc4661164befef28cc970f2',
    '75f644e97f30a13b16f53526e70465c21841f924a2c509e4940c7922ae3a2614',
)
BODIES = {
    'initial': (STATE+'7initial',1028,'8b32c86adb226ab1707971e5092a775b95cb1c9fdfb42440e7abd5b59bf8d5e5'),
    'leaf': ('_RNvMNtCs2u1vj83u0E8_14parallel_waves5stateNtB2_5State4leaf',248,'c46c33940987df7718001d3c460e4c3e0a7a66c2bd0c74897bd734debbb3ac5f'),
    'setup': (STATE+'11setup_chunk',491,'fca87df6202a020f526fe231555a8ea550795f44f5cd02a0af3aa2d48815b6e0'),
    'complete': (STATE+'12finish_setup',395,'8f50e88f0edc6882bf9a9e7cae5f786c2e36d38a6fc9eb2c885d63520ce20508'),
    'bytes': (PREFIX+'5bytes',187,'638e4cd88c4255378566e3908448df87e11f9d2440783f30fdb3aeb5a8e61079'),
    'bits': (PREFIX+'4bits',312,'27fa3e4ddfceeb54976c5b2f76ffdb0104997b66b8caa970f4c502b416b986a6'),
    'advance': (PREFIX+'7advance',565,'b76b5c8f2a6259e253d344a60a149fb0e69784311c75d361f7dc47f4fb30f557'),
}
CALLS = {
    'initial': {0x69:'memset',0x122:cleanup.SCRATCH,0x15a:engine.KERNEL,0x162:cleanup.SCRATCH,
                **{o:'__ymm@'+v for o,v in zip((0x170,0x188,0x1a0,0x1b8,0x1d0,0x20c),KAT)},
                0x24d:'memcpy',0x290:'memcpy',0x2df:TABLE,0x324:cleanup.SCRATCH,0x374:'memcpy'},
    'leaf': {0x3c:STATE+'7initial',0x8e:'memcpy',0xc2:'memcpy'},
    'setup': {0x45:cleanup.MEMORY,0x5f:slot.CLEAR,0x184:PREFIX+'5bytes',0x1be:PREFIX+'4bits',0x1db:PREFIX+'7advance'},
    'complete': {0x3b:cleanup.MEMORY,0x55:slot.CLEAR,0x162:slot.CLEAR},
    'bytes': {0x3d:PREFIX+'4bits',0x6a:engine.BODIES['absorb'][0],0x91:cleanup.MEMORY},
    'bits': {0x8c:engine.XOR,0xc8:engine.BODIES['absorb'][0],0xd9:slot.CLEAR,0x11d:cleanup.MEMORY},
    'advance': {0x44:ENCODE,0x7d:PREFIX+'4bits',0xb3:engine.BODIES['absorb'][0],
                0x13e:engine.BODIES['absorb'][0],0x153:slot.CLEAR,0x19d:'__umodti3',
                0x1c9:ZERO,0x1d4:engine.BODIES['absorb'][0],0x1fb:cleanup.MEMORY},
}
# Selected semantic landmarks supplement (not replace) the full body identity.
ANCHORS = (
    ('initial',0,'554157415641545657534881ec40080000'),
    ('initial',0x19,'4883e4e0'), ('initial',0x1d,'807a0904'),
    ('initial',0x55,'488d8c244001000041b8400200004889d331d2'),
    ('initial',0x116,'488d8c2440010000'), ('initial',0x14b,'488db424400100004889f1'),
    ('initial',0x1ef,'c640080248c70003000000'),
    ('initial',0x217,'48b849a2ec5c7bfff1ea4839842420010000'),
    ('initial',0x233,'488d942441010000488d8c240106000041b83f020000'),
    ('initial',0x276,'488db424a1030000488d94240106000041b83f020000'),
    ('initial',0x2e3,'4c8b74c1e0'), ('initial',0x31b,'488d8c24a0030000'),
    ('initial',0x366,'488d4f0141b85f0200004889f2'),
    ('initial',0x3dd,'c687aa030000ff48c787b00300000000000066c787c00300001f05c687c203000001'),
    ('leaf',0,'5541565657534881ecf0070000'), ('leaf',0x15,'4883e4e0'),
    ('leaf',0x1c,'49ffc84983f804'), ('leaf',0x25,'41c1e003b8040504054489c1d3e8'),
    ('leaf',0x48,'4883fb02'), ('leaf',0x84,'41b8af030000'), ('leaf',0xb5,'41b8af030000'),
    ('setup',0x1f,'80b9c203000000'),
    ('setup',0x2b,'c6865b0300000148c7866802000000000000488d8e70020000'),
    ('setup',0x52,'488d8ea8030000ba01000000'),
    ('setup',0x7e,'c686aa030000ffc686c203000003'),
    ('setup',0x128,'30d03c01'), ('setup',0x147,'4d39f44c89e84883d800'),
    ('setup',0x157,'4d29f44983dd0049c1ee03'), ('setup',0x166,'4939ee'),
    ('setup',0x19d,'418d41ff3c06'), ('setup',0x1a8,'4939ee'),
    ('setup',0x1c6,'4c89a6600300004c89ae68030000'),
    ('complete',0x21,'c6865b0300000148c7866802000000000000488d8e70020000'),
    ('complete',0x48,'488d8ea8030000ba01000000'),
    ('complete',0x102,'80beaa03000002'), ('complete',0x10f,'488b8660030000480b8668030000'),
    ('complete',0x123,'80bea903000000'),
    ('complete',0x130,'c5f96f8680030000c5f9ef8690030000c4e27917c0'),
    ('complete',0x155,'488d8ea8030000ba01000000'), ('complete',0x184,'b001'),
    ('bytes',0x1b,'80794900'), ('bytes',0x39,'41b108'), ('bytes',0x57,'4d01f54983d400'),
    ('bytes',0x74,'c6865b0300000148c78668020000000000004881c670020000'),
    ('bytes',0x9b,'4c896f204c896728'),
    ('bits',0x19,'8d47ff3c080f92c1410fb647493c080f92c220ca'),
    ('bits',0x64,'89f94028e9b20828c20fb6d2440fb6e94438ea440f42ea88442420'),
    ('bits',0x94,'4400ed'), ('bits',0x99,'45026f49'), ('bits',0xa3,'4180fd08'),
    ('bits',0xb1,'4983c5014883d300'), ('bits',0xd0,'ba010000004c89e1'),
    ('bits',0xdd,'49895f284d896f2041c6474900'),
    ('bits',0xfe,'c6865b0300000148c78668020000000000004881c670020000'),
    ('advance',0,'4157415641545657534881ec48010000'),
    ('advance',0x18,'480b4e08'), ('advance',0x3b,'4c8d7c2446'),
    ('advance',0x48,'0fb7842446010000'), ('advance',0x9b,'4c037e204983d400'),
    ('advance',0xe6,'488b4610488b4e1848894e08488906c6464a01'),
    ('advance',0x11f,'4983c6014983d700'), ('advance',0x12d,'488d5e4841b801000000'),
    ('advance',0x14a,'ba010000004889d9'), ('advance',0x157,'4c897e284c897620c6464900'),
    ('advance',0x169,'4885db'), ('advance',0x1ad,'4829c3b0074881fba8000000'),
    ('advance',0x1bb,'4901de4983d700'),
    ('advance',0x1dc,'c6875b0300000148c78768020000000000004881c770020000'),
    ('advance',0x21a,'4c3376304c337e38b0074d09f7'), ('advance',0x229,'c6464a02'),
)
BRANCHES = (
    ('initial',0x21,b'\x0f\x85',0xd0), ('initial',0xf6,b'\x75',0x116),
    *[('initial',o,b'\x75',0x1db) for o in (0x179,0x191,0x1a9,0x1c1,0x215,0x229)],
    ('initial',0x1d9,b'\x74',0x1ff), ('initial',0x1fa,b'\xe9',0x116),
    ('initial',0x2f7,b'\x75',0x31b), ('leaf',0x23,b'\x73',0x61), ('leaf',0x4c,b'\x75',0x71),
    ('setup',0x26,b'\x74',0xa2), ('setup',0x12c,b'\x0f\x85',0x28),
    ('setup',0x151,b'\x0f\x82',0x2b), ('setup',0x169,b'\x0f\x87',0x28),
    ('setup',0x18e,b'\xe9',0x2b), ('setup',0x1a3,b'\x77',0x1c6),
    ('setup',0x1ab,b'\x0f\x83',0x2b), ('setup',0x1c4,b'\x75',0x18c), ('setup',0x1e1,b'\x75',0x18c),
    *[('complete',o,b'\x0f\x85',0x1e) for o in (0x109,0x11d,0x12a)],
    ('complete',0x148,b'\x0f\x85',0x21), ('complete',0x186,b'\xe9',0x7d),
    ('bytes',0x1f,b'\x74',0x4f), ('bytes',0x5e,b'\x72',0xb7), ('bytes',0x70,b'\x74',0x9b),
    ('bits',0x32,b'\x0f\x85',0x121), ('bits',0x92,b'\x75',0xf6),
    ('bits',0x97,b'\x72',0xf2), ('bits',0x9d,b'\x72',0xf2), ('bits',0xa7,b'\x75',0x50),
    ('bits',0xb9,b'\x72',0x134), ('bits',0xce,b'\x75',0xfe),
    ('advance',0x1c,b'\x0f\x85',0x201), ('advance',0x2d,b'\x0f\x85',0x103),
    ('advance',0xa3,b'\x0f\x82',0x231), ('advance',0x10b,b'\x0f\x84',0x201),
    ('advance',0x127,b'\x0f\x82',0x231), ('advance',0x144,b'\x0f\x85',0x1dc),
    ('advance',0x16c,b'\x0f\x84',0x201), ('advance',0x1b9,b'\x77',0x201),
    ('advance',0x1c4,b'\x72',0x201), ('advance',0x1da,b'\x74',0x212), ('advance',0x227,b'\x75',0x201),
)


def operand(symbol):
    if symbol.startswith('__ymm@'): return bytes.fromhex('c5fdef05')
    if symbol==TABLE: return bytes.fromhex('488d0d')
    if symbol==ZERO: return bytes.fromhex('488d15')
    return b'\xe8'


def check_bodies(bodies):
    require(set(bodies)==set(BODIES),'construction population')
    for n,(_,size,digest) in BODIES.items():
        require(len(bodies[n])==size and hashlib.sha256(bodies[n]).hexdigest()==digest,
                'reviewed construction body: '+n)


def check_instructions(bodies,refs):
    require(set(bodies)==set(refs)==set(BODIES),'construction instruction population')
    for n,calls in CALLS.items():
        require(len(refs[n])==len(calls) and {r['offset']:r['symbol'] for r in refs[n]}==calls,
                'construction relocation population')
        for r in refs[n]:
            o=r['offset']; op=operand(r['symbol'])
            require(r['trailing']==r['addend']==0 and bodies[n][o-len(op):o+4]==op+bytes(4),
                    'construction relocation operand')
    for n,o,h in ANCHORS:
        code=bytes.fromhex(h)
        require(bodies[n][o:o+len(code)]==code,'construction semantic landmark')
    for n,o,op,target in BRANCHES:
        width=4 if len(op)==2 or op==b'\xe9' else 1
        end=o+len(op)+width
        require(bodies[n][o:o+len(op)]==op and
                end+int.from_bytes(bodies[n][end-width:end],'little',signed=True)==target,
                'construction reviewed branch')


def constant(rows,rva,expected):
    # Reject overlaps even where a second section covers only part of the span.
    found=[r for r in rows if r['rva']<rva+len(expected) and
           rva<r['rva']+min(len(r['code']),r['virtual_size'])]
    require(len(found)==1,'construction constant mapped once')
    row=found[0]; offset=rva-row['rva']
    require(offset>=0 and offset+len(expected)<=min(len(row['code']),row['virtual_size']) and
            not row['flags'] & 0xa0000000 and row['code'][offset:offset+len(expected)]==expected,
            'construction constant immutable nonexecutable exact bytes')
    return dict(rva=rva,bytes=len(expected),sha256=hashlib.sha256(expected).hexdigest(),readonly=True)


def inspect(data,image,mutate=False):
    prior=engine.inspect(data,image)
    selected={n:cleanup.caller.function(data,s[0]) for n,s in BODIES.items()}
    bodies={n:s[0] for n,s in selected.items()}
    check_bodies(bodies)
    check_instructions(bodies,{n:s[1] for n,s in selected.items()})
    records={n:slot.binding.bind(data,image,s[0]) for n,s in BODIES.items()}
    direct=cleanup.inspect(data,image)
    known={r['entry']:r['rva'] for r in [*records.values(),*prior['entries'].values(),*direct['entries'].values()]}
    for r in records.values():
        for symbol,target in r['reference_targets'].items():
            if symbol in known: require(target==known[symbol],'construction linked edge')
    rows,_=cleanup.caller.pe.linked(image)
    constants={v:constant(rows,records['initial']['reference_targets']['__ymm@'+v],bytes.fromhex(v)[::-1]) for v in KAT}
    constants['rates']=constant(rows,records['initial']['reference_targets'][TABLE],
                               b''.join(v.to_bytes(8,'little') for v in (168,136,168,136)))
    constants['padding']=constant(rows,records['advance']['reference_targets'][ZERO],bytes(168))
    count=0
    if mutate:
        for name,body in bodies.items():
            for i in range(len(body)):
                changed=bytearray(body); changed[i]^=1
                try: check_bodies(bodies|{name:bytes(changed)})
                except ValueError: count+=1
                else: raise AssertionError('construction review byte mutation escaped')
    data_symbols={TABLE,ZERO,*('__ymm@'+v for v in KAT)}
    return dict(schema=1,date='2026-10-05',status='AUTHOR_SELECTED_CONSTRUCTION_PREFIX_REVIEW',
                object_sha256=slot.OBJECT,image_sha256=slot.IMAGE,entries=records,constants=constants,
                body_byte_mutations_rejected=count,
                unreviewed_direct_callees=sorted({s for c in CALLS.values() for s in c.values()}-known.keys()-data_symbols),
                initial_specialized_algorithm_domain=[4,5,6,7],leaf_identity_to_algorithm=[4,5,4,5],
                inline_root_prefix_initialization_qualified=False,
                prefix_error_requires_caller_cancellation=True,constructor_kat_data_public=True,
                earlier_copies_individually_erased=False,maximum_transitive_stack_depth_qualified=False,
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
    sources=('windows_enclave_construction_review.py','test-windows-enclave-construction-review.py',
             'windows_enclave_engine_review.py','windows_enclave_state_operations.py',
             'windows_enclave_terminal_review.py','windows_enclave_state_cleanup.py',
             'windows_enclave_slot_review.py','windows_enclave_caller_binding.py',
             'windows_enclave_leaf_binding.py','windows_enclave_caller_unwind.py',
             'windows_enclave_caller_handlers.py','windows_enclave_caller_object.py',
             'windows_enclave_wrapper_binding.py','windows_enclave_frame_geometry.py')
    result['source_sha256']={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in sources}
    text=json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
