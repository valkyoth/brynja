"""Selected saved Waves construction/encoding review; not a whole-image gate."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_construction_review as construction
import windows_enclave_terminal_review as terminal
from windows_enclave_frame_geometry import Frame, Window, require

slot, cleanup = construction.slot, construction.cleanup
NEW = terminal.WAVES+'3new'
LEFT = '_RNvMNtCs2u1vj83u0E8_14parallel_waves24parallel_stream_encodingNtB2_20SecretEncodedInteger4left'
PANIC = '_RNvNtNtCs8xEFJqa6dYS_4core9panicking11panic_const24panic_const_shr_overflow'
TABLE = 'switch.table.'+NEW
NAME = 'anon.5f2396cd0f73852b79ba16fa154e009e.0'
BODIES = {
    'new': (NEW,2390,'d7908f7d6a5badf44b3f730f4e0d84f338f3bf685a20ef38986d3c245b44b04f'),
    'later_drop': ('?dtor$59@?0?'+NEW+'@4HA',74,'287b45a2405d77f2d58d0e13d7a5c41090cbcb33e5c0ba56136e2a1acdbacaea'),
    'name_drop': ('?dtor$62@?0?'+NEW+'@4HA',65,'4fe7a4d99221f80daaa339f36e7a7c19cabaab728890da2dec913bd16e218c97'),
    'encode': (construction.ENCODE,487,'7eda2f445aad4fd95fad9d71aec12f252c05170d7b204a671a5bee7814ec5a8e'),
    'block_left': (LEFT,160,'87033e0ac1e947561afea8f14f3682c454f712b413cf0fb130c5857e00ba92c9'),
}
CALLS = {
    'new': {0x12:'__chkstk',0x102:TABLE,0x127:construction.STATE+'7initial',
            **dict.fromkeys((0x159,0x636,0x67d,0x72a,0x770,0x8bf,0x8eb),'memcpy'),
            **dict.fromkeys((0x19d,0x1b6,0x2d1),construction.ENCODE),0x236:'__umodti3',
            **dict.fromkeys((0x2f9,0x4ba),construction.engine.BODIES['absorb'][0]),
            **dict.fromkeys((0x31f,0x354,0x3a2),cleanup.MEMORY),
            **dict.fromkeys((0x330,0x36e,0x3c8,0x5b1),slot.CLEAR),0x3ae:cleanup.SCRATCH,
            0x486:construction.PREFIX+'4bits',0x4eb:construction.PREFIX+'7advance',0x6d3:NAME,
            0x6f0:construction.STATE+'11setup_chunk',0x7bf:construction.STATE+'11setup_chunk',
            0x7e2:construction.STATE+'12finish_setup',0x701:slot.STATE_DROP,0x862:slot.STATE_DROP,
            0x810:LEFT,0x831:terminal.ENCODED,0x94d:terminal.ENCODED,
            0x899:construction.STATE+'6update',0x8d6:'memset'},
    'later_drop': {0x34:slot.STATE_DROP}, 'name_drop': {0x2b:slot.STATE_DROP},
    'encode': {0x146:'memset',0x156:'memcpy'},
    'block_left': {0x1c:slot.CLEAR,0x29:slot.CLEAR,0x9a:PANIC},
}
ANCHORS = (
    ('new',0xc,'b8f81d0000'), ('new',0x16,'4829c4488dac24800000004883e4e04889e3'),
    ('new',0x3a,'4d8d50ff4983fa03'), ('new',0x46,'4d85c9'),
    ('new',0x52,'4881fe00200000'), ('new',0x5b,'4981f900040000'),
    ('new',0x6f,'4981ff01200000'), ('new',0x78,'807a0904'), ('new',0x7e,'807a0801'),
    ('new',0x8f,'4e8d1ccd00000000'), ('new',0xda,'4883fa014883d8ff483d00000100'),
    ('new',0x10a,'4e8b6cc0f841c1e20341b8060706074489d141d3e8'),
    ('new',0x132,'4883ff02'), ('new',0x144,'488d93c10a0000488d8b0103000041b8af030000'),
    ('new',0x1c1,'8d4f0281ff01010000ba020000000f42d1'),
    ('new',0x1d2,'3d01010000410f43c401d08d04c5600000000fb7c0'),
    ('new',0x1e7,'31ff4c01f8400f92c7480fa4c73d4489f883e0074883f8014883dfff'),
    ('new',0x245,'4c89ea4829cab9000000004819c1c4e27917c0490f44cc490f44d44801fa4883d100'),
    ('new',0x267,'66c783f8000000000048c783b80000000000000048c783b000000060000000'),
    ('new',0x2a4,'488993e000000048898be80000004c89abf0000000c683fa00000000'),
    ('new',0x305,'c6835b0600000148c7836805000000000000488d8b70050000'),
    ('new',0x323,'488d8bf8000000ba01000000'),
    ('new',0x361,'488d8ba8060000ba01000000'), ('new',0x3a6,'488d8b00030000'),
    ('new',0x447,'66c783c00a0000016066c783c00b00000200'),
    ('new',0x4a2,'488d8b00030000488d93c00a000041b802000000'),
    ('new',0x606,'c683c20600000066c783c00600000403'),
    ('new',0x61e,'488d8b391a000041b8af030000488d9301030000'),
    ('new',0x662,'488dbba1120000488d93391a000041b8af030000'),
    ('new',0x6be,'48c7838000000060000000c6838800000008'),
    ('new',0x6db,'c643780c488d8ba01200004c8d4370b201'),
    ('new',0x719,'488d8b8a16000041b8af0300004889fa'),
    ('new',0x758,'488d8be1060000488d938a16000041b8af030000'),
    ('new',0x7af,'488d8be006000031d24d89f0'),
    ('new',0x7d7,'488d8be0060000'),
    ('new',0x7ec,'c5f9efc0c5f97f830003000066c783100300000000'),
    ('new',0x801,'488d8b00030000488b53504531c0'),
    ('new',0x829,'488d8b00030000'), ('new',0x857,'488d8be0060000'),
    ('new',0x86b,'440fb68311030000418d48eeb00180f9f0'),
    ('new',0x8aa,'488d8bc00e0000488d93e006000041b8e0030000'),
    ('new',0x8c3,'488dbbc00a000041b8000400004889f931d2'),
    ('new',0x8da,'41b8e0070000'), ('new',0x922,'c4c1797f8600080000'),
    ('new',0x93d,'41c6862008000001488d8b00030000'),
    ('later_drop',0x1c,'4883e2e04889d383bb900a0000ff'),
    ('later_drop',0x2c,'488d8be0060000'), ('name_drop',0x23,'488d8ba0120000'),
    ('encode',0,'5657534881ec30010000'), ('encode',0xa,'4c89c0480fc8480fca'),
    ('encode',0x16,'48895424284889442420'),
    ('encode',0x124,'bf100000004c29c74a8d1c044883c3204981c0ef000000'),
    ('encode',0x13b,'488d0c3c4883c13131d2'), ('encode',0x14a,'488d4c24314889da4989f8'),
    ('encode',0x15a,'40883e'), ('encode',0x1d0,'ffc76689be00010000'),
    ('block_left',0x12,'488d7111ba11000000'), ('block_left',0x20,'ba010000004889f1'),
    ('block_left',0x2d,'4881ff000100004c89f04883d800b8020000004883d800'),
    ('block_left',0x6f,'880344884301'), ('block_left',0x85,'40887b02ffc08806b0ff'),
)
BRANCHES = (
    ('new',0x42,b'\x77',0xaa), ('new',0x49,b'\x74',0xac), ('new',0x59,b'\x77',0xac),
    ('new',0x62,b'\x77',0xac), ('new',0x76,b'\x73',0xac),
    ('new',0x7c,b'\x75',0xd0), ('new',0x82,b'\x75',0xd0), ('new',0xec,b'\x76',0xf3),
    ('new',0x136,b'\x0f\x84',0x3cc), ('new',0x2ff,b'\x0f\x84',0x3e6),
    ('new',0x4c0,b'\x0f\x85',0x305), ('new',0x4f1,b'\x0f\x85',0x323),
    ('new',0x54e,b'\x0f\x84',0x334), ('new',0x6f7,b'\x74',0x70a),
    ('new',0x705,b'\xe9',0x3cc), ('new',0x7a3,b'\x74',0x7d1),
    ('new',0x7c8,b'\x75',0x839), ('new',0x7ea,b'\x75',0x839),
    ('new',0x816,b'\x74',0x86b), ('new',0x835,b'\xeb',0x84a),
    ('new',0x851,b'\x0f\x84',0xb9), ('new',0x87c,b'\x72',0x818),
    ('new',0x8a4,b'\x0f\x85',0x818), ('later_drop',0x2a,b'\x74',0x39),
    ('encode',0x22,b'\x74',0x2c), ('encode',0x27,b'\xe9',0x124),
    *[('encode',o,b'\x0f\x85',0x124) for o in (0x37,0x48,0x5d,0x72,0x87,0x9c)],
    *[('encode',o,b'\x75',0x124) for o in (0xac,0xbb,0xc9,0xd7,0xe8,0xf9,0x10a)],
    ('block_left',0x75,b'\x73',0x89), ('block_left',0x83,b'\x77',0x99),
)


def operand(symbol):
    return bytes.fromhex('488d05') if symbol in (TABLE,NAME) else b'\xe8'


def check_bodies(bodies):
    require(set(bodies)==set(BODIES),'root setup body population')
    for n,(_,size,digest) in BODIES.items():
        require(len(bodies[n])==size and hashlib.sha256(bodies[n]).hexdigest()==digest,'root setup body: '+n)


def check_instructions(bodies,refs):
    require(set(bodies)==set(refs)==set(BODIES),'root setup inputs')
    for n,calls in CALLS.items():
        require(len(refs[n])==len(calls) and {r['offset']:r['symbol'] for r in refs[n]}==calls,'root setup references')
        for r in refs[n]:
            o=r['offset']; op=operand(r['symbol'])
            require(r['addend']==r['trailing']==0 and bodies[n][o-len(op):o+4]==op+bytes(4),'root setup operand')
    for n,o,h in ANCHORS:
        b=bytes.fromhex(h)
        require(bodies[n][o:o+len(b)]==b,'root setup landmark')
    for n,o,op,target in BRANCHES:
        width=4 if len(op)==2 or op==b'\xe9' else 1
        end=o+len(op)+width
        require(bodies[n][o:o+len(op)]==op and
                end+int.from_bytes(bodies[n][end-width:end],'little',signed=True)==target,'root setup branch')


def reviewed_lengths(identity,block,total,custom,output):
    """Arithmetic model of this bounded caller, not execution of the saved image."""
    require(all(type(x) is int and 0<=x<1<<64 for x in (identity,block,total,custom,output)), 'integer domain')
    require(1<=identity<=4 and 1<=block<=1024 and custom<=8192 and output<=8192,'admitted shape')
    leaves=(total+block*8-1)//(block*8)
    require(leaves<=65536,'admitted leaf bound')
    rate=168 if identity in (1,3) else 136
    encoded_custom=1+max(1,(custom.bit_length()+7)//8)
    prefix=(8*(2+2+encoded_custom)+96+custom+7)//8
    return dict(algorithm=6 if rate==168 else 7,rate=rate,expected_leaves=leaves,
                prefix_bytes=((prefix+rate-1)//rate)*rate,
                block_encoding=bytes([1,block]) if block<256 else bytes([2,block>>8,block&255]))


def geometry():
    window=Window(0,65536)
    body=Frame.enter(window,65504,168)
    root=Frame.enter(window,body.current,11160,32)
    new=Frame.enter(window,root.current,7736,32)
    spans=[new.slot(label,offset,size) for label,offset,size in (
        ('initial working core',0x300,992), ('returned initial core / later public output',0xac0,1024),
        ('pre-name state',0x12a0,992), ('post-name state',0x6e0,992),
        ('pre-name moved payload, first byte/metadata held separately',0x1a39,943),
        ('post-name moved payload, first byte/metadata held separately',0x168a,943),
        ('final state before owner move',0xec0,992), ('uninstalled prefix',0xb0,80),
        ('prefix move temporary A',0x2a0,80), ('prefix move temporary B',0x240,80),
        ('block framing after initial core move',0x300,18))]
    return dict(spans=spans,new_rsp_from_window_high=new.current-window.high,
                earlier_copies_individually_erased=False,
                all_reachable_callee_depths_qualified=False,exception_dispatch_qualified=False)


def inspect(data,image,mutate=False):
    prior=construction.inspect(data,image)
    term=terminal.inspect(data,image)
    adapters=construction.engine.adapters.inspect(data,image)
    direct=cleanup.inspect(data,image)
    selected={n:slot.binding.obj.select(data,s[0]) for n,s in BODIES.items()}
    bodies={n:s[3] for n,s in selected.items()}; refs={n:s[4] for n,s in selected.items()}
    check_bodies(bodies); check_instructions(bodies,refs)
    records={n:slot.binding.bind(data,image,s[0]) for n,s in BODIES.items()}
    for n in ('later_drop','name_drop'):
        require(any(r['symbol']==BODIES[n][0] and r['target_rva']==records[n]['rva']
                    for r in records['new']['metadata']),'constructor exact retained funclet')
    bound=[*records.values(),*prior['entries'].values(),*term['entries'].values(),
           *adapters['entries'].values(),*direct['entries'].values()]
    engine=construction.engine.inspect(data,image)
    bound += list(engine['entries'].values())
    known={r['entry']:r['rva'] for r in bound}
    root=slot.binding.bind(data,image,'PrivateWaveRoot')
    for r in [root,*records.values(),prior['entries']['advance']]:
        for s,t in r['reference_targets'].items():
            if s in known: require(t==known[s],'root setup linked edge')
    rows,_=cleanup.caller.pe.linked(image)
    constants={
        'rate_table':construction.constant(rows,records['new']['reference_targets'][TABLE],
                                          b''.join(v.to_bytes(8,'little') for v in (168,136,168,136))),
        'function_name':construction.constant(rows,records['new']['reference_targets'][NAME],b'ParallelHash'),
    }
    count=0
    if mutate:
        for n,body in bodies.items():
            for i in range(len(body)):
                changed=bytearray(body); changed[i]^=1
                try: check_bodies(bodies|{n:bytes(changed)})
                except ValueError: count+=1
                else: raise AssertionError('root setup body mutation escaped')
    return dict(schema=1,date='2026-10-05',status='AUTHOR_SELECTED_ROOT_SETUP_REVIEW',
                object_sha256=slot.OBJECT,image_sha256=slot.IMAGE,entries=records,constants=constants,
                body_byte_mutations_rejected=count,geometry=geometry(),
                unreviewed_direct_callees=sorted({s for c in CALLS.values() for s in c.values()}-known.keys()-{TABLE,NAME}),
                block_encoder_specialized_to_maximum_1024=True,public_prefix_lengths=True,
                native_run_added=False,whole_image_qualified=False,release_gate_changed=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('object',type=Path); parser.add_argument('image',type=Path)
    parser.add_argument('--mutate',action='store_true'); parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=inspect(args.object.read_bytes(),args.image.read_bytes(),args.mutate)
    sources=('windows_enclave_root_setup.py','test-windows-enclave-root-setup.py',
             'windows_enclave_construction_review.py','windows_enclave_engine_review.py',
             'windows_enclave_state_operations.py','windows_enclave_terminal_review.py',
             'windows_enclave_state_cleanup.py','windows_enclave_slot_review.py',
             'windows_enclave_caller_binding.py','windows_enclave_leaf_binding.py',
             'windows_enclave_caller_handlers.py','windows_enclave_caller_object.py',
             'windows_enclave_caller_unwind.py','windows_enclave_wrapper_binding.py',
             'windows_enclave_frame_geometry.py')
    result['source_sha256']={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in sources}
    text=json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
