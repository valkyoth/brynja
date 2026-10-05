"""Saved scheduler engine/transfer review; scoped author aid, not a release gate."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_state_operations as adapters
from windows_enclave_frame_geometry import Frame, Window, require

cleanup = adapters.cleanup
slot = adapters.slot
CORE = '_RNvNtCsjNKEhcqdpKw_11brynja_core'
XOR = CORE+'13secret_memory20xor_secret_byte_bits'
COPY = CORE+'13secret_memory18copy_secret_region'
MASK = CORE+'13secret_memory22apply_secret_byte_mask'
KERNEL = '_RNvNtNtCshYLbG8W7MpL_17brynja_crypto_cpu15x86_avx2_keccak6secret7permute'
SESSION = '_RNvMNtNtCshYLbG8W7MpL_17brynja_crypto_cpu18hardened_execution6keccakNtB2_13KeccakSession7permute'
PAD = 'anon.3a19b6b51e69661c8cb0ff666193b4ce.1'
BODIES = {
    'absorb': (adapters.ENGINE+'6absorb',651,'4c12e2a4b1f50b7b8c3bd2c9fb3bd414ed40a3f0e184664eef555692802d8d75'),
    'finish': (adapters.ENGINE+'6finish',842,'8798c403651427ac4e3b8c935e5bcddafdd7dcc98dc474596b332f89d4bad86f'),
    'read': (adapters.ENGINE+'4read',726,'68b7139138a174c467d0afa9a6cb16e08a835e72dd181f6e0176aea6703b13be'),
    'copy': (COPY,32,'ee504003eb72cad384615984c9faaa1519dbdf48366caa6cfe97e77f04cd3af4'),
    'xor': (XOR,81,'9ceb72d8d224e29d0ec8c649ec6c0f349aa3d834fb21c2369a6e73f7fb21ea7c'),
    'mask': (MASK,5,'e8ebd827d1f36d7cfa5e5220610aa6370284d1589989363f48ac40166362d449'),
    'copy_leaf': (CORE+'22secret_memory_transfer10copy_bytes',68,'820c2a4fdf11073053919c00ab6524a905846dd6347f14a23b9371c1b0fda7e4'),
    'xor_leaf': (CORE+'17secret_memory_xor8xor_bits',32,'446db9bc5866729cb70f723a3065519795e8e169af7ab99ccb3e1048b944df4d'),
    'mask_leaf': (CORE+'18secret_memory_mask9mask_byte',16,'fe10033c91418ee361524797da612bf9a4346f4a267a1dc137b4451cbc783acb'),
}
LEAVES = ('mask','copy_leaf','xor_leaf','mask_leaf')
CALLS = {
    'absorb': {0xbb:KERNEL,0xc3:cleanup.SCRATCH,0x112:XOR},
    'finish': {0x55:adapters.ENGINE+'6absorb',0xbb:XOR,0x11d:XOR,
               0x188:KERNEL,0x190:cleanup.SCRATCH,0x24e:KERNEL,0x256:cleanup.SCRATCH,
               0x28b:PAD,0x299:XOR,0x2a8:SESSION,0x2cf:slot.CLEAR,0x309:cleanup.MEMORY},
    'read': {0x84:cleanup.MEMORY,0x13e:KERNEL,0x146:cleanup.SCRATCH,0x1af:COPY},
    'copy': {0x15:BODIES['copy_leaf'][0]}, 'xor': {0x45:BODIES['xor_leaf'][0]},
    'mask': {1:BODIES['mask_leaf'][0]}, 'copy_leaf': {}, 'xor_leaf': {}, 'mask_leaf': {},
}
ANCHORS = (
    ('absorb',0,'415741564154565755534883ec30'),
    ('absorb',0x8b,'4d01c44983d700'), ('absorb',0xea,'4981f9c8000000'),
    ('absorb',0xfa,'c644242000'), ('absorb',0x12e,'4983f9ff'),
    ('absorb',0x13e,'49ffc14c8989680200004c3b8960020000'),
    ('absorb',0x15d,'4183f801'), ('absorb',0x16a,'483b8148020000'),
    ('absorb',0x17b,'83f904'), ('absorb',0x19f,'88817002000088a171020000'),
    ('absorb',0x24f,'4488997f020000b0ff'),
    ('finish',0,'4157415641554154565755534883ec38'),
    ('finish',0x19,'4488442437'), ('finish',0x64,'4488be58030000889e59030000'),
    ('finish',0x95,'483dc8000000'), ('finish',0xf0,'4981fd40060000'),
    ('finish',0x10f,'88442420'), ('finish',0x15f,'83f901'),
    ('finish',0x16b,'483b8e48020000'), ('finish',0x17c,'83f804'),
    ('finish',0x277,'4881f9c7000000'), ('finish',0x283,'c644242007'),
    ('finish',0x292,'41b00741b101'),
    ('finish',0x2b4,'48c7866802000000000000c6865a03000001ba020000004889f9'),
    ('finish',0x2ec,'c6865b0300000148c78668020000000000004881c6700200004889f1'),
    ('read',0,'4157415641554154565755534883ec28'),
    ('read',0x6a,'c6815b0300000148c78168020000000000004881c170020000'),
    ('read',0xb8,'4c01c04c89c84883d000'), ('read',0xc7,'4c01c34983d1004c894c2420'),
    ('read',0x10a,'4183fa01'), ('read',0x117,'4c3b8948020000'),
    ('read',0x128,'83f804'), ('read',0x16a,'4929c6'),
    ('read',0x180,'4d89f44901c4'), ('read',0x18c,'4981fcc8000000'),
    ('read',0x1a2,'4889d14c89f24989c04d89f1'),
    ('read',0x1ca,'4c89a768020000'), ('read',0x1da,'88998002000088b981020000'),
    ('read',0x1e6,'488b442420'), ('read',0x28c,'4488998f02000040b6ff'),
    ('copy',0,'4883ec28b0024c39ca'), ('copy',0xb,'4989d24c89c24d89d0'),
    ('xor',0,'534883ec30b0014180f908'), ('xor',0xd,'440fb65c2460'),
    ('xor',0x13,'41b2084528ca4538d3'), ('xor',0x23,'4538d0'),
    ('xor',0x28,'b3ff4889c84489d1d2eb450fb6c0450fb6cb0fb6cb894c24204889c1'),
    ('copy_leaf',0,'4989d14989ca31c94c89c24883fa08'),
    ('copy_leaf',0x11,'498b04094989040a4883c1084883ea084883fa08'),
    ('copy_leaf',0x2c,'410fb604094188040a48ffc148ffca'),
    ('copy_leaf',0x3d,'31c031c931d2c3'),
    ('xor_leaf',0,'4989ca448b5c24280fb6024489c1d3e84421d84489c9d3e041300231c031c9c3'),
    ('mask_leaf',0,'4531c00fb60120d04408c0880131c0c3'),
)
BRANCHES = (
    ('absorb',0x92,b'\x0f\x82',0x284), ('absorb',0xf1,b'\x0f\x83',0x269),
    ('absorb',0x11e,b'\x0f\x85',0x269), ('absorb',0x132,b'\x0f\x84',0x27a),
    ('absorb',0x14f,b'\x75',0xde), ('absorb',0x161,b'\x0f\x85',0x25d),
    ('absorb',0x171,b'\x0f\x85',0x270), ('absorb',0x17e,b'\x0f\x84',0xb4),
    ('finish',0x5b,b'\x74',0x64), ('finish',0x5f,b'\xe9',0x2ec),
    ('finish',0x9b,b'\x0f\x83',0x2ec), ('finish',0xc1,b'\x0f\x85',0x2ec),
    ('finish',0xf7,b'\x0f\x83',0x1b8), ('finish',0x129,b'\x0f\x85',0x2ec),
    ('finish',0x135,b'\x0f\x84',0x1d8), ('finish',0x152,b'\x75',0xf0),
    ('finish',0x162,b'\x0f\x85',0x2d8), ('finish',0x172,b'\x0f\x85',0x2e4),
    ('finish',0x17f,b'\x75',0x1c0), ('finish',0x1f7,b'\x75',0x26c),
    ('finish',0x27e,b'\x77',0x2ec), ('finish',0x29f,b'\x75',0x2ec),
    ('finish',0x2ae,b'\x0f\x85',0x5d), ('finish',0x2d6,b'\xeb',0x30d),
    ('read',0xc5,b'\x72',0x6a), ('read',0xd3,b'\x72',0x6a),
    ('read',0x10e,b'\x0f\x85',0x2b0), ('read',0x11e,b'\x0f\x85',0x2c6),
    ('read',0x12b,b'\x0f\x85',0x29b), ('read',0x16d,b'\x0f\x82',0x2c9),
    ('read',0x173,b'\x0f\x84',0x2c9), ('read',0x186,b'\x0f\x82',0x2d1),
    ('read',0x193,b'\x0f\x87',0x2c9), ('read',0x1b5,b'\x0f\x85',0x2be),
    ('read',0x1d4,b'\x0f\x85',0xeb), ('read',0x296,b'\xe9',0x88),
    ('read',0x2cc,b'\xe9',0x6a), ('copy',9,b'\x75',0x1b),
    *[('xor',o,op,0x4b) for o,op in ((0xb,b'\x77'),(0x1c,b'\x77'),(0x21,b'\x74'),(0x26,b'\x77'))],
    ('copy_leaf',0xf,b'\x72',0x27), ('copy_leaf',0x25,b'\x73',0x11),
    ('copy_leaf',0x2a,b'\x74',0x3d), ('copy_leaf',0x3b,b'\x75',0x2c),
)


def check_bodies(bodies):
    require(set(bodies)==set(BODIES),'engine review population')
    for name,(_,size,digest) in BODIES.items():
        require(len(bodies[name])==size and hashlib.sha256(bodies[name]).hexdigest()==digest,
                'reviewed engine/helper body: '+name)


def check_instructions(bodies,refs):
    require(set(bodies)==set(refs)==set(BODIES),'engine instruction population')
    for name,calls in CALLS.items():
        require(len(refs[name])==len(calls) and {r['offset']:r['symbol'] for r in refs[name]}==calls,
                'engine relocation population')
        for r in refs[name]:
            offset=r['offset']
            op=b'\x48\x8d\x15' if r['symbol']==PAD else b'\xe9' if name=='mask' else b'\xe8'
            require(r['trailing']==r['addend']==0 and bodies[name][offset-len(op):offset+4]==op+bytes(4),
                    'engine call/tail/data operand')
    for name,offset,hexcode in ANCHORS:
        code=bytes.fromhex(hexcode)
        require(bodies[name][offset:offset+len(code)]==code,'engine semantic landmark')
    for name,offset,op,target in BRANCHES:
        width=4 if len(op)==2 or op==b'\xe9' else 1
        end=offset+len(op)+width
        require(bodies[name][offset:offset+len(op)]==op and
                end+int.from_bytes(bodies[name][end-width:end],'little',signed=True)==target,
                'engine reviewed branch')


def padding_constant(rows,rva):
    found=[r for r in rows if r['rva']<=rva<r['rva']+min(len(r['code']),r['virtual_size'])]
    require(len(found)==1,'padding constant mapped once')
    row=found[0]
    require(not row['flags'] & 0xa0000000 and row['code'][rva-row['rva']]==0x80,
            'padding constant immutable nonexecutable 0x80')
    return dict(rva=rva,byte=128,readonly=True)


def relative_frames():
    # Independent local frame layouts only: not a transitive root-to-kernel bound.
    window=Window(0,65536)
    frames={n:Frame.enter(window,65504,push+allocation) for n,push,allocation in
            (('absorb',56,48),('finish',64,56),('read',64,40),('copy',0,40),('xor',8,48))}
    slots={'absorb':((32,1,'public XOR destination bit'),),
           'finish':((32,1,'public XOR destination bit'),(55,1,'suffix argument copy')),
           'read':((32,8,'output counter upper word'),),
           'xor':((32,4,'public XOR mask'),), 'copy':()}
    return {n:dict(fixed_bytes=f.entry-f.current,
                   slots=[f.slot(label,o,size) for o,size,label in slots[n]],
                   transitive_depth_qualified=False) for n,f in frames.items()}


def inspect(data,image,mutate=False):
    prior=adapters.inspect(data,image)
    selected={n:cleanup.caller.function(data,s[0]) for n,s in BODIES.items()}
    bodies={n:s[0] for n,s in selected.items()}
    check_bodies(bodies)
    check_instructions(bodies,{n:s[1] for n,s in selected.items()})
    records={n:slot.binding.bind(data,image,s[0]) for n,s in BODIES.items() if n not in LEAVES}
    for n in LEAVES:
        records[n]=cleanup.leaf.bind(data,image,BODIES[n][0],[*prior['entries'].values(),*records.values()])
    direct=cleanup.inspect(data,image)
    known={r['entry']:r['rva'] for r in [*records.values(),*direct['entries'].values()]}
    for r in [*prior['entries'].values(),*records.values()]:
        for symbol,target in r['reference_targets'].items():
            if symbol in known: require(target==known[symbol],'engine/helper linked edge')
    rows,_=cleanup.caller.pe.linked(image)
    pad=padding_constant(rows,records['finish']['reference_targets'][PAD])
    count=0
    if mutate:
        for name,body in bodies.items():
            for i in range(len(body)):
                changed=bytearray(body)
                changed[i]^=1
                try: check_bodies(bodies|{name:bytes(changed)})
                except ValueError: count+=1
                else: raise AssertionError('engine review byte mutation escaped')
    return dict(schema=1,date='2026-10-05',status='AUTHOR_SELECTED_ENGINE_OPERATION_REVIEW',
                object_sha256=slot.OBJECT,image_sha256=slot.IMAGE,entries=records,
                padding=pad,relative_frames=relative_frames(),body_byte_mutations_rejected=count,
                unreviewed_direct_callees=sorted({s for calls in CALLS.values() for s in calls.values()}-known.keys()-{PAD}),
                absorb_requires_caller_cancellation=True,read_destination_transactional=False,
                earlier_read_output_cleared_by_outer_staging=True,
                counter_spills_individually_erased=False,whole_image_qualified=False,
                arbitrary_exception_cleanup_qualified=False,native_run_added=False,release_gate_changed=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('object',type=Path)
    parser.add_argument('image',type=Path)
    parser.add_argument('--mutate',action='store_true')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=inspect(args.object.read_bytes(),args.image.read_bytes(),args.mutate)
    sources=('windows_enclave_engine_review.py','test-windows-enclave-engine-review.py',
             'windows_enclave_state_operations.py','windows_enclave_terminal_review.py',
             'windows_enclave_state_cleanup.py','windows_enclave_slot_review.py',
             'windows_enclave_caller_binding.py','windows_enclave_leaf_binding.py',
             'windows_enclave_caller_unwind.py','windows_enclave_caller_handlers.py',
             'windows_enclave_caller_object.py','windows_enclave_wrapper_binding.py','windows_enclave_frame_geometry.py')
    result['source_sha256']={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in sources}
    text=json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
