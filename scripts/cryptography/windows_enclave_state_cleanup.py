"""Saved-image state destruction and exact owned-write ranges; author aid only."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_caller_binding as caller
import windows_enclave_leaf_binding as leaf
import windows_enclave_slot_review as slot
from windows_enclave_frame_geometry import Frame, Window, require

MEMORY = '_RNvMNtCscBEH4D3OuJh_22sha3_accelerated_state6engineNtB2_6Memory4wipe'
SCRATCH = '_RNvMNtNtCshYLbG8W7MpL_17brynja_crypto_cpu18hardened_execution14keccak_scratchNtB2_13KeccakScratch4wipe'
BODIES = {
    'state': (slot.STATE_DROP,204,'26426988297c40c744deca9b4d347716b9cde0051aeba36b494fc090749c7a93'),
    'memory': (MEMORY,74,'6fa655a9c6d73f0f23856804ff8206e0443298bcf53d0368664a15fae13d4859'),
    'scratch': (SCRATCH,128,'a093147dfcbd9774621f07705b5bb6ca7c47d8cd15d3ca14d67311fbcc2079f7'),
    'clear': (slot.CLEAR,89,'c0bc244ea4f39b7eef6d89558938bd751d42f7cb67bdbf414c17462b44be98e2'),
}
TRANSFERS = {
    'state': {0x33:(MEMORY,0xe8),0x4d:(slot.CLEAR,0xe8),0x81:(MEMORY,0xe8),
              0x89:(SCRATCH,0xe8),0xa3:(slot.CLEAR,0xe8)},
    'memory': {o:(slot.CLEAR,0xe9 if o==0x46 else 0xe8) for o in (0x12,0x1f,0x2d,0x46)},
    'scratch': {o:(slot.CLEAR,0xe9 if o==0x7c else 0xe8) for o in (0xe,0x1f,0x30,0x41,0x52,0x63,0x7c)},
    'clear': {},
}
# Whole bodies are pinned as well: these anchors document the load-bearing
# instructions, rather than treating a byte hash as semantic proof.
ANCHORS = (
    ('state',0,'56574883ec28'),
    ('state',6,'83b9b0030000020f84af000000'),
    ('state',0x16,'c6815b0300000148c7816802000000000000488db970020000'),
    ('state',0x37,'80beaa030000ff742c488d8ea8030000ba01000000'),
    ('state',0x51,'c686a903000000c5f857c0c5fc298660030000c5fc298680030000'),
    ('state',0x6c,'c686aa030000ffc686c2030000034889f9c5f877'),
    ('state',0x8d,'80beaa030000ff742c488d8ea8030000ba01000000'),
    ('state',0xa7,'c686a903000000c5f857c0c5fc298660030000c5fc298680030000'),
    ('state',0xc2,'4883c4285f5ec5f877c3'),
    ('memory',0,'564883ec204889ce4883c120bac8000000'),
    ('memory',0x16,'ba100000004889f1'),
    ('memory',0x23,'488d4e10ba10000000'),
    ('memory',0x31,'4881c6e8000000ba020000004889f14883c4205e'),
    ('scratch',0,'564883ec204889cebac8000000'),
    ('scratch',0x12,'488d8ec8000000ba28000000'),
    ('scratch',0x23,'488d8ef0000000ba28000000'),
    ('scratch',0x34,'488d8e18010000bac8000000'),
    ('scratch',0x45,'488d8ee0010000ba20000000'),
    ('scratch',0x56,'488d8e00020000ba20000000'),
    ('scratch',0x67,'4881c620020000ba200000004889f14883c4205e'),
    ('clear',0,'4989d04889c84983e007740f4889c890c6000048ffc049ffc875f5'),
    ('clear',0x1b,'4883fa0872374801d1'),
    ('clear',0x30,'c60000c6400100c6400200c6400300c6400400c6400500c6400600c64007004883c0084839c875d8c3'),
)
MEMORY_REGIONS = ((32,200),(0,16),(16,16),(232,2))
SCRATCH_REGIONS = ((0,200),(200,40),(240,40),(280,200),(480,32),(512,32),(544,32))


def check_bodies(bodies):
    require(set(bodies)==set(BODIES),'exact state cleanup population')
    for name,(_,size,digest) in BODIES.items():
        require(len(bodies[name])==size and hashlib.sha256(bodies[name]).hexdigest()==digest,
                'reviewed cleanup body: '+name)


def check_instructions(bodies, refs):
    require(set(bodies)==set(refs)==set(BODIES),'complete cleanup instruction inputs')
    for name,transfers in TRANSFERS.items():
        require(len(refs[name])==len(transfers) and
                {r['offset']:r['symbol'] for r in refs[name]}=={o:s for o,(s,_) in transfers.items()},
                'exact cleanup relocations')
        for r in refs[name]:
            offset=r['offset']
            require(r['addend']==r['trailing']==0 and bodies[name][offset-1:offset+4]==
                    bytes([transfers[offset][1]])+bytes(4),'cleanup call/tail-call opcode')
    for name,offset,hexcode in ANCHORS:
        code=bytes.fromhex(hexcode)
        require(bodies[name][offset:offset+len(code)]==code,'cleanup semantic anchor')


def clear_offsets(length):
    """Model the reviewed remainder-then-eight-store loops, not native execution."""
    require(type(length) is int and 0<=length<=65536,'bounded modeled clear length')
    cursor=0
    offsets=[]
    for _ in range(length & 7):
        offsets.append(cursor)
        cursor+=1
    if length>=8:
        while cursor!=length:
            offsets.extend(cursor+i for i in range(8))
            cursor+=8
    return offsets


def write_ranges(empty, prefix_present):
    """Writes for valid initialized states only; no forged-tag/OS-fault claim."""
    require(type(empty) is bool and type(prefix_present) is bool,'explicit initialized variant')
    if empty: return dict(volatile=[],ordinary_zero=[],ordinary_marker=[])
    memory=[(624+offset,size) for offset,size in MEMORY_REGIONS]
    volatile=memory+([(936,1)] if prefix_present else [])+memory+list(SCRATCH_REGIONS)
    ordinary_zero=[(616,8)]+([(937,1),(864,64)] if prefix_present else [])
    # Memory/scratch writes cannot alter the prefix's discriminant at 938;
    # after it is set to 255 the retained second prefix check skips normally.
    return dict(volatile=volatile,ordinary_zero=ordinary_zero,ordinary_marker=[(859,1),(938,1),(962,1)])


def geometry(window):
    parent=window.high+slot.geometry(window)['frames']['run']
    state=Frame.enter(window,parent,56)
    helper=Frame.enter(window,state.current,40)
    # Direct clear call adds a return address; each final tail clear reuses
    # the helper's incoming return/home space after its frame is restored.
    spans=[state.slot('state destructor RSI/RDI saves',-16,16,'entry'),
           helper.slot('memory or scratch RSI save',-8,8,'entry'),
           window.span('direct clear return/home',helper.current-8,40),
           window.span('tail clear reused return/home',helper.entry,40)]
    return dict(state_from_high=state.current-window.high,helper_from_high=helper.current-window.high,
                direct_clear_entry_from_high=helper.current-8-window.high,
                tail_clear_entry_from_high=helper.entry-window.high,spans=spans,
                scoped_cleanup_chain_has_external_callees=False,
                maximum_whole_worker_depth_qualified=False,exception_cleanup_qualified=False)


def inspect(data,image,mutate=False):
    previous=slot.inspect(data,image)
    bodies,refs={},{}
    for name,(symbol,_,_) in BODIES.items(): bodies[name],refs[name]=caller.function(data,symbol)
    check_bodies(bodies)
    check_instructions(bodies,refs)
    records={n:slot.binding.bind(data,image,spec[0]) for n,spec in BODIES.items() if n!='clear'}
    records['clear']=leaf.bind(data,image,slot.CLEAR,list(records.values()))
    by_symbol={r['entry']:r['rva'] for r in records.values()}
    for record in records.values():
        for symbol,target in record['reference_targets'].items():
            require(symbol in by_symbol and target==by_symbol[symbol],'closed exact cleanup call graph')
    for record in previous['entries'].values():
        for symbol in (slot.STATE_DROP,slot.CLEAR):
            if symbol in record['reference_targets']:
                require(record['reference_targets'][symbol]==by_symbol[symbol],'slot-to-cleanup edge')
    count=0
    if mutate:
        for name,code in bodies.items():
            for i in range(len(code)):
                changed=bytearray(code)
                changed[i]^=1
                try: check_bodies(bodies|{name:bytes(changed)})
                except ValueError: count+=1
                else: raise AssertionError('accepted cleanup body mutation')
    return dict(schema=1,date='2026-10-05',status='AUTHOR_SELECTED_STATE_CLEANUP_CHAIN_REVIEW',
                object_sha256=slot.OBJECT,image_sha256=slot.IMAGE,entries=records,
                reviewed_body_sha256={n:s[2] for n,s in BODIES.items()},
                instruction_anchors=len(ANCHORS),call_and_tail_sites=sum(map(len,TRANSFERS.values())),
                body_byte_mutations_rejected=count,geometry=geometry(Window(0,65536)),
                writes={name:write_ranges(e,p) for name,e,p in
                        (('empty',True,False),('live_no_prefix',False,False),('live_prefix',False,True))},
                all_992_state_bytes_individually_erased=False,prior_moved_copies_erased_by_destructor=False,
                native_run_added=False,whole_image_qualified=False,release_gate_changed=False,
                independently_verified=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('object',type=Path)
    parser.add_argument('image',type=Path)
    parser.add_argument('--mutate',action='store_true')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=inspect(args.object.read_bytes(),args.image.read_bytes(),args.mutate)
    sources=('windows_enclave_state_cleanup.py','test-windows-enclave-state-cleanup.py',
             'windows_enclave_slot_review.py','windows_enclave_caller_binding.py',
             'windows_enclave_caller_unwind.py','windows_enclave_leaf_binding.py',
             'windows_enclave_caller_handlers.py','windows_enclave_caller_object.py',
             'windows_enclave_wrapper_binding.py','windows_enclave_frame_geometry.py')
    result['source_sha256']={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in sources}
    text=json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
