"""Saved publication join/drop review; no general concurrency or fatal cleanup proof."""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_caller_binding as caller
import windows_enclave_slot_review as slot
from windows_enclave_frame_geometry import Frame, Window, require

PREFIX='_RNvCsk1CFy3R4N16_20parallel_wave_bridge'
BODIES={
    'join':('_RNvMCsk1CFy3R4N16_20parallel_wave_bridgeNtB2_11Publication4join',271,
            '331226ac01e9e05ddae9ddb74531d23fde1702bd46cd14731176f782e7611bff'),
    'drop':('_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueNtCsk1CFy3R4N16_20parallel_wave_bridge11PublicationEBD_',308,
            '7fd4288f53b1d3c39751230a1e98049b872bc76e5889da878dd181b58907dd39'),
    'option_drop':('_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueINtNtB4_6option6OptionNtCsk1CFy3R4N16_20parallel_wave_bridge11PublicationEEBZ_',340,
                   '221c64a4d610d668123dd040c14c68526fee78fc5fb0b30037eb25089c2c3fd0'),
}
GLOBALS={'5SLOTS':32,'4BITS':32,'5INPUT.0':8,'5WIDTH.0':8,'5BLOCK.0':8}
ABORT={'join':0x109,'drop':0x12e,'option_drop':0x14e}
# The option body has a different initial discriminant branch; the corresponding
# join loop/store sequence is 32 bytes later. Its register allocation matches Drop.
COMMON=(
    (0,'4883ec28'),
    (0x20,'4989c04981e0fffff9ff4981c800000400f04c0fb10275e8'),
)
JOIN_ANCHORS=(
    (4,'807918000f85f5000000'),(0x13,'807914007526'),
    (0x3f,'48b90000000001000000'),(0x49,'eb13'),
    (0x50,'f390f3904883c1fe0f84aa000000'),(0x5e,'84c075ee'),
    (0x62,'4c8b024181e0f00006004181f8000004007415f390'),
    (0x77,'4c8b024181e0f00006004181f80000040075c8'),
    (0x103,'4883c428c3'),(0x10d,'0f0b'),
)
DROP_ANCHORS=(
    (4,'807918000f85f5000000'),(0x13,'807914007526'),
    (0x3f,'49b80000000001000000'),(0x49,'eb13'),
    (0x50,'f390f3904983c0fe0f84cf000000'),(0x5e,'84c075ee'),
    (0x62,'4c8b0a4181e1f00006004181f9000004007415f390'),
    (0x77,'4c8b0a4181e1f00006004181f90000040075c8'),
    (0x103,'80791400751f'),
    (0x110,'4889c24881e2fffff9ff4881ca00000400f0480fb11175e8'),
    (0x128,'4883c428c3'),(0x132,'0f0b'),
)
OPTION_HEAD=((0,'4883ec28'),(4,'0fb6411885c0741883f8020f8433010000'),
             (0x15,'807914000f840a010000e924010000'),(0x29,'807914007530'))


def store_refs(name):
    shift=32 if name=='option_drop' else 0
    result=[]
    for index in range(11):
        symbol=('5SLOTS' if index<4 else '4BITS' if index<8 else ('5INPUT.0','5WIDTH.0','5BLOCK.0')[index-8])
        addend=(index%4)*8-4 if index<8 else -4
        result.append(dict(offset=0x8d+11*index+shift,symbol=PREFIX+symbol,addend=addend,trailing=0))
    return result


def anchors(name):
    if name=='join': return COMMON+JOIN_ANCHORS
    if name=='drop': return COMMON+DROP_ANCHORS
    return OPTION_HEAD+tuple((offset+32,code) for offset,code in COMMON+DROP_ANCHORS
                             if offset>=0x20)


def check_bodies(bodies):
    require(set(bodies)==set(BODIES),'complete publication population')
    for name,(_,size,digest) in BODIES.items():
        require(len(bodies[name])==size and hashlib.sha256(bodies[name]).hexdigest()==digest,
                'reviewed publication body: '+name)


def check_instructions(bodies,refs):
    require(set(bodies)==set(refs)==set(BODIES),'complete publication instruction inputs')
    for name,code in bodies.items():
        expected=store_refs(name)+[dict(offset=ABORT[name],symbol='PrivateWaveAbort',addend=0,trailing=0)]
        require([{k:r[k] for k in ('offset','symbol','addend','trailing')} for r in refs[name]]==expected,
                'exact publication store/abort references')
        for ref in expected[:-1]:
            offset=ref['offset']
            require(code[offset-3:offset+8]==b'\x48\xc7\x05'+
                    ref['addend'].to_bytes(4,'little',signed=True)+bytes(4),'zero qword store with RIP operand')
        offset=ABORT[name]
        require(code[offset-1:offset+4]==b'\xe8\0\0\0\0','only call is abort')
        for offset,hexcode in anchors(name):
            value=bytes.fromhex(hexcode)
            require(code[offset:offset+len(value)]==value,'publication semantic anchor')


def close_word(word):
    require(type(word) is int and 0<=word<(1<<64),'gate word')
    return (word & ~0x60000) | 0x40000


def quiescent(word):
    close_word(word)  # Validate, but do not close the input used by this predicate.
    return word & 0x600f0 == 0x40000


def writable_spans(rows,records):
    first=next(iter(records.values()))['reference_targets']
    spans=[]
    for name,size in GLOBALS.items():
        symbol=PREFIX+name
        address=first[symbol]
        require(all(r['reference_targets'][symbol]==address for r in records.values()),'shared publication global')
        matches=[r for r in rows if r['flags'] & 0xa0000000 == 0x80000000 and
                 0<=address-r['rva']<=r['virtual_size']-size]
        require(len(matches)==1,'complete writable nonexecutable global')
        spans.append(dict(symbol=symbol,rva=address,bytes=size))
    ordered=sorted(spans,key=lambda s:s['rva'])
    require(all(a['rva']+a['bytes']<=b['rva'] for a,b in zip(ordered,ordered[1:])),
            'nonoverlapping publication globals')
    return spans


def inspect(data,image,mutate=False):
    slot.inspect(data,image)  # Exact original image/object identity before parsing.
    bodies,refs={},{}
    for name,(symbol,_,_) in BODIES.items(): bodies[name],refs[name]=caller.function(data,symbol)
    check_bodies(bodies)
    check_instructions(bodies,refs)
    records={n:slot.binding.bind(data,image,s[0]) for n,s in BODIES.items()}
    rows,_=caller.pe.linked(image)
    spans=writable_spans(rows,records)
    stores={}
    for name,record in records.items():
        actual=[]
        for ref in store_refs(name):
            # REL32 field is followed by a four-byte immediate; RIP is after it.
            start=record['reference_targets'][ref['symbol']]+ref['addend']+4
            field=slot.binding.mapped(rows,record['rva']+ref['offset'],4)
            effective=record['rva']+ref['offset']+8+int.from_bytes(field,'little',signed=True)
            require(start==effective,'actual store address includes trailing immediate')
            require(any(s['symbol']==ref['symbol'] and s['rva']<=start<=s['rva']+s['bytes']-8
                        for s in spans),'whole store inside named global')
            actual.append(dict(rva=start,bytes=8))
        stores[name]=actual
    require(stores['join']==stores['drop']==stores['option_drop'],'identical eleven-store cleanup')
    abort={r['reference_targets']['PrivateWaveAbort'] for r in records.values()}
    require(len(abort)==1,'same abort target')
    abort_rva=abort.pop()
    require(slot.binding.executable(rows,abort_rva) and
            slot.binding.mapped(rows,abort_rva,8)==bytes.fromhex('b907000000cd29c3'),'reviewed fastfail body')
    count=0
    if mutate:
        for name,body in bodies.items():
            for i in range(len(body)):
                changed=bytearray(body)
                changed[i]^=1
                try: check_bodies(bodies|{name:bytes(changed)})
                except ValueError: count+=1
                else: raise AssertionError('accepted publication byte mutation')
    window=Window(0,65536)
    root=Frame.enter(window,window.high-208,11160,32)
    frame=Frame.enter(window,root.current,40)
    return dict(schema=1,date='2026-10-05',status='AUTHOR_SELECTED_PUBLICATION_JOIN_DROP_REVIEW',
                object_sha256=slot.OBJECT,image_sha256=slot.IMAGE,entries=records,
                publication_globals=spans,zero_stores=stores['join'],fastfail_rva=abort_rva,
                body_byte_mutations_rejected=count,poll_budget=1<<32,
                scoped_frame_from_high=frame.current-window.high,
                abort_entry_home=frame.unknown_callee('fastfail entry/home'),
                payload_erasure_claimed=False,retirement_qualified=False,
                universal_concurrency_proof=False,fatal_cleanup_qualified=False,
                native_run_added=False,whole_image_qualified=False,release_gate_changed=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('object',type=Path)
    parser.add_argument('image',type=Path)
    parser.add_argument('--mutate',action='store_true')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=inspect(args.object.read_bytes(),args.image.read_bytes(),args.mutate)
    sources=('windows_enclave_publication_review.py','test-windows-enclave-publication-review.py',
             'windows_enclave_slot_review.py','windows_enclave_caller_binding.py',
             'windows_enclave_caller_unwind.py','windows_enclave_caller_handlers.py',
             'windows_enclave_caller_object.py','windows_enclave_wrapper_binding.py',
             'windows_enclave_frame_geometry.py')
    result['source_sha256']={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in sources}
    text=json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
