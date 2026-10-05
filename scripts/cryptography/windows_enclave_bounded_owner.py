"""Saved bounded SHA-256 placement and full workspace clearing review."""
import argparse
import json
from pathlib import Path

import windows_enclave_bounded_rehash as rehash

borrowed,dispatch,shared = rehash.borrowed,rehash.dispatch,rehash.shared
require,digest = shared.require,shared.digest
WIPE = borrowed.WIPE
PLACED = '_RNvMCs8UD6ufIeXrh_18retained_placementNtB2_6Placed4hash'
PINS = {
    WIPE:(148,'8c2e8d7bd737912b35a1ff764c5c2cf3c4013361009022c74227789bfc80df38',
          '16a3528d988ad1de153fb04155929141e11fbff244d68c131c3b36fb68c70592'),
    PLACED:(439,'c39692a81d6002b30b707e6249c4dbf9f575e9b28d341ad0b3a01e83686be545',
            'fe3b45dc40565e9b34755603569d52f6fb7cbb72d9df935da4ec9eeefbe5cec1'),
}
RANGES = ((1024,64),(0,128),(1152,16),(1168,2),(128,640),(768,128),(896,128),(1088,64))
LANDMARKS = (
    (0,'4157415641554154565755534883ec38'),
    (0x2c,'ba200000004c89c9e8000000000fb6432085c0'),
    (0x60,'488b6b184883fdff'),(0x6e,'48ffc548896b18'),
    (0xab,'4c89f14c89ea4d89e0e80000000084c0'),
    (0xd9,'488d4c24204c89f241b0014989f1e800000000807c242001'),
    (0xfb,'66c7070104488b0bba20000000e800000000c6432003'),
    (0x11d,'4885c94889d0480f44c14883f820'),
    (0x139,'0f10000f104810410f114f10410f1107'),
    (0x150,'4c89f1e8000000000f1043080f11470848896f1848c7472001000000c60700c6432002'),
    (0x173,'ba200000004889f14883c4385b5d5f5e415c415d415e415fe900000000'),
    (0x19d,'c643200366c7070106'),(0x1a8,'b9200000004889c2e8000000000f0b'),
)
BRANCHES = ((0x3f,'74',0x60),(0x44,'74',0x53),(0x49,'0f85',0xcf),
            (0x5b,'e9',0x173),(0x68,'0f84',0x190),(0xbb,'74',0xd9),
            (0xd4,'e9',0x173),(0xf1,'75',0x113),(0x111,'eb',0x173),
            (0x12b,'75',0x1a8),(0x1a6,'eb',0x173))


def body_check(name,code,refs):
    size,body_hash,refs_hash = PINS[name]
    require(len(code) == size and digest(code) == body_hash,'complete owner body')
    require(digest(shared.encoded(refs)) == refs_hash,'complete owner references')


def coverage(ranges):
    require(len(ranges) == 8,'eight owner regions')
    cursor = 0
    for start,size in sorted(ranges):
        require(type(start) is int and type(size) is int and start == cursor and size > 0,
                'no overlap, gap or empty clearing region')
        cursor += size
    require(cursor == 1170,'complete owner extent')


def wipe_plan(code,refs):
    # Decode only this reviewed straight-line shape, including its tail jump.
    # Every nonoperand byte is checked; register changes cannot retain the plan.
    require(len(code) == 148,'complete wipe shape')
    def at(offset,raw):
        raw = bytes.fromhex(raw)
        require(code[offset:offset+len(raw)] == raw,'wipe instruction shape')
    def word(offset): return int.from_bytes(code[offset:offset+4],'little',signed=True)
    at(0,'564883ec204889ce4881c1');at(15,'ba');at(20,'e800000000')
    at(25,'ba');at(30,'4889f1e800000000')
    ranges = [(word(11),word(16)),(0,word(26))]
    for offset in (38,55,72,89,106):
        at(offset,'488d8e');at(offset+7,'ba');at(offset+12,'e800000000')
        ranges.append((word(offset+3),word(offset+8)))
    at(123,'4881c6');at(130,'ba');at(135,'4889f14883c4205ee900000000')
    ranges.append((word(126),word(131)))
    require(refs == [dict(offset=o,symbol=dispatch.CLEAR,trailing=0,addend=0)
                     for o in (21,34,51,68,85,102,119,144)],'seven clearing calls and tail reference')
    coverage(ranges)
    require(tuple(ranges) == RANGES,'reviewed field identity and order')
    return [dict(offset=start,bytes=size) for start,size in ranges]


def placement_instructions(code):
    for offset,hexcode in LANDMARKS:
        raw = bytes.fromhex(hexcode)
        require(code[offset:offset+len(raw)] == raw,'placement instruction')
    for offset,hexcode,target in BRANCHES:
        opcode = bytes.fromhex(hexcode)
        width = 4 if len(opcode) == 2 or opcode == b'\xe9' else 1
        value = code[offset+len(opcode):offset+len(opcode)+width]
        require(code[offset:offset+len(opcode)] == opcode and len(value) == width and
                offset+len(opcode)+width+int.from_bytes(value,'little',signed=True) == target,
                'placement branch destination')


def reconcile(records,anchors,clear):
    wiped,placed = records[WIPE],records[PLACED]
    require(set(anchors) == {borrowed.HASH,borrowed.RECEIVE,rehash.REHASH,rehash.COMPUTE},'complete caller inventory')
    for record in (*records.values(),*anchors.values()):
        require(record['image_sha256'] == clear['image_sha256'],'same saved image')
        require(record['reference_targets'].get(dispatch.CLEAR) == clear['rva'],'same exact clearing leaf')
    for record in (*anchors.values(),placed):
        require(record['reference_targets'].get(WIPE) == wiped['rva'],'every caller reaches this wipe')
    require(anchors[borrowed.RECEIVE]['reference_targets'].get(PLACED) == placed['rva'],'receive calls this placement hash')
    for name,size in ((WIPE,40),(PLACED,120)):
        frames = records[name]['unwind']
        require(len(frames) == 1 and frames[0]['stack_bytes'] == size and frames[0]['chain'] is None,
                'complete fixed owner frame')


def geometry(window):
    body = dispatch.Frame.enter(window,window.high-32,56)
    worker = dispatch.Frame.enter(window,body.current,360)
    hashed = dispatch.Frame.enter(window,worker.current,2584)
    receive = dispatch.Frame.enter(window,hashed.current,296)
    placed = dispatch.Frame.enter(window,receive.current,120)
    wipe = dispatch.Frame.enter(window,placed.current,40)
    spans = [placed.slot('placement saved GPRs',-64,64,'entry'),placed.slot('finalization return',32,24),
             placed.slot('input pointer and length',160,16),wipe.slot('wipe saved pointer',-8,8,'entry')]
    return dict(placement_rsp_from_high=placed.current-window.high,wipe_rsp_from_high=wipe.current-window.high,
                spans=spans,unknown_callee=placed.unknown_callee('update/finalize entry/home'),
                maximum_transitive_depth_qualified=False,individual_stack_copies_erased=False,
                clearing_tail_call_allocates_frame=False)


def inspect(data,native,image,wrapper,mutate=False):
    parent = dispatch.inspect(data,native,image,wrapper)
    anchors,records,count = {},{},0
    for module in (borrowed,rehash):
        for name in module.PINS:
            code,refs = shared.caller.function(data,name);module.body_check(name,code,refs)
            anchors[name] = shared.caller.bind(data,image,name)
    for name in PINS:
        code,refs = shared.caller.function(data,name);body_check(name,code,refs)
        if name == WIPE: regions = wipe_plan(code,refs)
        else: placement_instructions(code)
        records[name] = shared.caller.bind(data,image,name)
        if mutate:
            for index in range(len(code)):
                changed = bytearray(code);changed[index] ^= 1
                try: body_check(name,changed,refs)
                except ValueError: count += 1
                else: raise AssertionError('accepted owner body mutation')
    reconcile(records,anchors,parent['clearing_leaf'])
    return dict(schema=1,date='2026-10-05',status='SAVED_BOUNDED_OWNER_CLEARING_REVIEW',records=records,
                clearing_regions=regions,geometry=geometry(dispatch.Window(0,65536)),
                object_sha256=dispatch.OBJECT,archive_sha256=dispatch.ARCHIVE,archive_member=dispatch.MEMBER,
                actual_body_byte_mutations_rejected=count,update_finalize_callees_qualified=False,
                length_mismatch_abort_covered_by_normal_cleanup=False,whole_image_qualified=False,
                native_run_added=False,release_gate_changed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('saved_directory',type=Path)
    parser.add_argument('object',type=Path)
    parser.add_argument('--catalog',type=Path,default=shared.CATALOG)
    parser.add_argument('--mutate',action='store_true')
    parser.add_argument('--output',type=Path)
    args = parser.parse_args()
    row = shared.catalog(args.catalog.read_bytes())[0]
    require(row['route'] == 'mod.rs::open','bounded route')
    base = args.saved_directory
    native,image = (base/row['object']).read_bytes(),(base/row['image']).read_bytes()
    require(digest(native) == row['object_sha256'] and digest(image) == row['sha256'],'saved C/image')
    require(digest((base/'bounded-cleanup-image/normal_rust.lib').read_bytes()) == dispatch.ARCHIVE,'saved archive')
    wrapper = (base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes()
    result = inspect(args.object.read_bytes(),native,image,wrapper,args.mutate)
    sources = ('windows_enclave_bounded_owner.py','test-windows-enclave-bounded-owner.py',
               'windows_enclave_bounded_rehash.py','windows_enclave_bounded_input.py',
               'windows_enclave_bounded_dispatch.py','windows_enclave_sequential_c.py',
               'windows_enclave_caller_binding.py','windows_enclave_caller_object.py',
               'windows_enclave_caller_handlers.py','windows_enclave_leaf_binding.py','windows_enclave_frame_geometry.py')
    result['source_sha256'] = {n:digest(Path(__file__).with_name(n).read_bytes()) for n in sources}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
