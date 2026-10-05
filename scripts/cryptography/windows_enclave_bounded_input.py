"""Offline borrowed-input caller review for the saved bounded SHA-256 image.

Exact emitted bodies, returning branches and known frames, not a proof of all
transitive hashing/copy/runtime callees or arbitrary exception cleanup.
"""
import argparse
import json
from pathlib import Path

import windows_enclave_bounded_dispatch as dispatch

shared = dispatch.shared
require,digest = shared.require,shared.digest
HASH = '_RNvNtCs7RQXX2qQXJA_22retained_rehash_worker24retained_borrowed_worker4hash'
RECEIVE = '_RINvNtCs7RQXX2qQXJA_22retained_rehash_worker24retained_borrowed_worker7receiveNtB2_6NativeEB4_'
LIVE = '_RNvCs7RQXX2qQXJA_22retained_rehash_worker4LIVE'
WIPE = '_RNvMNtNtCskNJ9UBpP4M4_16brynja_hash_sha28hardened5ownerNtB2_17HardenedSha2Owner4wipe'
PINS = {
    HASH:(1868,'520df4f079230c8913e876a834d000b49f17f75b1b6892e9b69cef16f456b8e1',
          '7a2a4a5dde676ce55a7a8475621023a538328acee913790a44d15d1973d0627f'),
    RECEIVE:(1498,'ad69f2d9edfcc1feb9f0f923949d9a2ee48d100d1ac572c03ec6a69146664022',
             '3718412a1ef50742b74ce46d0426dda9c7b10f6a56b837d145be8592c1bea466'),
}
LANDMARKS = {
    HASH:(
        (0,'4157415641554154565755534881ecd8090000'),
        (0x190,'4c29f00f93c1483d000001000f94c020c83c01'),
        (0x1dc,'48c706be00000048c7460800000000'),
        (0x1eb,'488d8c242e050000e800000000'),
        (0x200,'4881c4d80900005b5d5f5e415c415d415e415fc3'),
        (0x294,'48897c2420488d4c2460488d94242e0500004c8d8424ee0000004989c1e800000000'),
        (0x477,'c647200348c706bf000000'),
        (0x4d2,'483d00040000'),(0x6ce,'483d93040000'),
        (0x6f7,'48c744245001000000488d4c2428e80000000083f801'),
        (0x713,'48b800000000010000004809c7'),
    ),
    RECEIVE:(
        (0,'4157415641554154565755534881ece8000000'),
        (0x65,'488dbe0004000041b92000000031c94889fa4d89f8e80000000085c0'),
        (0x83,'48c703790000000f57c00f114308'),
        (0x168,'4883f0044833ae080400004809c50f95c04981fc01040000'),
        (0x1ba,'4c01e2'),(0x1c8,'b9010000004889f24d89e1e80000000085c0'),
        (0x265,'ba000400004889f1e800000000ba200000004c89e1e800000000'),
        (0x2dc,'483d00040000'),(0x45d,'48c703bf0000004c896b0848c7431000000000'),
        (0x470,'ba200000004889f9e800000000ba000400004889f1e800000000'),
        (0x48a,'4881c620040000ba200000004889f1e800000000'),
        (0x4b8,'c6462003'),(0x4cc,'4881c4e80000005b5d5f5e415c415d415e415fc3'),
        (0x4fd,'483d93040000'),(0x564,'48c703020000004c896b0848c7431001000000'),
        (0x579,'48c70378000000'),
        (0x5a1,'ba200000004889f9e800000000ba000400004889f1e800000000ba20000000488b4c2440e800000000'),
    ),
}
BRANCHES = {
    HASH:((0x1a3,'75',0x1be),(0x22e,'75',0x1be),(0x24a,'0f85',0x1be),
          (0x267,'0f85',0x1be),(0x289,'0f85',0x1be),(0x482,'e9',0x1e3),
          (0x4e6,'74',0x4aa),(0x6f0,'74',0x6b2),(0x70d,'0f85',0x45d),(0x747,'e9',0x1eb)),
    RECEIVE:((0x81,'74',0x96),(0x91,'e9',0x470),(0x1bd,'72',0x1e8),
             (0x1c1,'75',0x1e8),(0x1c6,'74',0x1fb),(0x1da,'74',0x1fe),
             (0x2ec,'74',0x2b0),(0x51a,'74',0x4e5),(0x526,'74',0x54f),
             (0x5cf,'0f85',0x49e),(0x5d5,'e9',0x4bc)),
}


def body_check(name,code,refs):
    size,body_hash,refs_hash = PINS[name]
    require(len(code) == size and digest(code) == body_hash,'complete borrowed-input body')
    require(digest(shared.encoded(refs)) == refs_hash,'complete borrowed-input relocations')


def instructions(name,code):
    for offset,hexcode in LANDMARKS[name]:
        raw = bytes.fromhex(hexcode)
        require(code[offset:offset+len(raw)] == raw,'borrowed-input instruction landmark')
    for offset,hexcode,target in BRANCHES[name]:
        opcode = bytes.fromhex(hexcode)
        width = 4 if len(opcode) == 2 or opcode == b'\xe9' else 1
        value = code[offset+len(opcode):offset+len(opcode)+width]
        require(code[offset:offset+len(opcode)] == opcode and len(value) == width and
                offset+len(opcode)+width+int.from_bytes(value,'little',signed=True) == target,
                'borrowed-input branch destination')


def reconcile(parent,records):
    worker = parent['dispatcher']
    hashed,received = records[HASH],records[RECEIVE]
    require(worker['reference_targets'].get(HASH) == hashed['rva'],'dispatcher calls bound hash')
    require(hashed['reference_targets'].get(RECEIVE) == received['rva'],'hash calls bound receive')
    for record in (hashed,received):
        require(record['image_sha256'] == worker['image_sha256'],'same signed image')
        for symbol in (LIVE,dispatch.CLEAR):
            require(record['reference_targets'].get(symbol) == worker['reference_targets'][symbol],
                    'same retained owner and clearing leaf')
    require(WIPE in hashed['reference_targets'] and
            hashed['reference_targets'][WIPE] == received['reference_targets'].get(WIPE),
            'same workspace wipe target (callee not qualified here)')
    for name,size in ((HASH,2584),(RECEIVE,296)):
        frames = records[name]['unwind']
        require(len(frames) == 1 and frames[0]['stack_bytes'] == size and
                frames[0]['chain'] is None,'reviewed fixed caller frame')


def geometry(window):
    body = dispatch.Frame.enter(window,window.high-32,56)
    worker = dispatch.Frame.enter(window,body.current,360)
    hashed = dispatch.Frame.enter(window,worker.current,2584)
    received = dispatch.Frame.enter(window,hashed.current,296)
    spans = [hashed.slot('saved GPRs',-64,64,'entry'),hashed.slot('saved XMM6',2496,16),
             hashed.slot('public observation',40,56),hashed.slot('receive result',96,56),
             hashed.slot('compiler token copy',192,40),hashed.slot('input snapshot',238,1024),
             hashed.slot('input header',1262,32),hashed.slot('digest staging',1294,32),
             hashed.slot('SHA-256 workspace',1326,1170),
             received.slot('saved GPRs',-64,64,'entry'),received.slot('saved XMM6/7',192,32),
             received.slot('placement return and overlapping token copies',72,82),
             received.slot('expected public sequence argument',336,8)]
    return dict(hash_rsp_from_high=hashed.current-window.high,receive_rsp_from_high=received.current-window.high,
                spans=spans,unknown_callees=[hashed.unknown_callee('hash helper entry/home'),
                                           received.unknown_callee('receive helper entry/home')],
                maximum_transitive_depth_qualified=False,individual_stack_copies_erased=False)


def inspect(data,native,image,wrapper,mutate=False):
    parent = dispatch.inspect(data,native,image,wrapper)
    records,count = {},0
    for name in PINS:
        code,refs = shared.caller.function(data,name)
        body_check(name,code,refs); instructions(name,code)
        records[name] = shared.caller.bind(data,image,name)
        if mutate:
            for index in range(len(code)):
                changed = bytearray(code);changed[index] ^= 1
                try: body_check(name,changed,refs)
                except ValueError: count += 1
                else: raise AssertionError('accepted borrowed-input body mutation')
    reconcile(parent,records)
    return dict(schema=1,date='2026-10-05',status='SAVED_BOUNDED_BORROWED_INPUT_CALLER_REVIEW',
                records=records,geometry=geometry(dispatch.Window(0,65536)),
                object_sha256=dispatch.OBJECT,archive_sha256=dispatch.ARCHIVE,
                archive_member=dispatch.MEMBER,actual_body_byte_mutations_rejected=count,
                placement_hash_and_workspace_wipe_qualified=False,public_copy_sdk_semantics_qualified=False,
                rehash_callee_qualified=False,whole_image_qualified=False,
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
    require(row['route'] == 'mod.rs::open','bounded route identity')
    base = args.saved_directory
    native,image = (base/row['object']).read_bytes(),(base/row['image']).read_bytes()
    require(digest(native) == row['object_sha256'] and digest(image) == row['sha256'],'saved bounded C/image')
    require(digest((base/'bounded-cleanup-image/normal_rust.lib').read_bytes()) == dispatch.ARCHIVE,'saved archive')
    wrapper = (base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes()
    result = inspect(args.object.read_bytes(),native,image,wrapper,args.mutate)
    sources = ('windows_enclave_bounded_input.py','test-windows-enclave-bounded-input.py',
               'windows_enclave_bounded_dispatch.py','windows_enclave_sequential_c.py',
               'windows_enclave_caller_binding.py','windows_enclave_caller_object.py',
               'windows_enclave_caller_handlers.py','windows_enclave_leaf_binding.py','windows_enclave_frame_geometry.py')
    result['source_sha256'] = {n:digest(Path(__file__).with_name(n).read_bytes()) for n in sources}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
