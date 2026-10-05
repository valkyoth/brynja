"""Saved bounded SHA-256 dispatcher lifecycle, not its hashing callees."""
import argparse
import json
from pathlib import Path

import windows_enclave_sequential_c as shared
import windows_enclave_caller_object as obj
import windows_enclave_caller_handlers as mapping
import windows_enclave_leaf_binding as leaf
from windows_enclave_frame_geometry import Frame, Window

require,digest = shared.require,shared.digest
OBJECT = 'c6fb9928677c04458d9c8ec31f55746ff97b1fec7c21ef20fa8f4e8104400445'
ARCHIVE = 'ca26f3d5fe8f2148377ed3de9cfc7fb2e021f7482f7a09c3cd709133c4837ab5'
MEMBER = 'retained_rehash_worker.retained_rehash_worker.5ba691928e62cbf8-cgu.0.rcgu.o'
CLEAR = '_RNvNtCsjNKEhcqdpKw_11brynja_core22secret_memory_volatile23zeroize_region_volatile'
BODY_HASH = '4d8c592492fb33dbaa743aa551780500b668cdc8d64bccc2b08f29f12df4164e'
REF_HASH = '8b90d10cf47ebd62edb28dc906bb2728f6da47c72a0788ebe24406e35f1aea14'
CLEAR_HASH = '1d1fb26eaddd4029151c3bce70b49cba0f5a2678f6b0a30d8bc8a3f70893d9b6'
TABLE = bytes.fromhex('aa030000fb0100001505000081040000070200000b020000a1030000d3020000d702000032040000')
DESTINATIONS = (934,499,1289,1137,499,499,901,691,691,1034)
LANDMARKS = (
    (0,'4156565755534881ec40010000'),(0x3d,'48ffc7'),(0x4c,'f7c2ff0f0000'),
    (0x64,'b807000000'),(0x97,'4883c008483d0710000075cd'),
    (0x136,'48c705fcffffff00000000'),(0x14d,'ba20000000e800000000c647200431c0'),
    (0x187,'4883c008483d0010000075cd'),(0x193,'660fefc0'),
    (0x1b7,'b804000000'),(0x1d7,'8d4aff83f909'),(0x1ea,'49630c8a4c01d1ffe1'),
    (0x244,'c6472001'),(0x28c,'81f9ffff0000'),(0x2a5,'c6472000b867000000'),
    (0x4ea,'81feffff0000c6472000b905000000b867000000480f44c1'),
    (0x509,'4881c4400100005b5d5f5e415ec3'),
    (0x533,'41b8200000004889c2e80000000089c6488b0fba20000000e800000000'),
    (0x554,'c6472003b869000000'),(0x595,'ba200000004889d9e800000000'),
    (0x5ce,'c6472000b803000000'),(0x639,'b86a000000'),
)
BRANCHES = (
    (0x17,b'\x0f\x84',0x12f),(0x40,b'\x0f\x84',0x639),
    (0x144,b'\x0f\x84',0x504),(0x1dd,b'\x0f\x87',0x509),
    (0x292,b'\x0f\x84',0x525),(0x552,b'\x74',0x5ce),(0x5a4,b'\x74',0x5dc),
)


def bodies_check(code,refs,clear,clear_refs):
    require(len(code) == 1603 and digest(code) == BODY_HASH,'complete bounded dispatcher')
    require(digest(shared.encoded(refs)) == REF_HASH,'complete bounded dispatcher relocations')
    require(len(clear) == 105 and digest(clear) == CLEAR_HASH and not clear_refs,'complete clearing leaf')


def instructions(code):
    for offset,hexcode in LANDMARKS:
        expected = bytes.fromhex(hexcode)
        require(code[offset:offset+len(expected)] == expected,'bounded dispatcher landmark')
    for offset,opcode,target in BRANCHES:
        width = 4 if len(opcode) == 2 else 1
        value = code[offset+len(opcode):offset+len(opcode)+width]
        require(code[offset:offset+len(opcode)] == opcode and len(value) == width and
                offset+len(opcode)+width+int.from_bytes(value,'little',signed=True) == target,'bounded dispatcher branch')


def table_destinations(raw,table_rva,entry_rva):
    require(len(raw) == 40,'complete ten-entry dispatcher table')
    targets = [table_rva+int.from_bytes(raw[i:i+4],'little',signed=True)-entry_rva for i in range(0,40,4)]
    require(tuple(targets) == DESTINATIONS,'exact operation destinations')
    return targets


def jump_table(data,image,record):
    rows,symbols,selected,_,refs = obj.select(data,'RetainedWork')
    refs = [r for r in refs if r['offset'] == 486 and r['symbol'] == '.rdata']
    require(len(refs) == 1 and refs[0]['addend'] == refs[0]['trailing'] == 0,'unique table reference')
    symbol = symbols[refs[0]['symbol_index']]
    require(symbol['value'] == 0 and 1 <= symbol['section'] <= len(rows),'defined table start')
    table = rows[symbol['section']-1]
    require(table['name'] == b'.rdata' and table['flags'] & 0xe0000000 == 0x40000000
            and table['code'] == TABLE,'complete readonly object table')
    relocs = obj.relocations(data,table,symbols)
    require(set(relocs) == set(range(0,40,4)),'complete table relocations')
    for index,reloc in relocs.items():
        target = symbols[reloc['symbol']]
        require(reloc['kind'] == 4 and target['section'] == selected['section']
                and target['value'] == 0 and target['name'] == '.text','table targets dispatcher section')
        require(int.from_bytes(TABLE[index:index+4],'little')-index-4 == DESTINATIONS[index//4],
                'object table addend identity')
    linked,_ = shared.caller.pe.linked(image)
    address = record['reference_targets']['.rdata']
    candidates = [r for r in linked if r['rva'] <= address and address+40 <= r['rva']+min(r['virtual_size'],len(r['code']))]
    require(len(candidates) == 1 and candidates[0]['flags'] & 0xe0000000 == 0x40000000,'readonly linked table')
    raw = mapping.mapped(linked,address,40)
    return dict(rva=address,bytes=40,operation_offsets=table_destinations(raw,address,record['rva']))


def geometry(window):
    body = Frame.enter(window,window.high-32,56)
    worker = Frame.enter(window,body.current,360)
    slots = [worker.slot('saved nonvolatile GPRs',-40,40,'entry'),worker.slot('callee result',48,48)]
    slots += [worker.slot('token/candidate copy',i,32) for i in (96,128,160,192,224,256,288)]
    slots.append(worker.slot('opaque output argument',400,8))
    return dict(worker_rsp_from_high=worker.current-window.high,slots=slots,
                unknown_callee=worker.unknown_callee('hash/rehash/copy entry and home'),
                maximum_transitive_depth_qualified=False,individual_stack_copies_erased=False)


def inspect(data,native,image,wrapper,mutate=False):
    require(digest(data) == OBJECT,'saved bounded worker object')
    parent = shared.inspect(native,image,wrapper)
    code,refs = shared.caller.function(data,'RetainedWork')
    clear,clear_refs = shared.caller.function(data,CLEAR)
    bodies_check(code,refs,clear,clear_refs); instructions(code)
    record = shared.caller.bind(data,image,'RetainedWork')
    require(record['rva'] == parent['retained_worker_rva'],'C dispatcher calls this Rust worker')
    cleared = leaf.bind(data,image,CLEAR,[record])
    table = jump_table(data,image,record)
    count = 0
    if mutate:
        for which,original in enumerate((code,clear)):
            for index in range(len(original)):
                changed = bytearray(original); changed[index] ^= 1
                try: bodies_check(changed if which == 0 else code,refs,changed if which else clear,clear_refs)
                except ValueError: count += 1
                else: raise AssertionError('accepted bounded body mutation')
    return dict(schema=1,date='2026-10-05',status='SAVED_BOUNDED_DISPATCH_LIFECYCLE_REVIEW',
                dispatcher=record,clearing_leaf=cleared,jump_table=table,geometry=geometry(Window(0,65536)),
                object_sha256=OBJECT,archive_sha256=ARCHIVE,archive_member=MEMBER,
                actual_body_byte_mutations_rejected=count,hash_and_rehash_callees_qualified=False,
                public_copy_sdk_semantics_qualified=False,whole_image_qualified=False,
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
    require(digest((base/'bounded-cleanup-image/normal_rust.lib').read_bytes()) == ARCHIVE,'saved bounded archive')
    wrapper = (base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes()
    result = inspect(args.object.read_bytes(),native,image,wrapper,args.mutate)
    sources = ('windows_enclave_bounded_dispatch.py','test-windows-enclave-bounded-dispatch.py',
               'windows_enclave_sequential_c.py','windows_enclave_caller_binding.py','windows_enclave_caller_object.py',
               'windows_enclave_caller_handlers.py','windows_enclave_leaf_binding.py','windows_enclave_frame_geometry.py')
    result['source_sha256'] = {n:digest(Path(__file__).with_name(n).read_bytes()) for n in sources}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
