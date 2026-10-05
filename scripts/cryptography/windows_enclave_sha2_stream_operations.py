"""Offline binding of five saved scalar SHA-2 owner operations, not their callees."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_sha2_stream_lifecycle as lifecycle
from windows_enclave_construction_review import constant

entry,shared,bounded = lifecycle.entry,lifecycle.shared,lifecycle.bounded
require,digest,obj = lifecycle.require,lifecycle.digest,entry.obj
BEGIN,UPDATE,FINISH,REHASH = (lifecycle.PREFIX+s for s in ('5begin','6update','6finish','6rehash'))
EXPORT = '_RINvMs0_Csad7P77nok56_11sha2_streamNtB6_5Owner13export_publicNCNvCsgcnLRhTPBg3_18sha2_stream_worker7receives_0EB11_'
STATE = '_RNvMNtCsad7P77nok56_11sha2_stream17sha2_stream_stateNtB2_5State'
NEW,STATE_FINISH = STATE+'3new',STATE+'6finish'
MASK = '_RNvNtCscJA3KwNFXab_16brynja_hash_core23secret_memory_predicate12mask_is_zero'
COPY = '_RNvNtCsjNKEhcqdpKw_11brynja_core13secret_memory18copy_secret_region'
UPDATE32,UPDATE64 = ('_RNvMNtNtCskNJ9UBpP4M4_16brynja_hash_sha28hardened7state'+w+
                     'NtNtB4_5owner17HardenedSha2Owner8update'+w for w in ('32','64'))
PINS = {
    BEGIN:(314,'ad232c8a3cf2b5bcc693477a22e873526545e3f37b235e1b748e458cb988bf8b',
           'a5cc15c1e91192c1a872fcacc3045171682eb368d5d7853ae11757adc1564983'),
    UPDATE:(261,'5951109cf038e54bd4c53efcbe8e9e023f9388d0a54e7b5ad6b0be5f7db420b9',
            '7f5045a6e7c4496760895c39ad6cf036be91df2f9f4564ac15837a8783ba83e9'),
    FINISH:(523,'16d7ab4cfe6f5dca6388a4cb7018144379d76c95b47d5e960c491e9d1ec22404',
            '968433e4bd8a538f3e4a005ef49dde9b2d1bcc107772153bc7776dd5a220d7ec'),
    REHASH:(910,'d2dee376ad10e89c53b188ecadcf987319ca09402288bbf4c76689b083cada07',
            '8fac384241be0a951fc75be467b9580f7835789a13805e1887c755e6d1b5cc88'),
    EXPORT:(565,'95170f6e5cc33f87b544824668fa73ab6ae56fc30c67ef33c28688b29a00dee0',
            '6016cc34048cabe2cfb739a2531ab03c26328369ea16f8ee6b1543bffb2ec921'),
}
FRAMES = {BEGIN:1224,UPDATE:1240,FINISH:2456,REHASH:1368,EXPORT:1240}
TARGETS = {lifecycle.OPERATION:10464,NEW:10736,STATE_FINISH:14624,lifecycle.wiping.WIPE:6208,
           bounded.CLEAR:5920,'memcpy':28336,MASK:6176,COPY:6112,UPDATE32:7056,UPDATE64:8288,
           'PublicSha2Output':21680}
# Object REL32 slots encode destinations relative to the start of each seven-entry table.
TABLES = {
    UPDATE:('7100000075000000680000006c000000700000007400000018010000',
            (109,109,92,92,92,92,252),((79,0),)),
    FINISH:('fb00000006010000430100001c0100000b010000160100002f010000',
            (247,254,311,268,247,254,275),((234,0),)),
    REHASH:('c2010000d3000000c5010000f3000000d2010000e300000009010000'
            '4a0200001f0200004c0200002f0200005a0200002f02000043020000'
            '9e020000aa020000b6020000d7020000ae020000ba020000ce020000',
            (446,203,441,227,446,203,237,582,535,576,543,582,535,551,
             666,674,682,711,666,674,690),((184,0),(428,28),(522,28),(653,56))),
    EXPORT:('5e000000a60000008a0000009e00000082000000c6000000da000000',
            (90,158,126,142,110,174,190),((77,0),)),
}


def body_check(name,code,refs):
    size,ch,rh = PINS[name]
    require(len(code) == size and digest(code) == ch,'complete scalar operation body')
    require(digest(shared.encoded(refs)) == rh,'complete scalar operation references')


def table_targets(name,raw,address,start):
    expected = TABLES[name][1]
    require(len(raw) == len(expected)*4,'complete algorithm tables')
    targets = [address+(i//28)*28+int.from_bytes(raw[i:i+4],'little',signed=True)-start
               for i in range(0,len(raw),4)]
    require(tuple(targets) == expected,'exact algorithm table destinations')
    return targets


def linked_table(name,rows,address,start):
    raw = bounded.mapping.mapped(rows,address,len(TABLES[name][1])*4)
    constant(rows,address,raw)
    return table_targets(name,raw,address,start)


def jump_table(name,data,image,record):
    raw_hex,expected,sites = TABLES[name];raw = bytes.fromhex(raw_hex)
    rows,symbols,selected,_,refs = obj.select(data,name)
    refs = [r for r in refs if r['symbol'] == '.rdata']
    require(tuple((r['offset'],r['addend']) for r in refs) == sites and
            all(r['trailing'] == 0 for r in refs),'all algorithm table references')
    indices = {r['symbol_index'] for r in refs};require(len(indices) == 1,'same table section')
    symbol = symbols[indices.pop()]
    require(symbol['value'] == 0 and 1 <= symbol['section'] <= len(rows),'defined algorithm table')
    table = rows[symbol['section']-1]
    require(table['code'] == raw and table['flags'] & 0xe0000000 == 0x40000000,'complete readonly algorithm tables')
    relocs = obj.relocations(data,table,symbols)
    require(set(relocs) == set(range(0,len(raw),4)),'all algorithm table relocations')
    for at,ref in relocs.items():
        target = symbols[ref['symbol']]
        require(ref['kind'] == 4 and target['section'] == selected['section'] and target['value'] == 0 and
                target['name'] == '.text','algorithm table only targets selected operation')
        require(int.from_bytes(raw[at:at+4],'little')-(at%28)-4 == expected[at//4],
                'object subtable destination identity')
    rows,_ = shared.caller.pe.linked(image);address = record['reference_targets']['.rdata']
    return dict(rva=address,bytes=len(raw),destinations=linked_table(name,rows,address,record['rva']))


def reconcile(parent,receiver,records):
    for name,record in records.items():
        require(receiver['reference_targets'][name] == record['rva'],'receiver reaches this operation')
        require(record['image_sha256'] == parent['image_sha256'],'same operation image')
        frames = record['unwind']
        require(len(frames) == 1 and frames[0]['stack_bytes'] == FRAMES[name] and
                frames[0]['chain'] is None and not frames[0]['saved_registers'],'complete fixed operation frame')
        targets = {n:v for n,v in record['reference_targets'].items() if n != '.rdata'}
        require(all(n in TARGETS and TARGETS[n] == v for n,v in targets.items()),'reviewed callee addresses')
        require(targets.get(lifecycle.OPERATION) == parent['records'][lifecycle.OPERATION]['rva'] and
                targets.get(lifecycle.wiping.WIPE) == parent['workspace_wipe']['rva'],
                'same reviewed admission and workspace wipe')


def geometry(window):
    body = bounded.Frame.enter(window,window.high-32,56)
    worker = bounded.Frame.enter(window,body.current,1160)
    receive = bounded.Frame.enter(window,worker.current,104)
    slots = {BEGIN:((32,1174),),UPDATE:((32,1174),),FINISH:((32,25),(64,1174),(1242,1174)),
             REHASH:((32,25),(64,64),(136,1174)),EXPORT:((40,1174),)}
    result = {}
    for name,size in FRAMES.items():
        frame = bounded.Frame.enter(window,receive.current,size)
        admission = bounded.Frame.enter(window,frame.current,1224)
        result[name] = dict(rsp_from_high=frame.current-window.high,
                           admission_rsp_from_high=admission.current-window.high,
                           spans=[frame.slot('state, staging or bitstring',at,n) for at,n in slots[name]],
                           callee_entry=frame.unknown_callee('unqualified operation callee entry/home'))
    return dict(operations=result,maximum_transitive_depth_qualified=False,
                inactive_owner_bytes_require_page_teardown=True,stack_copies_require_outer_window_cleanup=True)


def inspect(data,native,image,wrapper,ir,mutate=False):
    # Import after constants: instruction definitions refer to operation names.
    import windows_enclave_sha2_stream_operation_shapes as shapes
    parent = lifecycle.inspect(data,native,image,wrapper,ir)
    receiver = shared.caller.bind(data,image,entry.RECEIVE)
    records = {};tables = {};count = 0;table_count = 0
    for name in PINS:
        code,refs = shared.caller.function(data,name);body_check(name,code,refs);shapes.instructions(name,code)
        records[name] = shared.caller.bind(data,image,name)
        if name in TABLES: tables[name] = jump_table(name,data,image,records[name])
        if mutate:
            for i in range(len(code)):
                changed = bytearray(code);changed[i] ^= 1
                try: body_check(name,changed,refs)
                except ValueError: count += 1
                else: raise AssertionError('accepted actual operation byte mutation')
    reconcile(parent,receiver,records)
    rows,_ = shared.caller.pe.linked(image)
    if mutate:
        for name,table in tables.items():
            at = table['rva'];index = next(i for i,r in enumerate(rows) if r['rva'] <= at < r['rva']+r['virtual_size'])
            row = rows[index]
            for i in range(table['bytes']):
                changed = bytearray(row['code']);changed[at-row['rva']+i] ^= 1
                altered = rows[:index]+[row | {'code':bytes(changed)}]+rows[index+1:]
                try: linked_table(name,altered,at,records[name]['rva'])
                except ValueError: table_count += 1
                else: raise AssertionError('accepted actual algorithm table mutation')
    reviewed = {lifecycle.OPERATION,lifecycle.wiping.WIPE,bounded.CLEAR}
    pending = sorted({n for r in records.values() for n in r['reference_targets'] if n not in reviewed | {'.rdata'}})
    return dict(schema=1,date='2026-10-05',status='SAVED_SCALAR_SHA2_OWNER_OPERATION_REVIEW',
                image_sha256=digest(image),object_sha256=digest(data),compiler_ir_sha256=digest(ir),
                records={n:{k:v for k,v in r.items() if k in ('rva','size','reference_targets','unwind')} for n,r in records.items()},
                tables=tables,geometry=geometry(bounded.Window(0,65536)),
                unqualified_transitive_callees=pending,actual_body_byte_mutations_rejected=count,
                actual_table_byte_mutations_rejected=table_count,whole_image_qualified=False,
                native_run_added=False,release_gate_changed=False,independently_verified=False,
                arbitrary_exception_cleanup_qualified=False,host_copy_rollback_claimed=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('saved_directory',type=Path);p.add_argument('object',type=Path)
    p.add_argument('--catalog',type=Path,default=shared.CATALOG)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path)
    args = p.parse_args();base = args.saved_directory
    row = shared.catalog(args.catalog.read_bytes())[1];require(row['route'] == 'sha2/mod.rs::open','scalar stream route')
    native,image = (base/row['object']).read_bytes(),(base/row['image']).read_bytes()
    require(digest(native) == row['object_sha256'] and digest(image) == row['sha256'],'saved C/image identity')
    require(digest((base/'sha2-scalar-cleanup-image/normal_rust.lib').read_bytes()) == entry.ARCHIVE,'saved Rust archive')
    result = inspect(args.object.read_bytes(),native,image,
                     (base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes(),
                     (base/'sha2-scalar-cleanup-image/normal_rust.ll').read_bytes(),args.mutate)
    sources = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    sources.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha2-stream-operations.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(sources)}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
