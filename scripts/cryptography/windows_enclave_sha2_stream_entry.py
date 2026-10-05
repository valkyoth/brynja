"""Saved scalar SHA-2 streaming entry/receive cleanup, not transitive owners."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_bounded_dispatch as bounded
from windows_enclave_construction_review import constant

shared,obj,leaf = bounded.shared,bounded.obj,bounded.leaf
require,digest = shared.require,shared.digest
MEMBER = 'sha2_stream_worker.sha2_stream_worker.bcb034bc1cec98f1-cgu.0.rcgu.o'
OBJECT = '2c4cfe8710f30f82321e44cde3dcacbe050ea7e86e9e95b1adc63b1d874bc555'
ARCHIVE = 'b8864c58b1944dbd44df15a2c1ffbfeb932959d62d721897fdf8fbf341e60609'
RECEIVE = '_RNvCsgcnLRhTPBg3_18sha2_stream_worker7receive'
DROP = '_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueNtCsgcnLRhTPBg3_18sha2_stream_worker7BuffersEBD_'
LIVE = '_RNvCsgcnLRhTPBg3_18sha2_stream_worker4LIVE.0'
PINS = {
    'RetainedWork':(760,'58420bccf94a6bf3f41c8ea2b17158c804b8b7f5544caa46f94b7ef148e90b60',
                    '2659590653d6502a4fbad2592a5a013d4eecffa7da5890e10caec7455bff9b44'),
    RECEIVE:(414,'0a749028a3c34ad46224a14067c97d950b991a2ad9ffa7c857014e5a3b9fa009',
             '500ba08e9016a1877c8e2eecfdb8c7145d75487ad03ae34fcc6b1768612bacba'),
    DROP:(43,'01634d59cef7c65dc7393b93a577fe0ddfbd1bbe8e82bf757cc36f8fdee3a986',
          '8af1dd860f1da591099ae384c64c4b79d13d7d5cc6dd731b81d758f0e2fc3c8c'),
}
LANDMARKS = {
    'RetainedWork':((0,'415741564154565755534881ec50040000'),
                    (0x11,'4885d2410f94c2f7c2ff0f0000410f95c3b8c80000004508d3'),
                    (0x30,'4d89ca4d29c2410f93c34981fa00000100410f94c24520da4180fa01'),
                    (0xb1,'48c705fcffffff0000000031c9b804000000'),
                    (0x109,'b8c90000004885f6'),(0x117,'0f57c00f1142300f1142200f1142100f1102'),
                    (0x145,'48891500000000b801000000'),
                    (0x166,'4c8d7424204c89f34881eb00fcffff400f92c541b8300400004c89f131d24d89cce800000000'),
                    (0x1cd,'4c8d4424204889f14889fae80000000089c584c0'),
                    (0x1eb,'ba300000004889d9e800000000488d4c2420ba00040000e800000000'),
                    (0x246,'4889f1e800000000488d4c2420e8000000004c89f0'),
                    (0x25b,'4881c4500400005b5d5f5e415c415e415fc3'),
                    (0x2b1,'488d54242041b8010000004889d9e80000000083f801'),
                    (0x2cd,'48b800000000010000004809c74084edbece000000480f45f7'
                            '488d4c2420e8000000004889f0')),
    RECEIVE:((0,'41574156415541545657534883ec30'),
             (0x1d,'488d97000400004531e441b93000000031c94989c0e80000000085c0'),
             (0x50,'4883bf00040000060f95c04d85f60f94c108c14981ff010400000f93c0'
                     '4981fd000100000f93c208c208ca'),
             (0x93,'4c8b87280400004d85c00f94c04d85ff0f94c14531e44c89c24c01fa'),
             (0xbf,'4883e0fe4883f80c'),(0xc9,'4d85e4'),(0xda,'c0e0034438e8'),
             (0xe4,'4c89e84c09f8'),(0xec,'4883fb10'),
             (0xf7,'b9010000004889fa4d89f9e80000000085c0'),
             (0x10f,'4883c3f54883fb05'),(0x11d,'488d050000000048630c984801c1ffe1'),
             (0x14d,'44886c24204889f14c89f24989f84d89f9e800000000'),
             (0x193,'3cff410f94c4')),
    DROP:((0,'564883ec204889ce4881c100040000ba30000000e800000000'
             'ba000400004889f14883c4205ee900000000'),),
}
BRANCHES = {
    'RetainedWork':((0x2a,'0f85',0x25b),(0x4c,'0f85',0x25b),(0x5c,'0f84',0x109),
                    (0x65,'0f84',0x156),(0x73,'0f85',0x25b),(0x7d,'0f85',0x160),
                    (0x94,'74',0xb1),(0x102,'75',0xd0),(0x111,'0f85',0x25b),
                    (0x18f,'0f87',0x240),(0x198,'0f84',0x240),(0x1a1,'0f87',0x240),
                    (0x1b1,'0f87',0x246),(0x1ba,'0f87',0x246),(0x1cb,'77',0x246),
                    (0x1e1,'75',0x1eb),(0x218,'74',0x26d),(0x21f,'0f85',0x2a9),
                    (0x22a,'75',0x2a9),(0x231,'75',0x246),(0x23c,'74',0x212),
                    (0x27d,'75',0x2a9),(0x284,'75',0x2a9),(0x28b,'75',0x2a9),
                    (0x292,'75',0x2a9),(0x29a,'74',0x2b1),(0x2a5,'74',0x278),
                    (0x2af,'eb',0x246),(0x2c7,'0f85',0x246),(0x2f3,'e9',0x25b)),
    RECEIVE:((0x39,'75',0x80),(0x7b,'74',0x93),(0xaf,'72',0x80),(0xb3,'75',0x80),
             (0xc7,'75',0xe4),(0xcc,'75',0x7d),(0xd8,'75',0xf2),(0xe0,'75',0x7d),
             (0xea,'75',0x7d),(0xf0,'74',0xc9),(0xf5,'74',0x10f),(0x109,'0f85',0x7d),
             (0x117,'0f87',0x7d),(0x199,'e9',0x80)),
}
TABLE = bytes.fromhex('310100007d010000590100007501000051010000a0010000')
DESTINATIONS = (301,373,333,357,317,392)


def body_check(name,code,refs):
    size,code_hash,refs_hash = PINS[name]
    require(len(code) == size and digest(code) == code_hash,'complete scalar stream body')
    require(digest(shared.encoded(refs)) == refs_hash,'complete scalar stream references')


def instructions(name,code):
    for at,h in LANDMARKS[name]:
        raw = bytes.fromhex(h);require(code[at:at+len(raw)] == raw,'stream lifecycle/receive instruction')
    for at,h,target in BRANCHES.get(name,()):
        op = bytes.fromhex(h);width = 4 if len(op) == 2 or op == b'\xe9' else 1
        raw = code[at+len(op):at+len(op)+width]
        require(code[at:at+len(op)] == op and len(raw) == width and
                at+len(op)+width+int.from_bytes(raw,'little',signed=True) == target,'stream branch destination')
    if name == 'RetainedWork': clearing_loops(code)


def clearing_loops(code):
    # Complete inline page-store loop and two short-circuit readback loops.
    raw = bytes.fromhex('c6040f00')+b''.join(bytes.fromhex('c6440f')+bytes([i,0]) for i in range(1,8))
    raw += bytes.fromhex('4883c1084881f90010000075cc')
    require(code[0xd0:0xd0+len(raw)] == raw,'eight stores and full 4096-byte page loop')
    for at,h in ((0x207,'b80304000041becd000000483d33040000'),
                 (0x21a,'807c041d00'),(0x225,'807c041e00'),(0x22c,'807c041f00'),
                 (0x233,'807c042000488d4004'),(0x26d,'b80400000041becd000000'),
                 (0x278,'807c041c00'),(0x27f,'807c041d00'),(0x286,'807c041e00'),
                 (0x28d,'807c041f00'),(0x294,'483d00040000'),(0x29c,'807c042000488d4005')):
        raw = bytes.fromhex(h);require(code[at:at+len(raw)] == raw,'complete buffer readback loops')
    header = [base+i for base in range(1027,1075,4) for i in (29,30,31,32)]
    payload = [base+i for base in range(4,1025,5) for i in (28,29,30,31)]
    payload += [base+32 for base in range(4,1024,5)]
    require(sorted(header+payload) == list(range(32,1104)),'readback covers exactly 1072 bytes')
    return dict(page_bytes=4096,payload_rsp_offset=32,payload_bytes=1024,header_rsp_offset=1056,header_bytes=48)


def table_targets(raw,address,entry):
    require(len(raw) == 24,'six complete operation table entries')
    targets = [address+int.from_bytes(raw[i:i+4],'little',signed=True)-entry for i in range(0,24,4)]
    require(tuple(targets) == DESTINATIONS,'exact operation 11..16 destinations')
    return targets


def linked_table(rows,address,entry):
    raw = bounded.mapping.mapped(rows,address,24)
    constant(rows,address,raw)
    return table_targets(raw,address,entry)


def jump_table(data,image,record):
    rows,symbols,selected,_,refs = obj.select(data,RECEIVE)
    refs = [r for r in refs if r['symbol'] == '.rdata']
    require(len(refs) == 1 and refs[0]['offset'] == 288 and refs[0]['addend'] == refs[0]['trailing'] == 0,
            'unique six-operation table reference')
    symbol = symbols[refs[0]['symbol_index']]
    require(symbol['value'] == 0 and 1 <= symbol['section'] <= len(rows),'defined operation table')
    table = rows[symbol['section']-1]
    require(table['code'] == TABLE and table['flags'] & 0xe0000000 == 0x40000000,'complete readonly operation table')
    relocs = obj.relocations(data,table,symbols)
    require(set(relocs) == set(range(0,24,4)),'all table relocations')
    for at,ref in relocs.items():
        target = symbols[ref['symbol']]
        require(ref['kind'] == 4 and target['section'] == selected['section'] and target['value'] == 0 and
                target['name'] == '.text','table only targets receive body')
        require(int.from_bytes(TABLE[at:at+4],'little')-at-4 == DESTINATIONS[at//4],'object destination identity')
    rows,_ = shared.caller.pe.linked(image);address = record['reference_targets']['.rdata']
    return dict(rva=address,operation_offsets=linked_table(rows,address,record['rva']))


def reconcile(parent,records,clear):
    worker,receive,drop = (records[n] for n in ('RetainedWork',RECEIVE,DROP))
    require(worker['rva'] == parent['retained_worker_rva'],'actual C calls this scalar worker')
    require(worker['reference_targets'][RECEIVE] == receive['rva'] and
            worker['reference_targets'][DROP] == drop['rva'],'actual receive and destructor callees')
    for record in (worker,drop):
        require(record['reference_targets'][bounded.CLEAR] == clear['rva'],'same reviewed volatile clearer')
    for name,frame in (('RetainedWork',1160),(RECEIVE,104),(DROP,40)):
        record = records[name];frames = record['unwind']
        require(record['image_sha256'] == parent['image_sha256'] == clear['image_sha256'],'same scalar stream image')
        require(len(frames) == 1 and frames[0]['stack_bytes'] == frame and frames[0]['chain'] is None and
                not frames[0]['saved_registers'],'complete scalar stream fixed frame')


def geometry(window):
    body = bounded.Frame.enter(window,window.high-32,56)
    worker = bounded.Frame.enter(window,body.current,1160)
    receive = bounded.Frame.enter(window,worker.current,104)
    drop = bounded.Frame.enter(window,worker.current,40)
    return dict(worker_rsp_from_high=worker.current-window.high,receive_rsp_from_high=receive.current-window.high,
                drop_rsp_from_high=drop.current-window.high,spans=[worker.slot('payload',32,1024),
                worker.slot('header',1056,48),receive.slot('final-bit argument',32,1)],
                unknown_callees=[receive.unknown_callee('owner operation or input copy entry'),
                                worker.unknown_callee('owner drop/quarantine, fill or observer entry')],
                maximum_transitive_depth_qualified=False,caller_register_erasure_claimed=False)


def inspect(data,native,image,wrapper,mutate=False):
    require(digest(data) == OBJECT,'saved scalar streaming worker object')
    parent = shared.inspect(native,image,wrapper)
    records = {};count = 0
    for name in PINS:
        code,refs = shared.caller.function(data,name);body_check(name,code,refs);instructions(name,code)
        records[name] = shared.caller.bind(data,image,name)
        if mutate:
            for i in range(len(code)):
                changed = bytearray(code);changed[i] ^= 1
                try: body_check(name,changed,refs)
                except ValueError: count += 1
                else: raise AssertionError('accepted actual stream body mutation')
    code,refs = shared.caller.function(data,bounded.CLEAR)
    require(len(code) == 105 and digest(code) == bounded.CLEAR_HASH and not refs,'same reviewed clearing implementation')
    clear = leaf.bind(data,image,bounded.CLEAR,list(records.values()));reconcile(parent,records,clear)
    table = jump_table(data,image,records[RECEIVE]);table_count = 0
    rows,_ = shared.caller.pe.linked(image);address = records['RetainedWork']['reference_targets'][LIVE]
    mapped = [r for r in rows if r['rva'] < address+8 and address < r['rva']+r['virtual_size']]
    require(len(mapped) == 1 and mapped[0]['rva'] <= address and address+8 <= mapped[0]['rva']+mapped[0]['virtual_size'] and
            mapped[0]['flags'] & 0xa0000000 == 0x80000000,'complete nonexecutable live-pointer storage')
    if mutate:
        at = table['rva'];index = next(i for i,row in enumerate(rows) if row['rva'] <= at < row['rva']+row['virtual_size'])
        row = rows[index]
        for i in range(24):
            changed = bytearray(row['code']);changed[at-row['rva']+i] ^= 1
            altered = rows[:index]+[row | {'code':bytes(changed)}]+rows[index+1:]
            try: linked_table(altered,at,records[RECEIVE]['rva'])
            except ValueError: table_count += 1
            else: raise AssertionError('accepted actual operation table mutation')
    known = set(PINS) | {bounded.CLEAR,LIVE,'.rdata'}
    pending = sorted({n for record in records.values() for n in record['reference_targets'] if n not in known})
    compact = {n:{k:v for k,v in record.items() if k in ('rva','size','reference_targets','unwind')} for n,record in records.items()}
    return dict(schema=1,date='2026-10-05',status='SAVED_SCALAR_SHA2_STREAM_ENTRY_REVIEW',
                image_sha256=digest(image),object_sha256=digest(data),records=compact,table=table,
                clearing_leaf_rva=clear['rva'],live_pointer_rva=address,unreviewed_transitive_callees=pending,
                geometry=geometry(bounded.Window(0,65536)),actual_body_byte_mutations_rejected=count,
                actual_table_byte_mutations_rejected=table_count,
                whole_image_qualified=False,native_run_added=False,release_gate_changed=False,
                independent_retest=False,arbitrary_exception_cleanup_qualified=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('saved_directory',type=Path);p.add_argument('object',type=Path)
    p.add_argument('--catalog',type=Path,default=shared.CATALOG)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path)
    args = p.parse_args();base = args.saved_directory
    row = shared.catalog(args.catalog.read_bytes())[1];require(row['route'] == 'sha2/mod.rs::open','scalar streaming route')
    native,image = (base/row['object']).read_bytes(),(base/row['image']).read_bytes()
    require(digest(native) == row['object_sha256'] and digest(image) == row['sha256'],'saved C/image identity')
    require(digest((base/'sha2-scalar-cleanup-image/normal_rust.lib').read_bytes()) == ARCHIVE,'saved Rust archive')
    result = inspect(args.object.read_bytes(),native,image,
                     (base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes(),args.mutate)
    sources = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    sources.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha2-stream-entry.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(sources)}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
