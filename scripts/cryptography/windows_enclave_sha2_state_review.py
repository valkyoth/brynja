"""Saved scalar state construction/consumption; offline review, not a new gate."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_sha2_state_shapes as shapes
from windows_enclave_construction_review import constant

ops = shapes.ops
shared,bounded,entry = ops.shared,ops.bounded,ops.entry
require,digest,obj = ops.require,ops.digest,ops.obj
NEW,FINISH = shapes.NEW,shapes.FINISH
ROUND = 'anon.7b9e5a485f344afc4b021075be1f825c.0'
CONSTANTS = {ROUND:(640,'125cf2084d7eec18dc9795be4baa221655c0eabab89e90a74fb0370378a60293')}
for name,h in (
    ('39590ef717dd703007d57c36d89e05c1','b678f8d644a7ea66d8c2968fbdcaafabd00be4a9f949d6bec064e41a55146f4e'),
    ('a44ffabea78ff96411155868310bc0ff','21da2e5d1f144451955e3f17b5f4dff1fe2a84e14d768ef91fd66caae81f5a92'),
    ('3af54fa572f36e3c85ae67bb67e6096a','cc6a4cedc5a332f2b9013ef8bb8d303dd533074d0ed118017f28160030a4e8f3'),
    ('19cde05babd9831f8c68059b7f520e51','574b82ad00e15ea5f71562ab8d2a2c4e6f2cd4a407d2b6430dcc927bbbe67c5e')):
    CONSTANTS['__xmm@'+name] = (16,h)
FINAL32,FINAL64 = (n.replace('8update','10finalize') for n in (ops.UPDATE32,ops.UPDATE64))
WRITE = '_RNvNtNtCskNJ9UBpP4M4_16brynja_hash_sha28hardened6output12write_secret'
MASK = '_RNvNtCsjNKEhcqdpKw_11brynja_core13secret_memory22apply_secret_byte_mask'
BYTES = '_RNvNtCsjNKEhcqdpKw_11brynja_core22secret_memory_transfer10copy_bytes'
TARGETS = {**ops.TARGETS,'memset':30064,FINAL32:6368,FINAL64:7584,WRITE:9408,MASK:6144,BYTES:6032}


def body_check(name,code,refs):
    size,ch,rh = shapes.PINS[name]
    require(len(code) == size and digest(code) == ch,'complete state body')
    require(digest(shared.encoded(refs)) == rh,'complete state references')


def ir_preconditions(raw):
    require(digest(raw) == ops.lifecycle.IR_HASH,'saved state compiler IR')
    checks = {NEW:('define internal fastcc void ','range(i16 0, 7)','range(i16 0, 512)'),
              FINISH:('define internal fastcc ','range(i64 0, 65)','dereferenceable(1174)')}
    for name,tokens in checks.items():
        lines = [s for s in raw.decode().splitlines() if s.startswith('define ') and '@'+name+'(' in s]
        require(len(lines) == 1 and all(t in lines[0] for t in tokens),'internal state parameter preconditions')
    return dict(sha256=digest(raw),constructor_tag_range=[0,7],constructor_t_range=[0,512],
                finish_output_length_range=[0,65],ranges_half_open=True,
                output_bound_enforced_by_reviewed_callers=True,standalone_unbounded_call_claimed=False)


def table_targets(name,raw,address,start):
    expected = shapes.TABLES[name];require(len(raw) == len(expected)*4,'complete state tables')
    actual = [address+(i//28)*28+int.from_bytes(raw[i:i+4],'little',signed=True)-start for i in range(0,len(raw),4)]
    require(tuple(actual) == expected,'exact constructor and cleanup table destinations')
    return actual


def linked_table(name,rows,address,start):
    raw = bounded.mapping.mapped(rows,address,4*len(shapes.TABLES[name]));constant(rows,address,raw)
    return table_targets(name,raw,address,start)


def tables(name,data,image,record):
    rows,symbols,selected,_,refs = obj.select(data,name)
    refs = [r for r in refs if r['symbol'] == '.rdata']
    require(tuple((r['offset'],r['addend']) for r in refs) == shapes.TABLE_SITES[name] and
            all(r['trailing'] == 0 for r in refs),'all state table references')
    indices = {r['symbol_index'] for r in refs};require(len(indices) == 1,'single state table section')
    symbol = symbols[indices.pop()]
    require(symbol['value'] == 0 and 1 <= symbol['section'] <= len(rows),'defined state tables')
    table = rows[symbol['section']-1];raw = table['code'];expected = shapes.TABLES[name]
    require(len(raw) == len(expected)*4 and table['flags'] & 0xe0000000 == 0x40000000,'complete readonly state tables')
    refs = obj.relocations(data,table,symbols)
    require(set(refs) == set(range(0,len(raw),4)),'all state table relocations')
    for at,ref in refs.items():
        target = symbols[ref['symbol']]
        require(ref['kind'] == 4 and target['section'] == selected['section'] and target['value'] == 0 and
                target['name'] == '.text','table targets selected state body')
        require(int.from_bytes(raw[at:at+4],'little')-(at%28)-4 == expected[at//4],'object state table destinations')
    linked,_ = shared.caller.pe.linked(image);address = record['reference_targets']['.rdata']
    return dict(rva=address,bytes=len(raw),destinations=linked_table(name,linked,address,record['rva']))


def constant_check(name,raw):
    size,h = CONSTANTS[name]
    require(len(raw) == size and digest(raw) == h,'exact constructor constants')
    if name.startswith('__xmm@'):
        require(raw == int(name[6:],16).to_bytes(16,'little'),'IV symbol and storage agree')


def constants(data,image,record):
    rows,symbols = obj.tables(data);linked,_ = shared.caller.pe.linked(image);result = {}
    for name,(size,_) in CONSTANTS.items():
        found = [s for s in symbols.values() if s['name'] == name]
        require(len(found) == 1 and found[0]['value'] == 0 and 1 <= found[0]['section'] <= len(rows),'unique constructor constants')
        row = rows[found[0]['section']-1]
        require(row['flags'] & 0xe0000000 == 0x40000000 and row['nrelocs'] == 0,'readonly relocation-free constants')
        constant_check(name,row['code']);address = record['reference_targets'][name]
        constant(linked,address,row['code']);constant_check(name,bounded.mapping.mapped(linked,address,size))
        result[name] = dict(rva=address,bytes=size,sha256=digest(row['code']))
    return result


def reconcile(parent,records):
    for caller,callee in ((ops.BEGIN,NEW),(ops.REHASH,NEW),(ops.FINISH,FINISH),(ops.REHASH,FINISH)):
        require(parent['records'][caller]['reference_targets'][callee] == records[callee]['rva'],'actual state call chain')
    for name,record in records.items():
        require(record['image_sha256'] == parent['image_sha256'],'same scalar state image')
        frames = record['unwind'];saved = [dict(register_class='xmm',register=6,offset=1216)] if name == NEW else []
        require(len(frames) == 1 and frames[0]['stack_bytes'] == (1304 if name == NEW else 1384) and
                frames[0]['chain'] is None and frames[0]['saved_registers'] == saved,'exact state frame and XMM save')
        for symbol,address in record['reference_targets'].items():
            if symbol in CONSTANTS or symbol == '.rdata': continue
            require(symbol in TARGETS and TARGETS[symbol] == address,'same state callee addresses')


def geometry(window):
    parent = ops.geometry(window);paths = {}
    for caller,callee in ((ops.BEGIN,NEW),(ops.REHASH,NEW),(ops.FINISH,FINISH),(ops.REHASH,FINISH)):
        caller_sp = window.high+parent['operations'][caller]['rsp_from_high']
        frame = bounded.Frame.enter(window,caller_sp,1304 if callee == NEW else 1384)
        spans = ((48,112),(192,1024),(1216,16)) if callee == NEW else ((56,24),(80,64),(148,1172))
        paths[caller+' -> '+callee] = dict(rsp_from_high=frame.current-window.high,
              spans=[frame.slot('state local storage',at,n) for at,n in spans],
              callee_entry=frame.unknown_callee('unqualified state callee entry/home'))
    return dict(paths=paths,maximum_transitive_depth_qualified=False,outer_window_cleanup_required=True,
                constructor_saved_xmm6_inside_window=True,all_by_value_source_copies_individually_erased=False)


def inspect(data,native,image,wrapper,ir,mutate=False):
    parent = ops.inspect(data,native,image,wrapper,ir);preconditions = ir_preconditions(ir)
    records = {};jumps = {};count = 0;table_count = 0
    for name in shapes.PINS:
        code,refs = shared.caller.function(data,name);body_check(name,code,refs);shapes.instructions(name,code)
        records[name] = shared.caller.bind(data,image,name);jumps[name] = tables(name,data,image,records[name])
        if mutate:
            for i in range(len(code)):
                changed = bytearray(code);changed[i] ^= 1
                try: body_check(name,changed,refs)
                except ValueError: count += 1
                else: raise AssertionError('accepted actual state body mutation')
    reconcile(parent,records);values = constants(data,image,records[NEW]);rows,_ = shared.caller.pe.linked(image)
    if mutate:
        for name,table in jumps.items():
            at = table['rva'];idx = next(i for i,r in enumerate(rows) if r['rva'] <= at < r['rva']+r['virtual_size'])
            row = rows[idx]
            for i in range(table['bytes']):
                altered = bytearray(row['code']);altered[at-row['rva']+i] ^= 1
                mutated = rows[:idx]+[row | {'code':bytes(altered)}]+rows[idx+1:]
                try: linked_table(name,mutated,at,records[name]['rva'])
                except ValueError: table_count += 1
                else: raise AssertionError('accepted actual state table mutation')
    pending = sorted({s for rec in records.values() for s in rec['reference_targets']
                      if s not in {*CONSTANTS,'.rdata',ops.lifecycle.wiping.WIPE,bounded.CLEAR}})
    return dict(schema=1,date='2026-10-05',status='SAVED_SCALAR_SHA2_STATE_CALLER_REVIEW',
                image_sha256=digest(image),object_sha256=digest(data),preconditions=preconditions,
                records={n:{k:v for k,v in r.items() if k in ('rva','size','reference_targets','unwind')} for n,r in records.items()},
                tables=jumps,constants=values,geometry=geometry(bounded.Window(0,65536)),
                unqualified_transitive_callees=pending,actual_body_byte_mutations_rejected=count,
                actual_table_byte_mutations_rejected=table_count,whole_image_qualified=False,native_run_added=False,
                independently_verified=False,release_gate_changed=False,arbitrary_exception_cleanup_qualified=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('saved_directory',type=Path);p.add_argument('object',type=Path)
    p.add_argument('--catalog',type=Path,default=shared.CATALOG)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path)
    args = p.parse_args();base = args.saved_directory
    row = shared.catalog(args.catalog.read_bytes())[1];require(row['route'] == 'sha2/mod.rs::open','scalar state route')
    native,image = (base/row['object']).read_bytes(),(base/row['image']).read_bytes()
    require(digest(native) == row['object_sha256'] and digest(image) == row['sha256'],'saved C/image identity')
    require(digest((base/'sha2-scalar-cleanup-image/normal_rust.lib').read_bytes()) == entry.ARCHIVE,'saved Rust archive')
    result = inspect(args.object.read_bytes(),native,image,
                     (base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes(),
                     (base/'sha2-scalar-cleanup-image/normal_rust.ll').read_bytes(),args.mutate)
    sources = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    sources.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha2-state-review.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(sources)}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
