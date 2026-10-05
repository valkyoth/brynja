"""Saved scalar SHA-3 owner operations, with explicit transitive-review boundaries."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_sha3_operations_shapes as s
import windows_enclave_worker_memory as memory

life,shared,obj = s.life,s.life.shared,s.life.obj
require,digest = life.require,life.digest
SPEC = shared.CATALOG.with_name('sha3-operations-20261005.json')
SPEC_HASH = '33e227de568fce9cceb798d9fab660c359e5dfd3951a7a307573ee6e9b7a7762'


def specification(raw):
    require(digest(raw)==SPEC_HASH,'saved owner operations review identity')
    value = json.loads(raw)
    require(value['schema']==1 and set(value['functions'])==set(s.ROLES),'complete owner/receiver population')
    require(set(value['tables'])=={'receive','export','update','finish'},'complete jump-table population')
    return value


def body_check(code,refs,pin):
    require(len(code)==pin['bytes'] and digest(code)==pin['sha256'],'complete scalar owner body')
    require(digest(shared.encoded(refs))==pin['references_sha256'],'complete scalar owner relocations')


def semantic_sequences(role,body):
    body = '\n'.join(' '.join(l.split()) for l in body.splitlines() if not l.lstrip().startswith('#'))
    for sequence in s.SEQUENCES[role]:
        require(sequence.replace('|','\n') in body,'owner admission/commit/cleanup sequence: '+role)
    if role not in ('receive','export'):
        require('testq %rdx, %rdx' in body and 'movq %rdx, 2160(%rsi)' in body,'owner nonzero sequence admission')
    if role!='receive':
        require('callq '+s.DROP in body and 'callq '+s.ZERO in body,'returned-error state and output cleanup')


def assembly(raw,pins):
    require(digest(raw)==life.ASM_HASH,'same saved scalar assembly')
    text = raw.decode();out = {}
    for role,pin in pins.items():
        label = '\n'+pin['name']+':\n';require(text.count(label)==1,'unique owner assembly label')
        start = text.index(label);end = text.index('.seh_endproc',start)
        body = text[start:end];semantic_sequences(role,body);out[role] = digest(body.encode())
    return out


def preconditions(raw,pins):
    require(digest(raw)==s.IR_HASH,'saved owner compiler IR identity')
    lines = raw.decode().splitlines()
    for role in ('export','finish','setup_chunk','squeeze'):
        headers = [l for l in lines if l.startswith('define ') and '@'+pins[role]['name']+'(' in l]
        require(len(headers)==1 and 'range(i8 0, 9)' in headers[0],'private final-bit precondition')
        if role=='export': require('i64 noundef range(i64 1, 0) %sequence' in headers[0],'private nonzero export sequence')
    return dict(sha256=digest(raw),last_bits_half_open_range=[0,9],export_sequence_nonzero=True,
                enforced_by_reviewed_receiver=True,standalone_unbounded_private_calls_claimed=False)


def table_destinations(raw,address,start,pin):
    source = bytes.fromhex(pin['object_hex']);sizes = pin['subtable_bytes']
    require(len(raw)==len(source)==sum(sizes) and all(n>0 and n%4==0 for n in sizes),'complete subtable extents')
    base = 0;out = []
    for size in sizes:
        for at in range(base,base+size,4):
            # COFF REL32 is relative to the relocation word; the dispatch
            # instruction adds this subtable's base, not the section's base.
            expected = base+int.from_bytes(source[at:at+4],'little')-at-4
            actual = address+base+int.from_bytes(raw[at:at+4],'little',signed=True)-start
            require(actual==expected,'exact owner/receiver dispatch destination')
            out.append(actual)
        base += size
    return out


def readonly(image,address,length):
    rows,_ = shared.caller.pe.linked(image)
    found = [r for r in rows if r['rva']<=address and address+length<=r['rva']+min(len(r['code']),r['virtual_size'])]
    require(len(found)==1 and found[0]['flags'] & 0xe0000000==0x40000000,'readonly complete linked data')
    return life.bounded.mapping.mapped(rows,address,length)


def table(data,image,record,pin):
    rows,symbols,selected,_,refs = obj.select(data,record['entry'])
    refs = [r for r in refs if r['symbol']=='.rdata']
    require([[r['offset'],r['addend']] for r in refs]==pin['operands'] and all(r['trailing']==0 for r in refs),
            'complete dispatch operand population')
    indices = {r['symbol_index'] for r in refs};require(len(indices)==1,'one combined table section')
    symbol = symbols[indices.pop()]
    require(symbol['value']==0 and 1<=symbol['section']<=len(rows),'defined table section')
    section = rows[symbol['section']-1];source = bytes.fromhex(pin['object_hex'])
    require(section['code']==source and section['flags'] & 0xe0000000==0x40000000,'reviewed readonly object table')
    relocs = obj.relocations(data,section,symbols)
    require(set(relocs)==set(range(0,len(source),4)),'complete table relocation population')
    for ref in relocs.values():
        target = symbols[ref['symbol']]
        require(ref['kind']==4 and target['section']==selected['section'] and target['value']==0 and
                target['name']=='.text','table branches into this function')
    address = record['reference_targets']['.rdata'];raw = readonly(image,address,len(source))
    return raw,dict(rva=address,bytes=len(raw),destinations=table_destinations(raw,address,record['rva'],pin))


def widths(data,image,record):
    rows,symbols = obj.tables(data);names = ['switch.table.'+record['entry']+suffix for suffix in ('','.123')]
    raw = b''.join(n.to_bytes(8,'little') for n in (28,32,48,64));out = {}
    for name in names:
        syms = [v for v in symbols.values() if v['name']==name]
        require(len(syms)==1 and syms[0]['value']==0 and 1<=syms[0]['section']<=len(rows),'named width data')
        section = rows[syms[0]['section']-1]
        require(section['code']==raw and not section['nrelocs'] and section['flags'] & 0xe0000000==0x40000000,
                'exact readonly width constants')
        address = record['reference_targets'][name]
        require(readonly(image,address,32)==raw,'actual linked retained-output widths')
        out[name] = dict(rva=address,bytes=32,values=[28,32,48,64])
    return out


def frames(records,pins):
    require(set(records)==set(pins),'all owner frames')
    for role,r in records.items():
        p = pins[role];f = r['unwind']
        require(len(f)==1 and f[0]['stack_bytes']==p['stack_bytes'] and f[0]['saved_registers']==p['saved_registers'] and
                f[0]['chain'] is None and f[0]['frame']==0,'complete fixed frame and saved-register slots')


def connections(records,pins,targets,tables,runtime):
    require(set(runtime)==s.RUNTIME_BOUNDARIES,'explicit pending runtime population')
    for role,r in records.items():
        for name,address in r['reference_targets'].items():
            expected = tables[role]['rva'] if name=='.rdata' else (targets | runtime).get(name)
            require(expected is not None and address==expected,'actual owner cleanup/transport/state callee')
    for role,pin in pins.items():
        if role!='receive': require(records['receive']['reference_targets'].get(pin['name'])==records[role]['rva'],
                                   'receiver enters every reviewed owner operation')


def geometry(window,pins):
    body = life.bounded.Frame.enter(window,window.high-32,56)
    worker = life.bounded.Frame.enter(window,body.current,1208)
    receiver = life.bounded.Frame.enter(window,worker.current,200)
    result = {}
    spans = {'begin':((32,1136),(1170,1134)),
             'setup':((368,1120),(1488,1120),(2608,1120),(3743,1107),(4850,1134),(5984,16)),
             'finish_setup':((208,1120),(1328,1136),(2476,988),(3464,988),(4452,988)),
             'rehash':((32,32),(64,1136),(1200,1024),(2224,1136)),
             'squeeze':((32,32),(64,24),(88,32),(120,32),(152,1024))}
    for role,pin in pins.items():
        if role=='receive': continue
        f = life.bounded.Frame.enter(window,receiver.current,pin['stack_bytes'])
        result[role] = dict(rsp_from_high=f.current-window.high,
                           reviewed_spans=[f.slot('copied state/staging/metadata/saved register',a,n) for a,n in spans.get(role,())],
                           unknown_callee=f.unknown_callee('callee entry/home; deeper review pending'))
    return dict(paths=result,copied_states_individually_erased=False,outer_window_clearing_required=True,
                maximum_whole_image_depth_qualified=False)


def inspect(base,mutate=False):
    parent = life.inspect(base);spec = specification(SPEC.read_bytes());pins = spec['functions']
    row = shared.catalog(shared.CATALOG.read_bytes())[3];profile = life.workers.specification(life.workers.SPEC.read_bytes())['profiles'][2]
    directory = (base/row['object']).parent
    data = life.workers.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']]
    image = (base/row['image']).read_bytes();native = (base/row['object']).read_bytes()
    require(digest(data)==parent['object_sha256'] and digest(image)==parent['image_sha256'],'same lifecycle image/object')
    asm = assembly((directory/'normal_rust.s').read_bytes(),pins)
    pre = preconditions((directory/'normal_rust.ll').read_bytes(),pins)
    records = {};count = 0
    for role,pin in pins.items():
        code,refs = shared.caller.function(data,pin['name']);body_check(code,refs,pin)
        records[role] = shared.caller.bind(data,image,pin['name'])
        if mutate:
            for at in range(len(code)):
                bad = bytearray(code);bad[at] ^= 1
                try: body_check(bad,refs,pin)
                except ValueError: count += 1
                else: raise AssertionError('accepted actual owner body mutation')
    frames(records,pins);tables = {};table_count = 0
    for role,pin in spec['tables'].items():
        raw,tables[role] = table(data,image,records[role],pin)
        if mutate:
            for at in range(len(raw)):
                bad = bytearray(raw);bad[at] ^= 1
                try: table_destinations(bad,tables[role]['rva'],records[role]['rva'],pin)
                except ValueError: table_count += 1
                else: raise AssertionError('accepted actual table mutation')
    width_data = widths(data,image,records['rehash'])
    # Reproduce existing transport and runtime identities, not merely load their reports.
    transport = life.workers.transport;tp = transport.specification(transport.SPEC.read_bytes())
    tr = transport.inspect(native,image,(base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes(),
                           (base/'sdk-system32-review/vertdll.dll').read_bytes(),tp['profiles'][2],tp['templates'])
    targets = {n:v['rva'] for n,v in parent['records'].items()}
    targets.update({p['name']:records[k]['rva'] for k,p in pins.items()})
    targets.update({tp['profiles'][2]['prefix']+k:v['rva'] for k,v in tr['records'].items()})
    targets.update(memory.inspect(data,image,55)['runtime_targets'])
    targets.update({n:v['rva'] for n,v in width_data.items()})
    callees = {};runtime = {}
    for role,r in records.items():
        for name,address in r['reference_targets'].items():
            if name=='.rdata': require(address==tables[role]['rva'],'same dispatch data');continue
            if name in s.RUNTIME_BOUNDARIES:
                require(name not in runtime or runtime[name]==address,'consistent runtime boundary')
                runtime[name] = address;continue
            if name not in targets:
                # Rate-specialized helpers may have identical code shapes.
                # Disambiguate with already reproduced incoming call operands,
                # and bind the selected helper's complete object/xdata extent.
                callee = memory.handlers.bind(data,image,name,list(records.values()))
                callees[name] = callee;targets[name] = callee['rva']
            require(address==targets[name],'actual owner cleanup/transport/state callee')
    connections(records,pins,targets,tables,runtime)
    result = dict(schema=1,status='SAVED_SCALAR_SHA3_OWNER_OPERATIONS_REVIEW',image_sha256=digest(image),object_sha256=digest(data),
                  records=records,dispatch_tables=tables,width_constants=width_data,geometry=geometry(life.bounded.Window(0,65536),pins),
                  assembly_body_sha256=asm,compiler_preconditions=pre,callee_identity_only=callees,runtime_boundaries_pending=runtime,
                  actual_body_byte_mutations_rejected=count,actual_table_byte_mutations_rejected=table_count,
                  transitive_callee_semantics_qualified=False,arbitrary_exception_cleanup_qualified=False,
                  whole_image_qualified=False,independently_verified=False,native_run_added=False,release_gate_changed=False)
    paths = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha3-operations.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(paths)}
    result['spec_sha256'] = digest(SPEC.read_bytes())
    return result


if __name__=='__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path);a = p.parse_args()
    text = json.dumps(inspect(a.saved_directory,a.mutate),indent=2)+'\n'
    if a.output: a.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
