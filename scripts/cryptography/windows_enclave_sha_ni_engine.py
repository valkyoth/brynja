"""Saved SHA-NI engine/session normal paths; not whole-image qualification."""
import argparse
import json
from pathlib import Path
import re
import sys

import windows_enclave_sha_ni_engine_shapes as shapes

state = shapes.state
life,shared,obj = state.life,state.shared,state.obj
require,digest = state.require,state.digest
SPEC = shared.CATALOG.with_name('sha-ni-engine-20261005.json')
SPEC_HASH = '6190b085276654024af64d8e20366133404bc14d7434ac2b8d51d2ed555b0c5b'


def specification(raw):
    require(digest(raw) == SPEC_HASH,'engine review identity')
    value = json.loads(raw)
    require(value['schema'] == 1 and set(value['functions']) == set(shapes.NAMES),'complete engine population')
    return value['functions']


def body_check(name,code,refs,pins):
    pin = pins[name]
    require(len(code) == pin['bytes'] and digest(code) == pin['sha256'],'complete reviewed engine body')
    require(refs == pin['references'],'complete engine relocation population')


def instructions(name,code):
    for h in shapes.SEQUENCES[name]:
        require(code.count(bytes.fromhex(h)) == 1,'unique inspected engine instruction sequence')


def compiler(assembly,ir):
    require(digest(assembly) == shapes.ASM_HASH and digest(ir) == state.receiver.IR_HASH,'saved emitted compiler artifacts')
    text = assembly.decode();start = text.index(shapes.KERNEL+':')
    body = text[start:text.index('.seh_endproc',start)]
    require(body.count('# BRYNJA_SECRET_BEGIN') == body.count('# BRYNJA_SECRET_END') == 1,'one opaque kernel')
    opaque = body.split('# BRYNJA_SECRET_BEGIN')[1].split('# BRYNJA_SECRET_END')[0]
    require(not re.search(r'%(?:rsp|esp|rbp|ebp)\b|\b(?:push|pop|call)[ql]?\b',opaque),'no stack traffic inside selected opaque kernel')
    require(opaque.count('# BRYNJA_REGISTER_ERASE') == 1,'one register-erasure boundary')
    for name,tokens in {
        shapes.FINISH:('dereferenceable(1984)','range(i64 28, 33)'),
        shapes.UPDATE:('dereferenceable(1984)','range(i64 0, -9223372036854775808)'),
        shapes.PADDING:('dereferenceable(1984)','range(i64 64, 129)'),
        shapes.KAT:('dereferenceable(720)','range(i8 0, 4)'),
        shapes.SESSION:('dereferenceable(720)','dereferenceable(64)','dereferenceable(128)'),
    }.items():
        lines = [l for l in ir.decode().splitlines() if l.startswith('define ') and '@'+name+'(' in l]
        require(len(lines) == 1 and lines[0].startswith('define internal fastcc ') and
                all(t in lines[0] for t in tokens),'private engine parameter precondition')
    return dict(assembly_sha256=digest(assembly),ir_sha256=digest(ir),
                opaque_kernel_stack_traffic=False,standalone_arbitrary_input_claimed=False,
                caller_registers_or_spills_erased=False)


def dispatch_targets(raw,address,start):
    require(len(raw) == 20,'five session destinations')
    values = tuple(address+int.from_bytes(raw[i:i+4],'little',signed=True)-start for i in range(0,20,4))
    require(values == shapes.DESTINATIONS,'exact session dispatch destinations')
    return values


def dispatch(data,image,record):
    rows,symbols,selected,_,refs = obj.select(data,shapes.SESSION)
    refs = [r for r in refs if r['symbol'] == '.rdata']
    require(len(refs) == 1 and (refs[0]['offset'],refs[0]['addend'],refs[0]['trailing']) == (117,0,0),
            'exact session table operand')
    symbol = symbols[refs[0]['symbol_index']]
    require(symbol['value'] == 0 and 1 <= symbol['section'] <= len(rows),'unique session table')
    section = rows[symbol['section']-1]
    require(section['code'] == shapes.DISPATCH and section['flags'] & 0xe0000000 == 0x40000000,'readonly dispatch bytes')
    refs = obj.relocations(data,section,symbols)
    require(set(refs) == set(range(0,20,4)),'complete dispatch relocations')
    for at,ref in refs.items():
        target = symbols[ref['symbol']]
        require(ref['kind'] == 4 and target['section'] == selected['section'] and
                target['value'] == 0 and target['name'] == '.text','session-local table targets')
        require(int.from_bytes(shapes.DISPATCH[at:at+4],'little')-at-4 == shapes.DESTINATIONS[at//4],
                'object dispatch destinations')
    linked,_ = shared.caller.pe.linked(image);address = record['reference_targets']['.rdata']
    raw = life.bounded.mapping.mapped(linked,address,20)
    life.constants.constant(linked,address,raw)
    return raw,dict(rva=address,bytes=20,destinations=dispatch_targets(raw,address,record['rva']))


def constants(data,image,records):
    rows,symbols = obj.tables(data);linked,_ = shared.caller.pe.linked(image);result = {}
    names = [n for n in records[shapes.KAT]['reference_targets'] if n.startswith('__ymm@')]+[shapes.TABLE]
    require(len(names) == 7 and len(set(names)) == 7,'six KAT constants and one round table')
    for name in names:
        found = [s for s in symbols.values() if s['name'] == name]
        require(len(found) == 1 and found[0]['value'] == 0 and 1 <= found[0]['section'] <= len(rows),'unique constant')
        row = rows[found[0]['section']-1];raw = row['code']
        require(row['flags'] & 0xe0000000 == 0x40000000 and row['nrelocs'] == 0,'readonly relocation-free constant')
        if name == shapes.TABLE:
            require(len(raw) == 256 and digest(raw) == shapes.TABLE_HASH,'SHA-256 round constants')
            record = records[shapes.KERNEL]
        else:
            require(raw == int(name[6:],16).to_bytes(32,'little'),'exact KAT constant')
            record = records[shapes.KAT]
        result[name] = life.constants.constant(linked,record['reference_targets'][name],raw)
    return result


def reconcile(records,anchors,targets,image_hash,pins):
    require(set(records) == set(shapes.NAMES) and set(anchors) == {state.NEW,state.FINISH},'engine and caller population')
    addresses = {n:r['rva'] for n,r in records.items()} | targets
    for name,r in records.items():
        require(r['image_sha256'] == image_hash,'same engine image')
        expected = {v['symbol'] for v in pins[name]['references']}
        require(set(r['reference_targets']) == expected,'no missing engine edge')
        for edge in expected:
            require(edge in addresses and r['reference_targets'][edge] == addresses[edge],'exact engine reference target')
        if name in shapes.FRAMES:
            f = r['unwind'];saved = [dict(register_class='xmm',register=6,offset=48)] if name == shapes.UPDATE else []
            require(len(f) == 1 and f[0]['stack_bytes'] == shapes.FRAMES[name] and
                    f[0]['saved_registers'] == saved and f[0]['chain'] is None,'complete engine frame')
    for caller,callee in ((state.NEW,shapes.KAT),(state.FINISH,shapes.FINISH)):
        require(anchors[caller]['image_sha256'] == image_hash and
                anchors[caller]['reference_targets'].get(callee) == addresses[callee],'actual state-to-engine edge')


def geometry(window):
    paths = state.geometry(window)['paths'];spans = [];positions = {}
    new_rsp = window.high+paths[state.REHASH+' -> '+state.NEW]['rsp_from_high']
    kat = life.Frame.enter(window,new_rsp,296);session = life.Frame.enter(window,kat.current,56)
    scratch = life.Frame.enter(window,session.current,40)
    spans += [kat.slot('public KAT pointer/state/expected/block',32,264),
              window.span('kernel saved pointers and return/home',session.current-40,72),
              window.span('scratch clear leaf return/home',scratch.current-8,40)]
    positions['kat'] = kat.current-window.high
    positions['kat_kernel'] = session.current-40-window.high
    positions['kat_scratch_clear'] = scratch.current-8-window.high
    finish_rsp = window.high+paths[state.REHASH+' -> '+state.FINISH]['rsp_from_high']
    finish = life.Frame.enter(window,finish_rsp,136)
    update = life.Frame.enter(window,finish.current,136)
    session = life.Frame.enter(window,update.current,56)
    scratch = life.Frame.enter(window,session.current,40)
    spans += [finish.slot('length encoding temporary',48,16),finish.slot('output width',64,8),
              update.slot('total-length high word',40,8),update.slot('saved caller XMM6',48,16),
              window.span('update kernel saved pointers and return/home',session.current-40,72),
              window.span('update scratch clear leaf return/home',scratch.current-8,40)]
    positions['finish_update_scratch_clear'] = scratch.current-8-window.high
    return dict(rsp_from_high=positions,spans=spans,individual_length_spills_erased=False,
                caller_saved_xmm6_erased=False,outer_window_cleanup_required=True,
                maximum_transitive_depth_qualified=False)


def inspect(base,mutate=False):
    parent = state.inspect(base)
    row = shared.catalog(shared.CATALOG.read_bytes())[2]
    profile = life.workers.specification(life.workers.SPEC.read_bytes())['profiles'][1]
    directory = base/'sha2-stream-cleanup'
    data = life.workers.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']]
    image = (base/row['image']).read_bytes();pins = specification(SPEC.read_bytes())
    require(digest(data) == parent['object_sha256'] and digest(image) == parent['image_sha256'],'same state/engine inputs')
    compiled = compiler((directory/'normal_rust.s').read_bytes(),(directory/'normal_rust.ll').read_bytes())
    records = {};mutants = 0
    for name in shapes.NAMES:
        code,refs = shared.caller.function(data,name);body_check(name,code,refs,pins);instructions(name,code)
        if name in shapes.FRAMES: records[name] = shared.caller.bind(data,image,name)
        else: records[name] = life.bounded.leaf.bind(data,image,name,list(records.values()))
        if mutate:
            for at in range(len(code)):
                bad = bytearray(code);bad[at] ^= 1
                try: body_check(name,bad,refs,pins)
                except ValueError: mutants += 1
                else: raise AssertionError('accepted engine body byte mutant')
    raw,table = dispatch(data,image,records[shapes.SESSION]);values = constants(data,image,records)
    targets = {n:v['rva'] for n,v in values.items()} | {'.rdata':table['rva']}
    for name in (state.COPY,life.wiping.WIPE,life.SCRATCH):
        targets[name] = shared.caller.bind(data,image,name)['rva']
    # The enclosing state review already reproduces the reviewed wipe/copy/runtime
    # bindings. Remaining portable and panic edges are recorded, not qualified.
    external = {}
    for n,r in records.items():
        for edge,address in r['reference_targets'].items():
            if edge not in records and edge not in targets:
                if edge in external: require(external[edge] == address,'consistent external edge')
                external[edge] = address
    memory = life.memory.inspect(data,image,47)['runtime_targets']
    require(external['memcpy'] == memory['memcpy'],'same reviewed copy runtime')
    targets[life.bounded.CLEAR] = life.bounded.leaf.bind(data,image,life.bounded.CLEAR,list(records.values()))['rva']
    require(external.pop(life.bounded.CLEAR) == targets[life.bounded.CLEAR],'same bound volatile clearer')
    anchors = {n:shared.caller.bind(data,image,n) for n in (state.NEW,state.FINISH)}
    reconcile(records,anchors,targets | external,digest(image),pins)
    table_mutants = 0
    if mutate:
        for at in range(len(raw)):
            bad = bytearray(raw);bad[at] ^= 1
            try: dispatch_targets(bad,table['rva'],records[shapes.SESSION]['rva'])
            except ValueError: table_mutants += 1
            else: raise AssertionError('accepted session table mutant')
    return dict(schema=1,status='SAVED_SHA_NI_ENGINE_SESSION_REVIEW',image_sha256=digest(image),object_sha256=digest(data),
                records=records,constants=values,dispatch=table,compiler=compiled,geometry=geometry(life.Window(0,65536)),
                actual_body_byte_mutations_rejected=mutants,actual_table_byte_mutations_rejected=table_mutants,
                additional_reference_targets=external,portable_and_panic_callees_qualified=False,
                complete_owner_operation_semantics_qualified=False,whole_image_qualified=False,
                independently_verified=False,native_run_added=False,release_gate_changed=False)


def report(base,mutate=False):
    result = inspect(base,mutate)
    paths = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha-ni-engine.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(paths)}
    result['spec_sha256'] = digest(SPEC.read_bytes())
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path);a = p.parse_args()
    text = json.dumps(report(a.saved_directory,a.mutate),indent=2)+'\n'
    if a.output: a.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
