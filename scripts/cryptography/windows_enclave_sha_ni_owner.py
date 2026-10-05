"""Saved SHA-NI owner/decoder normal-return review, not OS-unwind qualification."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_sha_ni_owner_shapes as shapes

engine,state,life = shapes.engine,shapes.state,shapes.life
shared,obj = engine.shared,engine.obj
require,digest = engine.require,engine.digest
SPEC = shared.CATALOG.with_name('sha-ni-owner-20261005.json')
SPEC_HASH = '3a91fc03d5ec371abc8e9b7d2c02debeb309e06fb592b06bc87d53e996fa0853'


def specification(raw):
    require(digest(raw) == SPEC_HASH,'owner review identity')
    result = json.loads(raw)
    require(result['schema'] == 1 and set(result['functions']) == set(shapes.NAMES),'owner review population')
    return result['functions']


def body_check(name,code,refs,pins):
    refs = [{k:v for k,v in r.items() if k!='symbol_index'} for r in refs]
    p = pins[name]
    require(len(code) == p['bytes'] and digest(code) == p['sha256'],'complete owner body')
    require(digest(shared.encoded(refs)) == p['references_sha256'],'complete owner relocations')


def normalized(text):
    return '\n'.join(' '.join(l.split()) for l in text.splitlines() if l.strip() and not l.lstrip().startswith('#'))


def instructions(name,body):
    for sequence in shapes.SEQUENCES[name]:
        require(sequence.replace('|','\n') in normalized(body),'owner semantic instruction sequence')


def assembly(raw):
    require(digest(raw) == engine.shapes.ASM_HASH,'same saved assembly')
    text = raw.decode();result = {}
    for name in shapes.NAMES:
        marker = '\n'+('"'+name+'":' if name.startswith('?') else name+':')+'\n'
        require(text.count(marker) == 1,'unique owner assembler body')
        start = text.index(marker)+1
        end = text.index('.Lfunc_end18:',start) if name == shapes.PREDICATE else text.index('.seh_endproc',start)
        body = text[start:end];instructions(name,body);result[name] = digest(body.encode())
    return result


def table_targets(name,raw,address,start):
    original = bytes.fromhex(shapes.TABLES[name][0]);require(len(raw) == len(original),'complete owner table extent')
    expected = tuple(int.from_bytes(original[i:i+4],'little')-(i%28)-4 for i in range(0,len(original),4))
    actual = tuple(address+(i//28)*28+int.from_bytes(raw[i:i+4],'little',signed=True)-start for i in range(0,len(raw),4))
    require(actual == expected,'exact owner identity/width branch destinations')
    return actual


def table(data,image,name,record):
    rows,symbols,selected,_,refs = obj.select(data,name)
    refs = [r for r in refs if r['symbol']=='.rdata']
    original,operands = shapes.TABLES[name];original = bytes.fromhex(original)
    require(tuple((r['offset'],r['addend']) for r in refs) == operands and
            all(r['trailing']==0 for r in refs),'owner table operand population')
    indices = {r['symbol_index'] for r in refs};require(len(indices)==1,'one owner table section')
    symbol = symbols[indices.pop()]
    require(symbol['value']==0 and 1 <= symbol['section'] <= len(rows),'defined table section')
    section = rows[symbol['section']-1]
    require(section['code']==original and section['flags'] & 0xe0000000 == 0x40000000,'readonly reviewed owner table')
    relocs = obj.relocations(data,section,symbols)
    require(set(relocs)==set(range(0,len(original),4)),'complete owner table relocations')
    for ref in relocs.values():
        target = symbols[ref['symbol']]
        require(ref['kind']==4 and target['section']==selected['section'] and target['value']==0 and
                target['name']=='.text','table targets this owner body')
    linked,_ = shared.caller.pe.linked(image);address = record['reference_targets']['.rdata']
    raw = life.bounded.mapping.mapped(linked,address,len(original))
    life.constants.constant(linked,address,raw)
    return raw,dict(rva=address,bytes=len(raw),destinations=table_targets(name,raw,address,record['rva']))


def reconcile(records,receiver,targets,tables,pins):
    require(set(records)==set(shapes.NAMES) and set(tables)==set(shapes.TABLES),'all owner bodies and tables')
    for name,r in records.items():
        require(r['image_sha256']==receiver['image_sha256'],'same receiver/owner image')
        for edge,address in r['reference_targets'].items():
            expected = tables[name]['rva'] if edge=='.rdata' else targets.get(edge)
            require(expected is not None and address==expected,'exact owner callee/constant binding')
        require(r['size']==pins[name]['bytes'],'whole selected runtime extent')
    for name in (shapes.BEGIN,shapes.UPDATE,shapes.FINISH,shapes.REHASH,shapes.DECODE):
        require(receiver['reference_targets'].get(name)==records[name]['rva'],'receiver calls reviewed owner/decoder')
    for name,edge in ((shapes.BEGIN,state.NEW),(shapes.UPDATE,engine.shapes.UPDATE),
                      (shapes.FINISH,state.FINISH),(shapes.REHASH,state.NEW),(shapes.REHASH,state.FINISH),
                      (shapes.FINISH,shapes.PREDICATE),(shapes.FINISH_DROP,life.GUARD),(shapes.REHASH_DROP,life.GUARD)):
        require(records[name]['reference_targets'].get(edge)==targets[edge],'required owner path')


def geometry(window):
    body = life.Frame.enter(window,window.high-32,56)
    worker = life.Frame.enter(window,body.current,1208)
    receiver = life.Frame.enter(window,worker.current,168)
    frames = {n:life.Frame.enter(window,receiver.current,k) for n,k in shapes.FRAMES.items()}
    spans = []
    for name,regions in {
        shapes.BEGIN:((32,2000),(2033,1983)),shapes.UPDATE:((32,2000),),
        shapes.FINISH:((32,2000),(2040,32),(2072,16)),
        shapes.REHASH:((32,2000),(2032,2000),(4032,32),(4072,32),(4104,24)),
    }.items():
        spans += [frames[name].slot('owner copied state, staging or metadata',offset,length) for offset,length in regions]
    return dict(rsp_from_high={n:f.current-window.high for n,f in frames.items()},spans=spans,
                outer_window_cleanup_required=True,individual_copied_enums_erased=False,
                arbitrary_handler_invocation_qualified=False,maximum_whole_image_depth_qualified=False)


def inspect(base,mutate=False):
    parent = engine.inspect(base)
    row = shared.catalog(shared.CATALOG.read_bytes())[2]
    profile = life.workers.specification(life.workers.SPEC.read_bytes())['profiles'][1]
    directory = base/'sha2-stream-cleanup'
    data = life.workers.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']]
    image = (base/row['image']).read_bytes();pins = specification(SPEC.read_bytes())
    require(digest(data)==parent['object_sha256'] and digest(image)==parent['image_sha256'],'same reviewed image/object')
    asm = assembly((directory/'normal_rust.s').read_bytes())
    receiver = shared.caller.bind(data,image,life.RECEIVE)
    records = {};count = 0
    for name in shapes.NAMES:
        if name==shapes.PREDICATE:
            code,refs = shared.caller.function(data,name)
            records[name] = life.bounded.leaf.bind(data,image,name,list(records.values()))
        else:
            _,_,_,code,refs = obj.select(data,name)
            records[name] = life.memory.handlers.bind(data,image,name,[receiver])
        body_check(name,code,refs,pins)
        if mutate:
            for at in range(len(code)):
                bad = bytearray(code);bad[at] ^= 1
                try: body_check(name,bad,refs,pins)
                except ValueError: count += 1
                else: raise AssertionError('accepted owner body mutation')
    tables = {};table_count = 0
    for name in shapes.TABLES:
        raw,tables[name] = table(data,image,name,records[name])
        if mutate:
            for at in range(len(raw)):
                bad = bytearray(raw);bad[at] ^= 1
                try: table_targets(name,bad,tables[name]['rva'],records[name]['rva'])
                except ValueError: table_count += 1
                else: raise AssertionError('accepted owner table mutation')
    targets = {n:r['rva'] for n,r in parent['records'].items()} | {shapes.PREDICATE:records[shapes.PREDICATE]['rva']}
    for name in (state.NEW,state.FINISH,state.COPY,life.OPERATION,life.SCRATCH,life.wiping.WIPE,life.GUARD):
        targets[name] = shared.caller.bind(data,image,name)['rva']
    targets[life.bounded.CLEAR] = life.bounded.leaf.bind(data,image,life.bounded.CLEAR,list(records.values()))['rva']
    targets['memcpy'] = life.memory.inspect(data,image,47)['runtime_targets']['memcpy']
    constructor = shared.caller.bind(data,image,state.NEW)
    targets['__chkstk'] = constructor['reference_targets']['__chkstk']
    linked,_ = shared.caller.pe.linked(image)
    targets[life.NONE] = records[shapes.BEGIN]['reference_targets'][life.NONE]
    life.constants.constant(linked,targets[life.NONE],bytes.fromhex('02000000000000000000000000000000'))
    reconcile(records,receiver,targets,tables,pins)
    # Object/image xdata identity is bound above. OS handler semantics are not
    # inferred from the existence of compiler-generated destructor funclets.
    return dict(schema=1,status='SAVED_SHA_NI_OWNER_DECODER_REVIEW',image_sha256=digest(image),object_sha256=digest(data),
                records=records,tables=tables,assembly_bodies_sha256=asm,geometry=geometry(life.Window(0,65536)),
                actual_body_byte_mutations_rejected=count,actual_table_byte_mutations_rejected=table_count,
                normal_return_owner_paths_reviewed=True,handler_semantics_qualified=False,
                whole_image_qualified=False,independently_verified=False,native_run_added=False,release_gate_changed=False)


def report(base,mutate=False):
    result = inspect(base,mutate)
    paths = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha-ni-owner.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(paths)}
    result['spec_sha256'] = digest(SPEC.read_bytes())
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path);a = p.parse_args()
    text = json.dumps(report(a.saved_directory,a.mutate),indent=2)+'\n'
    if a.output: a.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
