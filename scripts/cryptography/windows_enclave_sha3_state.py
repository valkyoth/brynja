"""Bind saved scalar SHA-3 state construction/consumption, not the whole image."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_sha3_state_shapes as s

ops = s.ops
life,shared,obj = ops.life,ops.shared,ops.obj
require,digest = ops.require,ops.digest
SPEC = shared.CATALOG.with_name('sha3-state-20261005.json')
SPEC_HASH = '9ff7c28a705768d1637725dc3e677351f9cb76e38e593372ca728e29d151059f'
EDGES = (('begin','new'),('rehash','new'),('finish','finish_fixed'),('rehash','finish_fixed'),('rehash','finish_xof'))


def specification(raw):
    require(digest(raw)==SPEC_HASH,'saved state review identity')
    value = json.loads(raw)
    require(value['schema']==1 and set(value['functions'])==set(s.NAMES),'three complete state bodies')
    require(all(p['name']==s.NAMES[k] for k,p in value['functions'].items()),'exact state identities')
    require(set(value['tables'])=={'new','finish_fixed'},'complete state dispatch-table population')
    return value


def assembly(raw,pins):
    require(digest(raw)==life.ASM_HASH,'same saved scalar SHA-3 assembly')
    text = raw.decode();result = {};padding = None
    for role,pin in pins.items():
        label = '\n'+pin['name']+':\n';require(text.count(label)==1,'unique state function')
        start = text.index(label);end = text.index('.seh_endproc',start)
        body = text[start:end];s.sequences(role,body)
        if role=='finish_fixed': padding = s.permutation_cleanup(body)
        result[role] = digest(body.encode())
    return result,padding


def preconditions(raw):
    require(digest(raw)==ops.s.IR_HASH,'same saved compiler IR')
    lines = raw.decode().splitlines()
    for role,token in (('new','i8 noundef range(i8 0, 8)'),('finish_fixed','i64 noundef range(i64 28, 65)')):
        rows = [l for l in lines if l.startswith('define internal fastcc ') and '@'+s.NAMES[role]+'(' in l]
        require(len(rows)==1 and token in rows[0] and 'dereferenceable(1136)' in rows[0],
                'private enum/output-length and initialized-owner preconditions')
    return dict(constructor_algorithm_half_open_range=[0,8],fixed_output_half_open_range=[28,65],
                owner_bytes=1136,enforced_by_reviewed_owner_paths=True,arbitrary_private_abi_calls_qualified=False)


def connections(parent,records,targets,tables):
    require(set(records)==set(s.NAMES),'complete state population')
    for caller,role in EDGES:
        require(parent['records'][caller]['reference_targets'].get(s.NAMES[role])==records[role]['rva'],
                'actual owner-to-state connection')
    for role,record in records.items():
        require(record['image_sha256']==parent['image_sha256'],'same state image')
        for name,address in record['reference_targets'].items():
            expected = tables[role]['rva'] if name=='.rdata' else targets.get(name)
            require(expected is not None and address==expected,'actual state cleanup/prefix/sponge/copy destination')


def geometry(window,pins,owner_pins):
    parent = ops.geometry(window,owner_pins);result = {}
    spans = {'new':((35,1),(112,1032),(1152,258),(1424,258),(1688,1040)),
             'finish_fixed':((40,24),(64,32),(96,1040),(1136,1024),(2160,1136)),
             'finish_xof':()}
    for caller,role in EDGES:
        frame = life.bounded.Frame.enter(window,window.high+parent['paths'][caller]['rsp_from_high'],pins[role]['stack_bytes'])
        result[caller+' -> '+role] = dict(rsp_from_high=frame.current-window.high,
            reviewed_spans=[frame.slot('state/staging/metadata',a,n) for a,n in spans[role]],
            next_call=frame.unknown_callee('deeper callee review pending'))
    return dict(paths=result,all_moved_copies_individually_erased=False,outer_window_clearing_required=True,
                maximum_whole_image_depth_qualified=False)


def inspect(base,mutate=False):
    parent = ops.inspect(base);lifecycle = life.inspect(base)
    spec = specification(SPEC.read_bytes());pins = spec['functions']
    row = shared.catalog(shared.CATALOG.read_bytes())[3]
    profile = life.workers.specification(life.workers.SPEC.read_bytes())['profiles'][2]
    directory = (base/row['object']).parent
    data = life.workers.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']]
    image = (base/row['image']).read_bytes()
    require(digest(data)==parent['object_sha256'] and digest(image)==parent['image_sha256'],'same reviewed state image/object')
    asm,padding = assembly((directory/'normal_rust.s').read_bytes(),pins)
    pre = preconditions((directory/'normal_rust.ll').read_bytes());records = {};mutants = 0
    for role,pin in pins.items():
        code,refs = shared.caller.function(data,pin['name']);ops.body_check(code,refs,pin)
        records[role] = shared.caller.bind(data,image,pin['name'])
        if mutate:
            for at in range(len(code)):
                bad = bytearray(code);bad[at] ^= 1
                try: ops.body_check(bad,refs,pin)
                except ValueError: mutants += 1
                else: raise AssertionError('accepted state body-byte mutation')
    ops.frames(records,pins);tables = {};table_mutants = 0
    for role,pin in spec['tables'].items():
        raw,tables[role] = ops.table(data,image,records[role],pin)
        if mutate:
            for at in range(len(raw)):
                bad = bytearray(raw);bad[at] ^= 1
                try: ops.table_destinations(bad,tables[role]['rva'],records[role]['rva'],pin)
                except ValueError: table_mutants += 1
                else: raise AssertionError('accepted state dispatch mutation')
    targets = {n:r['rva'] for n,r in lifecycle['records'].items()}
    targets.update({n:r['rva'] for n,r in parent['callee_identity_only'].items()})
    targets.update(ops.memory.inspect(data,image,55)['runtime_targets'])
    callees = {};anchors = [*records.values(),*parent['records'].values()]
    for role,record in records.items():
        for name in record['reference_targets']:
            if name=='.rdata' or name in targets: continue
            if name in (s.BYTES,s.MASK): callee = life.bounded.leaf.bind(data,image,name,anchors)
            else: callee = ops.memory.handlers.bind(data,image,name,anchors)
            targets[name] = callee['rva'];callees[name] = callee
    connections(parent,records,targets,tables)
    owner_pins = ops.specification(ops.SPEC.read_bytes())['functions']
    result = dict(schema=1,status='SAVED_SCALAR_SHA3_STATE_REVIEW',image_sha256=digest(image),object_sha256=digest(data),
        records=records,dispatch_tables=tables,assembly_body_sha256=asm,compiler_preconditions=pre,
        padding_cleanup=padding,geometry=geometry(life.bounded.Window(0,65536),pins,owner_pins),
        additional_callee_identity_only=callees,actual_body_byte_mutations_rejected=mutants,
        actual_table_byte_mutations_rejected=table_mutants,transitive_callee_semantics_qualified=False,
        whole_image_qualified=False,arbitrary_exception_cleanup_qualified=False,independently_verified=False,
        native_run_added=False,release_gate_changed=False)
    paths = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha3-state.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(paths)}
    result['spec_sha256'] = digest(SPEC.read_bytes())
    return result


if __name__=='__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path);a = p.parse_args()
    text = json.dumps(inspect(a.saved_directory,a.mutate),indent=2)+'\n'
    if a.output: a.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
