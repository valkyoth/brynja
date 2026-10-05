"""Saved scalar SHA-2 crypto/transfer helpers; offline review, not a new gate."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_sha2_primitive_shapes as shapes

state,old = shapes.state,shapes.old
ops,shared,bounded,entry = state.ops,state.shared,state.bounded,state.entry
require,digest,obj = state.require,state.digest,state.obj
CONSTANTS = {shapes.ROUND32:(256,old.TABLE_HASH),shapes.ROUND64:state.CONSTANTS[state.ROUND]}
EXTERNAL = {bounded.CLEAR:5920,'memset':30064,shapes.PANIC:31008}
EDGES = {
    shapes.U32:{shapes.COPY,shapes.S32,bounded.CLEAR},
    shapes.U64:{shapes.COPY,shapes.S64,bounded.CLEAR},
    shapes.F32:{shapes.COPY,shapes.S32,shapes.MASK,bounded.CLEAR,'memset',shapes.PANIC},
    shapes.F64:{shapes.COPY,shapes.S64,shapes.MASK,bounded.CLEAR,'memset',shapes.PANIC},
    shapes.WRITE:{shapes.BYTES,bounded.CLEAR},shapes.COPY:{shapes.BYTES},
    shapes.S32:{shapes.ROUND32},shapes.S64:{shapes.ROUND64},
    shapes.MASK:{shapes.MASKBYTE},shapes.BYTES:set(),shapes.MASKBYTE:set(),shapes.PRED:set(),
}


def body_check(name,code,refs):
    size,ch,rh = shapes.PINS[name]
    require(len(code) == size and digest(code) == ch,'complete scalar primitive body')
    require(digest(shared.encoded(refs)) == rh,'complete scalar primitive references')


def constant_check(name,raw):
    size,h = CONSTANTS[name]
    require(len(raw) == size and digest(raw) == h,'complete scalar round table')


def constants(data,image,records):
    rows,symbols = obj.tables(data);linked,_ = shared.caller.pe.linked(image);result = {}
    for function,name in ((shapes.S32,shapes.ROUND32),(shapes.S64,shapes.ROUND64)):
        found = [s for s in symbols.values() if s['name'] == name]
        require(len(found) == 1 and found[0]['value'] == 0 and 1 <= found[0]['section'] <= len(rows),
                'unique round table at section start')
        row = rows[found[0]['section']-1];constant_check(name,row['code'])
        require(row['flags'] & 0xe0000000 == 0x40000000 and row['nrelocs'] == 0,'readonly round table')
        address = records[function]['reference_targets'][name]
        state.constant(linked,address,row['code'])
        constant_check(name,bounded.mapping.mapped(linked,address,len(row['code'])))
        result[name] = dict(rva=address,bytes=len(row['code']),sha256=digest(row['code']))
    return result


def reconcile(records,anchors,tables,image_hash):
    require(set(records) == set(shapes.PINS),'complete primitive inventory')
    require(set(anchors) == {state.NEW,state.FINISH,ops.UPDATE,ops.FINISH,ops.REHASH},'actual caller inventory')
    require(set(tables) == set(CONSTANTS),'both scalar round tables')
    targets = EXTERNAL | {n:r['rva'] for n,r in records.items()} | {n:r['rva'] for n,r in tables.items()}
    reached = set()
    for name,record in {**anchors,**records}.items():
        require(record['image_sha256'] == image_hash,'same scalar primitive image')
        if name in records:
            require(set(record['reference_targets']) == EDGES[name],'exact primitive reference closure')
        for edge,address in record['reference_targets'].items():
            if edge in targets:
                require(address == targets[edge],'actual caller/callee or constant identity')
                if edge in records: reached.add(edge)
        if name in shapes.FRAMES:
            frames = record['unwind']
            require(len(frames) == 1 and frames[0]['stack_bytes'] == shapes.FRAMES[name] and
                    frames[0]['chain'] is None and not frames[0]['saved_registers'],'exact primitive frame')
    require(reached == set(records),'every selected primitive actually reached')


def geometry(window):
    # State::finish under Owner::finish is the deepest reviewed state caller.
    # State construction also uses update/finalize for public general-t IVs.
    parent = state.geometry(window)
    callsites = [window.high+p['rsp_from_high'] for p in parent['paths'].values()]
    callsites += [window.high+p['rsp_from_high'] for p in ops.geometry(window)['operations'].values()]
    caller_sp = min(callsites)
    update = bounded.Frame.enter(window,caller_sp,120)
    final = bounded.Frame.enter(window,caller_sp,104)
    write = bounded.Frame.enter(window,caller_sp,72)
    copy = bounded.Frame.enter(window,update.current,40)
    spans = [update.slot('update saved GPRs',-64,64,'entry'),
             update.slot('saved input pointer and complete-byte length',40,16),
             final.slot('finalize saved GPRs',-64,64,'entry'),
             final.slot('caller bit-length and output-width arguments',144,16),
             write.slot('output length argument',112,8),
             window.span('scalar32 leaf saves/return/home',update.current-24,56),
             window.span('scalar64 leaf saves/return/home',update.current-40,72),
             window.span('copy leaf return/home',copy.current-8,40)]
    return dict(deepest_selected_caller_rsp_from_high=caller_sp-window.high,
                update_rsp_from_high=update.current-window.high,finalize_rsp_from_high=final.current-window.high,
                write_rsp_from_high=write.current-window.high,copy_rsp_from_high=copy.current-window.high,
                deepest_selected_leaf_rsp_from_high=copy.current-8-window.high,spans=spans,
                runtime_entry=final.unknown_callee('memset entry/home only'),
                selected_chain_only=True,maximum_transitive_depth_qualified=False,
                final_clear_and_write_error_clear_tail_reuse_entry=True,
                outer_window_cleanup_required=True,individual_caller_spills_erased=False)


def inspect(data,native,image,wrapper,ir,mutate=False):
    state.inspect(data,native,image,wrapper,ir)
    records = {};count = 0
    for name in shapes.PINS:
        code,refs = shared.caller.function(data,name);body_check(name,code,refs);shapes.instructions(name,code)
        if name in shapes.FRAMES: records[name] = shared.caller.bind(data,image,name)
        if mutate:
            for i in range(len(code)):
                changed = bytearray(code);changed[i] ^= 1
                try: body_check(name,changed,refs)
                except ValueError: count += 1
                else: raise AssertionError('accepted actual scalar primitive body mutation')
    anchors = {n:shared.caller.bind(data,image,n) for n in (state.NEW,state.FINISH,ops.UPDATE,ops.FINISH,ops.REHASH)}
    for name in (shapes.BYTES,shapes.MASK,shapes.MASKBYTE,shapes.PRED):
        records[name] = entry.leaf.bind(data,image,name,[*anchors.values(),*records.values()])
    tables = constants(data,image,records);reconcile(records,anchors,tables,digest(image))
    return dict(schema=1,date='2026-10-05',status='SAVED_SCALAR_SHA2_PRIMITIVE_REVIEW',
                image_sha256=digest(image),object_sha256=digest(data),
                records={n:{k:v for k,v in r.items() if k in ('rva','size','reference_targets','unwind')} for n,r in records.items()},
                constants=tables,geometry=geometry(bounded.Window(0,65536)),
                actual_body_byte_mutations_rejected=count,
                exact_bounded_sha256_body_and_reference_reuse=[shapes.U32,shapes.COPY,shapes.BYTES],
                scalar32_same_body_but_different_constant_reference=True,
                private_caller_preconditions_required=True,panic_branch_excluded_by_admitted_partial_bits=True,
                standalone_unbounded_call_claimed=False,padding_memset_is_not_volatile_erasure=True,
                unqualified_runtime_callees=['memset'],arbitrary_exception_cleanup_qualified=False,
                other_image_workers_qualified=False,whole_image_qualified=False,native_run_added=False,
                independently_verified=False,release_gate_changed=False)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('saved_directory',type=Path);p.add_argument('object',type=Path)
    p.add_argument('--catalog',type=Path,default=shared.CATALOG)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path)
    args = p.parse_args();base = args.saved_directory
    row = shared.catalog(args.catalog.read_bytes())[1];require(row['route'] == 'sha2/mod.rs::open','scalar primitive route')
    native,image = (base/row['object']).read_bytes(),(base/row['image']).read_bytes()
    require(digest(native) == row['object_sha256'] and digest(image) == row['sha256'],'saved C/image identity')
    require(digest((base/'sha2-scalar-cleanup-image/normal_rust.lib').read_bytes()) == entry.ARCHIVE,'saved Rust archive')
    result = inspect(args.object.read_bytes(),native,image,
                     (base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes(),
                     (base/'sha2-scalar-cleanup-image/normal_rust.ll').read_bytes(),args.mutate)
    sources = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    sources.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha2-primitives.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(sources)}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
