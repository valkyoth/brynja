"""Three saved SHA-3 batch populations; partial author review, not a gate."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_sha2_batch_chains as binding
import windows_enclave_sha3_batch_plan as plan
import windows_enclave_sha3_batch_lifecycle as lifecycle
import windows_enclave_sha3_batch_copy as copies
import windows_enclave_sha3_batch_storage as storage

c=binding.c
require,digest=c.require,c.digest
SPEC=c.shared.CATALOG.with_name('sha3-batch-chains-20261008.json')
SPEC_HASH='f272ae0169c7fad30327b4a55329689462beac39a9fec40dc3ecf0819c257255'
COUNTS={'scalar':54,'avx2':54,'simd':58}
FUNCLETS={'scalar':0,'avx2':2,'simd':17}
PREFIX={'scalar':'PublicSha3Batch','avx2':'PublicSha3Batch','simd':'PublicKeccakSimd'}


def specification(raw):
    require(digest(raw)==SPEC_HASH,'frozen three-route SHA-3 batch inventory')
    value=json.loads(raw)
    require(set(value)==set(COUNTS),'three distinct SHA-3 batch routes')
    for lane,count in COUNTS.items():
        require(len(value[lane]['functions'])==count,'complete SHA-3 batch population')
    return value


def reused_helpers(base,root,lane,functions,ir,pin):
    """Replay prior semantics, then compare bytes, relocations, extent and ABI.

    This identifies exact callees only. Current batch-specific caller arguments,
    ownership and cleanup composition remain separate, unfinished work.
    """
    reviewer=c.scalar if lane=='scalar' else c.previous
    report=reviewer.inspect(base,root)
    row=next(r for r in c.shared.catalog(c.shared.CATALOG.read_bytes()) if r['route']==report['route'])
    profile=next(r for r in c.w.specification(c.w.SPEC.read_bytes())['profiles'] if r['route']==row['route'])
    directory=(base/row['object']).parent
    data=c.w.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']]
    require(digest(data)==report['object_sha256'],'replayed prior object identity')
    prior=c.previous.inventory(data)
    exact,changed=c.reuse.exact_reuse(functions,prior,ir,(directory/'normal_rust.ll').read_text())
    require(sorted(exact)==pin['exact_prior_helpers'],'exact enumerated prior helper population')
    require(sorted(changed)==pin['changed_prior_abi_pending'],'explicit changed ABI population')
    destructor=storage.rebind(lane,functions,prior,ir,(directory/'normal_rust.ll').read_text())
    return dict(prior_route=report['route'],prior_image_sha256=report['image_sha256'],
        prior_semantics_replayed=True,exact_body_reference_extent_and_abi=exact,
        changed_abi_requiring_explicit_review=changed,state_destructor_rebinding=destructor,
        batch_caller_composition_qualified=False)


def transfers(bodies,tables,vtables):
    calls={};jumps={}
    for name,body in bodies.items():
        lines=c.shapes.lines(body)
        call=[l for l in lines if l.startswith('callq *')]
        jump=[l for l in lines if l.startswith('jmpq *')]
        if call:calls[name]=call
        if jump:jumps[name]=jump
    require(set(jumps)==set(tables),'every indirect jump has a bound local dispatch table')
    require(all(len(jumps[n])==len(tables[n]['operands']) for n in jumps),
            'all actual dispatch operands accounted')
    return dict(indirect_calls_pending=calls,bound_jump_sites=sum(map(len,jumps.values())),
        readonly_callback_tables=vtables,callback_argument_provenance_qualified=False)


def inspect_route(base,root,lane,pin,mutate=False):
    row,data,image,asm,ir,sources=binding.load(base,root,pin)
    directory=(base/row['object']).parent
    require(digest((directory/'normal_rust.lib').read_bytes())==pin['archive_sha256'],
            'complete saved worker archive')
    functions=c.previous.inventory(data)
    require(set(functions)==set(pin['functions']),'complete frozen SHA-3 batch bodies')
    require(sum(n.startswith('?') for n in functions)==FUNCLETS[lane],'complete cleanup funclet population')
    for n,v in functions.items():c.body_check(v,pin['functions'][n])
    bodies=c.previous.s.bodies(asm,functions)
    records=binding.bind_all(data,image,functions)
    runtime_names={'memcpy','memset','memcmp','__chkstk','__umodti3','PublicProbeAbort'} | {
        PREFIX[lane]+suffix for suffix in ('Input','Output','Source','Observe')}
    constants,tables,runtime,vtables,locations=binding.data_bindings(
        data,image,records,functions,runtime_names,'simd' if lane=='simd' else 'scalar')
    require(not locations,'no unassigned diagnostic pointer object')
    sizes,edges,vectors,indirect,geometry=c.frames(records,bodies)
    actual_transfers=transfers(bodies,tables,vtables)
    transport=c.transport_binding(base,row,data,image,records,runtime,PREFIX[lane])
    prior=reused_helpers(base,root,lane,functions,ir,pin) if lane!='simd' else None
    admission=plan.inspect(bodies,asm,ir) if lane!='simd' else None
    transitions=lifecycle.inspect(bodies,ir,lane) if lane!='simd' else None
    copy_review=copies.inspect(bodies,ir,prior['changed_abi_requiring_explicit_review']) if lane=='avx2' else None
    placement=storage.inspect(bodies,asm,ir,lane,prior) if lane!='simd' else None
    mutations=0
    if mutate:
        for name,(code,refs,kind) in functions.items():
            for at in range(len(code)):
                bad=bytearray(code);bad[at]^=1
                try:c.body_check((bad,refs,kind),pin['functions'][name])
                except ValueError:mutations+=1
                else:raise AssertionError('accepted complete body byte mutation')
    return dict(route=row['route'],source_sha256=sources,image_sha256=digest(image),
        object_sha256=digest(data),functions={n:dict(rva=r['rva'],bytes=r['size'],
            frame_bytes=sizes[n],saved_vectors=vectors[n],inner_references=edges[n],
            references=r['reference_targets'],cleanup_metadata=r.get('metadata',[]))
            for n,r in sorted(records.items())},cleanup_funclets=FUNCLETS[lane],
        constants=constants,dispatch_tables=tables,transfers=actual_transfers,
        transport=transport,prior_helpers=prior,sequential_plan_admission=admission,
        sequential_lifecycle=transitions,
        widened_copy_helpers=copy_review,
        sequential_state_storage=placement,
        direct_graph_geometry_only=geometry,transitive_depth_qualified=False,
        runtime_boundaries_pending=runtime,body_byte_mutations_rejected=mutations,
        private_chain_complete=False,whole_image_qualified=False)


def inspect(base,root,mutate=False):
    spec=specification(SPEC.read_bytes())
    routes={lane:inspect_route(base,root,lane,pin,mutate) for lane,pin in spec.items()}
    return dict(schema=1,status='AUTHOR_PARTIAL_SHA3_BATCH_CHAIN_REVIEW',completion_package=6,
        completion_package_closed=False,routes=routes,whole_image_qualified=False,
        independently_verified=False,release_gate_changed=False,new_native_run=False,
        remaining_private_review=['batch callers and exact state/authority lifecycle composition',
            'distinct framing, finish/squeeze and retained-output paths',
            'four-lane kernel, compaction and indirect callback argument lifetimes',
            'complete private temporary, normal-return and failure cleanup assignments'],
        shared_completion_package=8,
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')} |
            {Path(__file__),Path(__file__).with_name('test-windows-enclave-sha3-batch-chains.py')})})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('saved_directory',type=Path)
    parser.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    parser.add_argument('--mutate',action='store_true');parser.add_argument('--output',type=Path)
    args=parser.parse_args();result=inspect(args.saved_directory,args.source_root,args.mutate)
    text=json.dumps(result,indent=2)+'\n'
    if args.output:args.output.write_text(text,encoding='utf-8')
    else:print(text,end='')
