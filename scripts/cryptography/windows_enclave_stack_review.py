"""Saved-image normal stack geometry; external/exception boundaries stay open.

All original functions are byte-bound before analysis. This composes normal
Rust workers and the explicitly reviewed runtime helpers, not loaded SDK code,
C transport wrappers, arbitrary cleanup funclets, or final window retirement.
"""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_stack_flow as flow
import windows_enclave_stack_compose as composition
import windows_enclave_stack_callbacks as callbacks
import windows_enclave_runtime_frames as frames

decode=flow.decode
workers=decode.workers
require,digest=workers.require,workers.digest


def runtimes(image,functions,records):
    arithmetic=frames.arithmetic.inspect(image,functions,records)
    memory=workers.catalog.inspect(image)['runtime']
    result={name:dict(rva=row['rva'],bytes=row['fixed_stack_bytes']) for name,row in arithmetic.items()}
    for name,role,rep in (('memcpy','copy','copy_rep'),('memset','fill','fill_rep')):
        result[name]=dict(rva=memory['frames'][role]['rva'],
            bytes=memory['frames'][rep]['fixed_frame_bytes'])
    return result


def assign(functions,records,nodes,runtime,indirect):
    """Direct targets retain COFF symbol identity, including ICF aliases."""
    edges=0;indirect_sites=set()
    for name,node in list(nodes.items()):
        raw,refs,_=functions[name]
        for scan in node['scans']:
            for call in scan['calls']:
                site=call['site']
                if call['target'] is None:
                    require(indirect is not None,'indirect target provenance required')
                    call['targets']=indirect['targets'];indirect_sites.add((name,site));continue
                selected=[r for r in refs if r['offset']==site+1]
                require(len(selected)==1 and selected[0]['addend']==selected[0]['trailing']==0 and
                    raw[site:site+5] in (b'\xe8'+bytes(4),b'\xe9'+bytes(4)),
                    'every direct transfer is exact original COFF CALL/tail reference')
                target=selected[0]['symbol']
                require(records[name]['reference_targets'][target]==call['target'],
                    'actual direct destination matches bound symbol')
                if target in nodes:
                    require(records[target]['rva']==call['target'],'exact internal callee entry')
                elif target in runtime:
                    require(runtime[target]['rva']==call['target'],'exact reviewed runtime callee entry')
                else:
                    require(target not in functions,'normal path cannot enter excluded cleanup funclet')
                    target='boundary:'+target
                call['targets']=[target];edges+=1
    if indirect is not None:require(len(indirect_sites)==indirect['sites'],'all indirect sites composed')
    for name,row in runtime.items():
        require(name not in nodes,'runtime/worker identities disjoint')
        nodes[name]=dict(incoming_bytes=0 if name=='__chkstk' else 32,runtime_summary=True,
            scans=[dict(entry_residue=r,local_low=-row['bytes'],calls=[]) for r in (0,8,16,24)])
    return dict(direct_sites=edges//2,indirect_sites=len(indirect_sites))


def inspect(base,root,row,text):
    data,image=workers.load(base,row);functions,records=workers.bind(data,image)
    frame_report=frames.inspect(image,functions,records)
    instructions=decode.parse(text);runtime=runtimes(image,functions,records)
    probes={v['rva'] for n,v in runtime.items() if n=='__chkstk'}
    nodes={};leaves={};excluded=[]
    for name,(_,refs,_) in functions.items():
        if name.startswith('?'):
            excluded.append(name);continue
        code=decode.body(image,records[name],instructions)
        targets=decode.destinations(data,image,name,records[name],refs)
        scans=flow.inspect(code,records[name]['rva'],targets,probes)
        incoming=32
        if not frame_report['functions'][name]['metadata_present']:
            leaves[name]=flow.leaf_accesses(name,code,scans);incoming=leaves[name]['incoming_bytes']
        nodes[name]=dict(incoming_bytes=incoming,scans=scans)
    indirect=callbacks.inspect(base,root,row['route'],digest(image),functions,nodes)
    population=assign(functions,records,nodes,runtime,indirect)
    composed=composition.compose(nodes)
    roots=sorted(n for n in functions if not n.startswith(('_','?')))
    require(roots,'actual named worker entry population')
    return dict(route=row['route'],image_sha256=digest(image),object_sha256=digest(data),
        disassembly_sha256=digest(text.encode()),normal_functions=len(functions)-len(excluded),
        excluded_cleanup_funclets=sorted(excluded),leaf_accesses=leaves,
        callback_review=indirect,runtime_summaries=runtime,**population,
        roots={n:composed[n] for n in roots},function_geometry=nodes,composed=composed,
        complete_protected_window_bound_proven=False,exception_depth_proven=False,
        nonleaf_stack_alias_lifetimes_inferred=False)


def collect(base,root,disassembly):
    rows=[]
    for row in workers.catalog.catalog():
        text=(disassembly/(row['sha256']+'.txt')).read_text(encoding='utf-8')
        rows.append(inspect(base,root,row,text))
    return dict(schema=1,status='AUTHOR_NORMAL_STACK_GRAPH_WITH_EXPLICIT_BOUNDARIES',records=rows,
        whole_image_qualified=False,completion_package_closed=False,
        release_gate_changed=False,new_native_enclave_run=False,independently_verified=False,
        decoder='retained LLVM disassembly, rebound to actual signed PE bytes',
        prerequisites=['completed family pointer, lifetime and jump-table index contracts',
            'runtime selector and CPU/OS contract', 'OS probe limit and committed stack window'],
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')})})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('saved_directory',type=Path);parser.add_argument('disassembly_directory',type=Path)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2])
    args=parser.parse_args()
    print(json.dumps(collect(args.saved_directory,args.root,args.disassembly_directory),indent=2))
