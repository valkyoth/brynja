"""Frozen three-route ParallelHash inventory; not semantic qualification.

Bind actual COFF extents and PE destinations before permitting helper reuse.
The saved concurrent assembly has a known funclet-name discrepancy; its object
is authoritative. No assembly-derived concurrent cleanup claim is made here.
"""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_kmac_chains as common

require,digest=common.require,common.digest
SPEC=common.shared.CATALOG.with_name('parallel-populations-20261012.json')
SPEC_HASH='619f563ae84e9e41bb428dbc121211af6e8ee218b858fb83eeda5ad4e66967bb'
COUNTS={'scalar':61,'avx2':73,'concurrent':64}
FUNCLETS={'scalar':0,'avx2':13,'concurrent':4}


def specification(raw):
    require(digest(raw)==SPEC_HASH,'frozen ParallelHash population manifest')
    result=json.loads(raw)
    require(set(result)==set(COUNTS),'all three distinct ParallelHash routes')
    for lane,pin in result.items():
        require(len(pin['functions'])==COUNTS[lane] and
            sum(n.startswith('?dtor$') for n in pin['functions'])==FUNCLETS[lane],
            'complete function and cleanup population: '+lane)
    return result


def source_binding(root,build,pin):
    manifest=json.loads(build)
    require(manifest['target']=='x86_64-pc-windows-msvc','saved Windows target')
    sources={n.replace('\\','/'):h for n,h in manifest['source_sha256'].items()}
    require(len(sources)==pin['source_count'],'complete source population')
    for name,sha in sources.items():
        path=Path(name)
        require(not path.anchor and ':' not in name and '..' not in path.parts,'relative source path')
        require(digest((root/path).read_bytes())==sha,'unchanged source '+name)
    return sources


def load(base,root,pin):
    directory=base/pin['directory']
    members=common.w.archive.members((directory/'normal_rust.lib').read_bytes())
    # The exact Rust member is an explicit boundary. Compiler-builtins and C/SDK
    # objects are not silently promoted into this Rust-family population.
    require(pin['member'] in members,'exact Rust archive member')
    inputs={'object':members[pin['member']], 'image':(base/pin['image']).read_bytes(),
        'assembly':(directory/'normal_rust.s').read_bytes(),
        'ir':(directory/'normal_rust.ll').read_bytes(),
        'build':(directory/pin['build']).read_bytes()}
    for key,raw in inputs.items():require(digest(raw)==pin[key+'_sha256'],'saved '+key+' identity')
    sources=source_binding(root,inputs['build'],pin)
    return inputs,sources


def functions_check(functions,pin):
    require(set(functions)==set(pin['functions']),'no omitted or added emitted function')
    for name,value in functions.items():common.body_check(value,pin['functions'][name])


def reachability(records,roots):
    require(set(roots)<=set(records),'actual family entry points')
    reached=set()
    def visit(name):
        if name in reached:return
        reached.add(name)
        row=records[name]
        for target in row['reference_targets']:
            if target in records:visit(target)
        for item in row.get('metadata',[]):
            if item['symbol'] in records:visit(item['symbol'])
    for name in roots:visit(name)
    require(reached==set(records),'no orphan body or cleanup funclet')
    return sorted(reached)


def inspect_route(base,root,lane,pin,mutate=False):
    inputs,sources=load(base,root,pin)
    data,image=inputs['object'],inputs['image']
    functions=common.previous.inventory(data);functions_check(functions,pin)
    records=common.previous.bind_all(data,image,functions)
    reachable=reachability(records,pin['roots'])
    # Validate and retain every external relocation: constants, mutable identity,
    # transport and runtime are separate obligations, not presumed safe callees.
    external={}
    for name,row in records.items():
        for target,address in row['reference_targets'].items():
            if target in records:continue
            external.setdefault(target,[]).append(dict(caller=name,rva=address))
    count=0
    if mutate:
        for name,(code,refs,kind) in functions.items():
            for at in range(len(code)):
                changed=bytearray(code);changed[at]^=1
                try:common.body_check((changed,refs,kind),pin['functions'][name])
                except ValueError:count+=1
                else:raise AssertionError('accepted full-body byte mutation')
    return dict(route=pin['route'],object_sha256=digest(data),image_sha256=digest(image),
        source_sha256=sources,roots=pin['roots'],reachable=reachable,
        function_count=len(records),cleanup_funclets=FUNCLETS[lane],
        records=records,external_references=external,
        body_byte_mutations_rejected=count,complete_family_review=False,
        concurrent_assembly_used_for_semantics=False,
        concurrent_funclet_listing_discrepancy=(dict(listing='dtor$54',object='dtor$55',
            function='Waves::finish',authoritative='bound COFF body and xdata') if lane=='concurrent' else None))


def inspect(base,root,mutate=False):
    spec=specification(SPEC.read_bytes())
    routes={lane:inspect_route(base,root,lane,pin,mutate) for lane,pin in spec.items()}
    return dict(schema=1,status='AUTHOR_PARALLELHASH_BOUND_POPULATIONS',completion_package=7,
        pass_number=1,completion_package_closed=False,routes=routes,
        whole_image_qualified=False,independently_verified=False,new_native_run=False,
        release_gate_changed=False,
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')} | {Path(__file__)})})


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path)
    args=p.parse_args();result=inspect(args.saved_directory,args.source_root,args.mutate)
    text=json.dumps(result,indent=2)+'\n'
    if args.output:args.output.write_text(text,encoding='utf-8')
    else:print(text,end='')
