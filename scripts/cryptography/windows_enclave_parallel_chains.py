"""Close package 07's conditional Rust-family review, not Windows qualification.

Re-execute the semantic reviews and compare all three actual COFF/PE populations.
There is deliberately no CLI for importing a historical PASS receipt. Package
08's existing shared contracts remain prerequisites, not newly satisfied claims.
"""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_parallel_concurrent as concurrent

sequential=concurrent.sequential
inventory,c=concurrent.inventory,concurrent.c
require,digest=inventory.require,inventory.digest
SHARED={
    'admission':'C/OS original resident pages, private windows, exclusive entry and CPU deployment',
    'runtime':'transport, memory/division helpers, stack probes, SDK and native scheduler contracts',
    'abi':'Win64 register preservation, home space and cumulative transitive private-stack bounds',
    'retirement':'whole-window retirement including moved copies, frame padding and compiler spills',
    'exceptions':'outer return, exception dispatch, fatal termination and platform teardown',
    'output':'explicit declassification; failed or subsequently revoked copies are not rolled back',
}


def canonical(value):
    return digest(json.dumps(value,sort_keys=True,separators=(',',':')).encode())


def reconcile_route(lane,row,pin,sources,records):
    """Cross-check freshly produced semantic assignments with actual linked edges."""
    expected=set(pin['functions'])
    require(set(records)==expected and set(row['assignments'])==expected and
        set(row['reachable'])==expected and len(row['reachable'])==len(expected),
        'exact assigned/reachable population, not matching counts alone')
    require(all(isinstance(v,str) and v.strip() for v in row['assignments'].values()),
        'every actual body has a named semantic assignment')
    require(row['unassigned']==[] and row['conditional_rust_family_review_complete'] is True and
        row['whole_image_qualified'] is False,'conditional family scope only')
    require(row['source_sha256']==sources and len(sources)==pin['source_count'],
        'all current build-source identities retained')
    require(all(row[k]==pin[k] for k in ('object_sha256','image_sha256')),
        'semantic review uses exact frozen object and signed image')
    conditions=concurrent.PRECONDITIONS if lane=='concurrent' else sequential.PRECONDITIONS
    require(row['prerequisites']==list(conditions),'all pre-existing shared obligations retained')
    composition=row['caller_lifetime_composition']
    if lane=='concurrent':
        require(composition['earlier_moved_values_erased_here'] is False and
            composition['exception_runtime_qualified'] is False and
            composition['full_private_window_qualification_package']==8,
            'concurrent typed cleanup does not qualify whole windows')
    else:
        require(composition['earlier_moved_copies_erased_here'] is False and
            composition['whole_window_qualification_package']==8,
            'sequential typed cleanup does not qualify earlier copies')
    handlers={}
    for name in expected:
        if not name.startswith('?dtor$'):continue
        parent=name.split('@?0?',1)[1].removesuffix('@4HA')
        require(parent in records and any(m['symbol']==name and m['target_rva']==records[name]['rva']
            for m in records[parent].get('metadata',[])),
            'every actual funclet has its original parent xdata edge')
        handlers[name]=parent
    require(len(handlers)==inventory.FUNCLETS[lane],'complete handler population')
    runtime=row['data_bindings']['runtime_boundaries']
    expected_runtime=(concurrent.RUNTIME if lane=='concurrent' else
        sequential.RUNTIME|({'memcmp'} if lane=='avx2' else set()))
    require(set(runtime)==expected_runtime,'complete named runtime handoff')
    for name,boundary in runtime.items():
        callers={n for n,r in records.items() if name in r['reference_targets']}
        require(callers and set(boundary['callers'])==callers and
            len(boundary['callers'])==len(callers) and boundary['assigned_completion_package']==8 and
            all(records[n]['reference_targets'][name]==boundary['rva'] for n in callers),
            'runtime address, all callers and package08 boundary preserved')
    require(row['distinct_instruction_mutants_rejected'] in (0,row['distinct_body_bytes']),
        'no partially completed instruction mutation campaign')
    return dict(body_count=len(expected),cleanup_funclets=len(handlers),
        object_sha256=row['object_sha256'],image_sha256=row['image_sha256'],
        build_source_count=len(sources),build_sources_sha256=canonical(sources),
        assignments_sha256=canonical(row['assignments']),semantic_report_sha256=canonical(row),
        handlers=dict(sorted(handlers.items())),runtime_boundaries=runtime,
        distinct_instruction_bytes=row['distinct_body_bytes'],
        distinct_instruction_mutants_rejected=row['distinct_instruction_mutants_rejected'],
        prerequisites=row['prerequisites'])


def reconcile(routes,spec,sources,records,shared):
    require(set(routes)==set(spec)==set(sources)==set(records)==set(inventory.COUNTS),
        'exactly all three distinct routes')
    require(shared==SHARED,'unchanged package08 prerequisite handoff')
    result={lane:reconcile_route(lane,routes[lane],spec[lane],sources[lane],records[lane])
        for lane in inventory.COUNTS}
    require(sum(r['body_count'] for r in result.values())==198 and
        sum(r['cleanup_funclets'] for r in result.values())==17,
        'all 198 route-specific bodies and 17 funclets')
    return result


def inspect(base,root,mutate=False):
    # These calls execute the prior semantic checks. No imported receipt is used.
    before=sequential.inspect(base,root,mutate)
    routes=before['routes']|{'concurrent':concurrent.inspect_route(base,root,mutate)}
    spec=inventory.specification(inventory.SPEC.read_bytes())
    sources={};records={}
    for lane,pin in spec.items():
        inputs,sources[lane]=inventory.load(base,root,pin)
        functions=c.previous.inventory(inputs['object']);inventory.functions_check(functions,pin)
        records[lane]=c.previous.bind_all(inputs['object'],inputs['image'],functions)
        require(inventory.reachability(records[lane],pin['roots'])==routes[lane]['reachable'],
            'fresh linked reachability agrees with semantic route')
    combined=reconcile(routes,spec,sources,records,SHARED)
    return dict(schema=1,status='AUTHOR_CONDITIONAL_PARALLELHASH_FAMILY_COMPLETE',
        completion_package=7,pass_number=4,pass_complete=True,completion_package_closed=True,
        closure_scope='Conditional author review of the three frozen Rust-family populations only',
        whole_image_qualified=False,independently_verified=False,new_native_run=False,
        release_gate_changed=False,shared_runtime_window_package=8,
        routes=combined,assigned_bodies=198,assigned_funclets=17,
        shared_prerequisites=SHARED,shared_prerequisites_satisfied=False,
        semantic_reviews_reexecuted=[before['status'],'concurrent.inspect_route'],
        remaining=['pre-existing shared whole-image/runtime/window obligations in package 08',
            'independent retest, native qualification and existing release workflow'],
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}|{Path(__file__)})})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('saved_directory',type=Path)
    parser.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    parser.add_argument('--mutate',action='store_true');args=parser.parse_args()
    print(json.dumps(inspect(args.saved_directory,args.source_root,args.mutate),indent=2))
