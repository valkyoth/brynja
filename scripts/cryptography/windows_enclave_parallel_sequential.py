"""Reconcile both saved sequential Rust families, conditional on package 08.

Actual COFF/PE bodies, resolved LLVM ABIs and freshly replayed predecessor
reviews are required. This is author machine-code review, not native execution,
independent verification, a generic theorem prover or a release gate.
"""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_parallel_reuse as reuse
import windows_enclave_parallel_request as request
import windows_enclave_parallel_entry as entry
import windows_enclave_parallel_scalar_state_contracts as scalar_state
import windows_enclave_parallel_scalar_owners_contracts as scalar_owners
import windows_enclave_parallel_avx2_state_contracts as avx2_state
import windows_enclave_parallel_avx2_owners_contracts as avx2_owners

inventory,c=reuse.inventory,reuse.c
require,digest=inventory.require,inventory.digest
life=request.life;framing=life.framing;leaf=framing.leaf
TABLES={'scalar':scalar_state.CONTRACTS|scalar_owners.CONTRACTS,
        'avx2':avx2_state.CONTRACTS|avx2_owners.CONTRACTS}
SELECTED=(leaf,framing,life,entry,request)
RUNTIME={'PublicParallelInput','PublicParallelOutput','PublicParallelSource',
    'PublicParallelObserve','PublicProbeAbort','__chkstk','__udivti3','__umodti3','memcpy','memset'}
HANDLERS={'begin':6,'custom':7,'update':7,'squeeze':11,'setup_state':28}
PRECONDITIONS=(
    'C/OS admits exclusive original resident page and private window, serialized without reentry',
    'complete AVX2 deployment bundle and original authority remain valid before each Rust entry',
    'fixed transport copies, runtime memory/division/stack-probe and Windows ABI contracts',
    'whole private-window retirement covers moved copies, frame padding and compiler spills',
    'exception/abort/platform teardown outside invoked Rust funclets remains package 08',
    'application discards output on error; a failed or subsequently revoked copy is not rolled back')


def names(functions,lane):
    result={role:row['name'] for role,row in TABLES[lane].items()}
    require(len(result)==(19 if lane=='scalar' else 24) and
        len(set(result.values()))==len(result) and set(result.values())<=set(functions),
        'exact remaining sequential population')
    return result


def instructions(bodies,lane):
    require(set(bodies)==set(TABLES[lane]),'no omitted remaining body or funclet')
    for role,row in TABLES[lane].items():
        code=bodies[role]
        require(code==bytes.fromhex(row['code']),'complete actual sequential body: '+role)
        leaf.finish.windows(code,[],row['branches'])
    return sum(map(len,bodies.values()))


def assignments(functions,lane,exact):
    """Assign every body once; overlapping selected reviews remain corroboration."""
    require(set(exact)<=set(functions),'all reused helpers present')
    result={name:'exact KMAC body/references/ABI/constants' for name in exact}
    corroboration={}
    for module in SELECTED:
        for role,name in module.names(functions,lane).items():
            label=module.__name__+':'+role
            if name in result:corroboration.setdefault(name,[]).append(label)
            else:result[name]=label
    n=names(functions,lane)
    require(not set(n.values())&set(result),'remaining and preceding assignments do not overlap')
    result.update({name:'sequential state/caller: '+role for role,name in n.items()})
    require(set(result)==set(functions) and len(result)==inventory.COUNTS[lane],
        'no unassigned sequential body, not just a count match')
    return result,corroboration


def narrowed_abi(current,previous,role):
    changes={'state_update':('range(i64 0, -9223372036854775808)',
            'range(i64 0, 2305843009213693952)'),
        'xor_wrapper':('range(i8 0, 9) %4','range(i8 0, 8) %4'),
        'xor_bits':('range(i32 0, 9) %3','range(i32 0, 8) %3')}
    require(role in changes,'only three explicitly reviewed narrowings')
    before,after=changes[role]
    require(previous.count(before)==1 and current==previous.replace(before,after),
        'exact single narrowing; preserve all pointer, target and unwind attributes')


def abi_reuse(functions,ir,prior,old_ir,lane,n):
    if lane=='scalar':return {}
    result={}
    for role in ('state_update','xor_wrapper','xor_bits','cshake_drop'):
        name=n[role]
        old=(c.shapes.one(prior,r'drop_glue.*sha3_accelerated_state5StateE')
            if role=='cshake_drop' else name)
        require(functions[name]==prior[old],'complete same helper body/ref/extent: '+role)
        actual=c.reuse.abi(ir,name);previous=c.reuse.abi(old_ir,old)
        if role=='cshake_drop':
            require(actual==previous.replace('@'+old+'(','@'+name+'('),
                'renamed destructor has same resolved ABI')
        else:narrowed_abi(actual,previous,role)
        result[role]=dict(prior_name=old,abi_sha256=digest(actual.encode()),
            comparison='exact rename' if role=='cshake_drop' else 'explicit narrowing')
    return result


def constants_check(inputs,records,functions,lane,n):
    runtime=RUNTIME|({'memcmp'} if lane=='avx2' else set())
    constants,tables,external=c.data_bindings(inputs['object'],inputs['image'],records,functions,runtime)
    require(set(external)==runtime,'no silently accepted external call')
    prefix='anon.'+('e6d9992799cc35347964fcf2b37d7de4' if lane=='scalar'
        else '8150f061f3aeb3ba0974a94dde79d0f7')
    expected={prefix+'.0':b'ParallelHash',prefix+'.1':b'\x01\x02',prefix+'.2':b'\0',
        prefix+'.3':bytes(range(1,7)),prefix+'.4':b'\3',prefix+'.5':b'\5\6',prefix+'.6':b'\4'}
    if lane=='scalar':
        for role,targets in {'state_drop':[0x97,0x23,0x23,0x84],
                'leaf_state':[0x42,0x331,0x42,0x331],
                'setup_state':[0x90,0x391,0x90,0x391]}.items():
            require(tables[n[role]]['destinations']==targets,'strength/live-tag table '+role)
        require(set(tables)=={n[r] for r in ('state_drop','leaf_state','setup_state')}|
            {request.names(functions,lane)['receive']},'all scalar dispatch tables explained')
    else:
        for role in ('initial','setup_state'):
            expected['switch.table.'+n[role]]=b''.join(v.to_bytes(8,'little') for v in (168,136,168,136))
        expected['anon.3a19b6b51e69661c8cb0ff666193b4ce.0']=bytes(168)
        expected['anon.3a19b6b51e69661c8cb0ff666193b4ce.1']=b'\x80'
        rn=request.names(functions,lane)
        require(set(tables)=={rn['receive'],rn['decode']},'all AVX2 dispatch tables explained')
        # Compare every vector of the public startup KAT with the separately
        # stored 25-lane KAT used by the replayed authority test; include lane25.
        kat=constants['anon.886b1edfcdffe7c13102d1d0ad2ffa3f.0']
        answer=c.previous.readonly(inputs['image'],kat['rva'],200)
        refs=records[n['initial']]['reference_targets']
        actual=[c.previous.readonly(inputs['image'],rva,32)
            for symbol,rva in refs.items() if symbol.startswith('__ymm@')]
        require(sorted(actual)==sorted(answer[i:i+32] for i in range(0,192,32)) and
            functions[n['initial']][0][0x219:0x221]==answer[192:],
            'six distinct KAT vectors and final scalar lane')
    for symbol,value in expected.items():
        require(symbol in constants and constants[symbol]['bytes']==len(value) and
            c.previous.readonly(inputs['image'],constants[symbol]['rva'],len(value))==value,
            'exact linked framing/phase/rate constant: '+symbol)
    return dict(constants=constants,tables=tables,runtime_boundaries=external)


def handlers_check(records,n,lane):
    if lane=='scalar':return {}
    result={}
    for parent,index in HANDLERS.items():
        role='setup_handler' if parent=='setup_state' else parent+'_handler'
        name=n[role]
        require(name=='?dtor$'+str(index)+'@?0?'+n[parent]+'@4HA',
            'actual funclet name, not separately emitted listing alias')
        require(any(m['symbol']==name and m['target_rva']==records[name]['rva']
            for m in records[n[parent]].get('metadata',[])),'parent xdata invokes exact bound handler')
        result[parent]=dict(handler=name,rva=records[name]['rva'])
    return result


def inspect_route(base,root,lane,pin,mutate=False):
    import windows_enclave_parallel_sequential_models as models
    inputs,sources=inventory.load(base,root,pin)
    functions=c.previous.inventory(inputs['object']);inventory.functions_check(functions,pin)
    records=c.previous.bind_all(inputs['object'],inputs['image'],functions)
    prior,old_ir,old_image,old_object=reuse.prior_inputs(base,root,lane)
    parts=reuse.partition(functions,prior,inputs['ir'].decode(),old_ir)
    exact=parts['exact_body_reference_extent_and_abi']
    require(len(exact)==reuse.EXACT[lane],'unchanged exact reuse population')
    constants=reuse.constant_contract(inputs['object'],inputs['image'],records,functions,exact)
    old_records=c.previous.bind_all(old_object,old_image,prior)
    require(constants==reuse.constant_contract(old_object,old_image,old_records,prior,exact),
        'all exactly reused helpers retain their linked constants')
    assigned,corroborated=assignments(functions,lane,exact)
    n=names(functions,lane);bodies={r:functions[name][0] for r,name in n.items()}
    size=instructions(bodies,lane)
    abis=abi_reuse(functions,inputs['ir'].decode(),prior,old_ir,lane,n)
    data=constants_check(inputs,records,functions,lane,n)
    handlers=handlers_check(records,n,lane)
    composition=models.compose(bodies,lane)
    reachable=inventory.reachability(records,pin['roots'])
    count=0
    if mutate:
        for role,code in bodies.items():
            for at in range(len(code)):
                bad=bytearray(code);bad[at]^=1
                try:instructions(bodies|{role:bad},lane)
                except ValueError:count+=1
                else:raise AssertionError('accepted independently pinned instruction mutant')
    return dict(object_sha256=digest(inputs['object']),image_sha256=digest(inputs['image']),
        source_sha256=sources,assignments=assigned,corroborating_reviews=corroborated,
        reachable=reachable,funclets=inventory.FUNCLETS[lane],unassigned=[],
        distinct_semantics={r:row['contract'] for r,row in TABLES[lane].items()},
        distinct_body_bytes=size,distinct_instruction_mutants_rejected=count,
        changed_and_renamed_abi=abis,remaining_handlers=handlers,data_bindings=data,
        caller_lifetime_composition=composition,
        conditional_rust_family_review_complete=True,whole_image_qualified=False,
        prerequisites=list(PRECONDITIONS))


def inspect(base,root,mutate=False):
    # Re-run the checks, including the primitive proofs, rather than trusting
    # historical JSON PASS labels. Selected reports retain their original scope.
    previous=c.inspect(base,root)
    selected={m.__name__:m.inspect(base,root,mutate) for m in (leaf,framing,life,request)}
    spec=inventory.specification(inventory.SPEC.read_bytes())
    routes={lane:inspect_route(base,root,lane,spec[lane],mutate) for lane in TABLES}
    for lane,row in routes.items():
        for report in selected.values():
            require(report['routes'][lane]['image_sha256']==row['image_sha256'],
                'replayed selected review uses same signed image')
    return dict(schema=1,status='AUTHOR_CONDITIONAL_PARALLELHASH_SEQUENTIAL_ROUTES',
        completion_package=7,pass_number=2,pass_complete=True,completion_package_closed=False,
        whole_image_qualified=False,independently_verified=False,new_native_run=False,
        release_gate_changed=False,shared_runtime_window_package=8,routes=routes,
        primitive_review_replayed=previous['status'],
        selected_reviews_replayed={n:r['status'] for n,r in selected.items()},
        remaining=['concurrent route reconciliation (Pass B)','combined package-07 reconciliation (Pass C)',
            'pre-existing whole-image/runtime/window obligations in package 08'],
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}|{Path(__file__)})})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('saved_directory',type=Path)
    parser.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    parser.add_argument('--mutate',action='store_true');args=parser.parse_args()
    print(json.dumps(inspect(args.saved_directory,args.source_root,args.mutate),indent=2))
