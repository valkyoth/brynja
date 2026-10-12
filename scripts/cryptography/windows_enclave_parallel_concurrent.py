"""Conditional saved concurrent Rust-family review, not a release gate.

Actual COFF/PE and resolved ABI comparisons are required. The separately emitted
assembly listing is deliberately not used for the dtor55 cleanup assignment.
"""
import argparse
import json
from pathlib import Path
import re
import sys

import windows_enclave_parallel_sequential as sequential
import windows_enclave_parallel_concurrent_contracts as contracts
import windows_enclave_retirement_review as retirement
import windows_enclave_terminal_review as terminal
import windows_enclave_root_setup as setup

reuse=sequential.reuse
inventory,c=reuse.inventory,reuse.c
require,digest=inventory.require,inventory.digest
TABLES=contracts.CONTRACTS
SELECTED=(reuse.root_return,setup,reuse.publication,reuse.root_return.slot,
    retirement,terminal,terminal.cleanup,setup.construction,setup.construction.engine)
RUNTIME={'PrivateInputCopy','PrivateInputOutput','PrivateSchedulerComplete',
    'PrivateSchedulerRetire','PrivateWaveAbort','PrivateWaveDispatch',
    'PrivateWaveRootRegion','__chkstk','__umodti3','memcmp','memcpy','memset'}
PREFIX='_RNvCsk1CFy3R4N16_20parallel_wave_bridge'
GLOBALS={PREFIX+n:size for n,size in {'7CLAIMED':1,'4GATE':8,'5SLOTS':32,
    '4BITS':32,'5INPUT.0':8,'5WIDTH.0':8,'5BLOCK.0':8}.items()}
GLOBAL_OPERANDS={'7CLAIMED':('PrivateWaveRoot',46),'4GATE':('PrivateWaveLeaf',57),
    '5SLOTS':('PrivateWaveLeaf',154),'4BITS':('PrivateWaveLeaf',197),
    '5BLOCK.0':('PrivateWaveLeaf',208),'5WIDTH.0':('PrivateWaveLeaf',215),
    '5INPUT.0':('PrivateWaveLeaf',222)}
PRECONDITIONS=(
    'original distinct root/worker windows and CPU deployment admitted before entry by C/OS',
    'transport, native scheduler and OS/runtime calls honor their independently reviewed contracts',
    'root remains live until every Rust ticket and native worker is quiescent; no fatal-return fiction',
    'whole-window retirement covers moved values, compiler spills, scratch and stale stack copies',
    'exception dispatch, fatal termination and cumulative transitive frame bounds remain package 08',
    'public output is explicit declassification; failed OS copy may expose a prefix and is not transactional')


def names(functions):
    result={role:row['name'] for role,row in TABLES.items()}
    require(len(result)==15 and len(set(result.values()))==15 and
        set(result.values())<=set(functions),'exact remaining concurrent bodies')
    return result


def instructions(bodies):
    require(set(bodies)==set(TABLES),'complete concurrent instruction population')
    for role,row in TABLES.items():
        require(bodies[role]==bytes.fromhex(row['code']),'actual concurrent body: '+role)
        sequential.leaf.finish.windows(bodies[role],[],row['branches'])
    return sum(map(len,bodies.values()))


def assignments(functions,exact):
    require(len(exact)==23 and set(exact)<=set(functions),'exact sequential helper population')
    assigned={name:'exact sequential AVX2 body/reference/ABI/constants' for name in exact}
    corroborated={}
    for module in SELECTED:
        for role,row in module.BODIES.items():
            name=row[0]
            if name not in functions:continue  # Native C entries are package08, not Rust bodies.
            label=module.__name__+':'+role
            if name in assigned:corroborated.setdefault(name,[]).append(label)
            else:assigned[name]=label
    n=names(functions)
    require(not set(n.values())&set(assigned),'new contracts do not hide multiply assigned bodies')
    assigned.update({name:'concurrent caller/helper: '+role for role,name in n.items()})
    require(set(assigned)==set(functions) and len(assigned)==64,'no missing or orphan concurrent body')
    return assigned,corroborated


def changed_abi(current,previous,name):
    """Only the six observed differences, never strip target/pointer attributes."""
    if 'panicking' in name:
        require(re.search(r' !dbg !\d+ \{$',current) is not None and
            re.search(r' !dbg !\d+ \{$',previous) is not None,'both panic debug identities present')
        require(re.sub(r' !dbg !\d+ \{$',' {',current)==re.sub(r' !dbg !\d+ \{$',' {',previous),
            'only panic debug node renumbered')
        return 'debug metadata only; nonreturning abort contract retained'
    before,after,count=(
        ('range(i64 0, 1025)','range(i64 0, 2305843009213693952)',2)
        if '18copy_secret_region' in name else
        ('range(i64 0, 1025)','range(i64 0, 2305843009213693952)',1)
        if '10copy_bytes' in name else
        ('range(i64 1, 1025)','range(i64 1, 4097)',1)
        if '23zeroize_region_volatile' in name else
        ('range(i64 0, 2305843009213693952)','range(i64 0, 256)',1)
        if '5State6update' in name else ('','',0))
    require(count and previous.count(before)==count and current==previous.replace(before,after),
        'exact reviewed ABI range difference')
    return 'explicit bounded caller composition, not equality of ABI domains'


def abi_reuse(functions,ir,prior,old_ir,changed):
    require(len(changed)==6,'six same-body ABI differences')
    result={}
    for name in changed:
        require(functions[name]==prior[name],'same actual body/references/extent before ABI comparison')
        now=c.reuse.abi(ir,name);before=c.reuse.abi(old_ir,name)
        result[name]=dict(comparison=changed_abi(now,before,name),current_abi=now,prior_abi=before)
    return result


def globals_check(image,records):
    rows,_=c.shared.caller.pe.linked(image);spans=[]
    found={s for r in records.values() for s in r['reference_targets'] if s.startswith(PREFIX)}
    require(found==set(GLOBALS),'all concurrent mutable identities explicitly assigned')
    for name,size in GLOBALS.items():
        targets={r['reference_targets'][name] for r in records.values() if name in r['reference_targets']}
        require(len(targets)==1,'same original publication allocation in every caller')
        address=targets.pop()
        caller,offset=GLOBAL_OPERANDS[name.removeprefix(PREFIX)]
        field=records[caller]['rva']+offset
        encoded=reuse.root_return.slot.binding.mapped(rows,field,4)
        require(field+4+int.from_bytes(encoded,'little',signed=True)==address,
            'global origin derived from actual linked instruction, not a report address')
        matches=[r for r in rows if r['flags']&0xe0000000==0xc0000000 and
            r['rva']<=address and address+size<=r['rva']+r['virtual_size']]
        require(len(matches)==1 and (size==1 or address%8==0),'whole aligned writable non-executable global')
        row=matches[0];offset=address-row['rva']
        require(row['code'][offset:offset+size].ljust(size,b'\0')==bytes(size),
            'zero initial claim/gate/pointer metadata; virtual tail is loader-zeroed')
        spans.append(dict(symbol=name,rva=address,bytes=size))
    ordered=sorted(spans,key=lambda v:v['rva'])
    require(all(a['rva']+a['bytes']<=b['rva'] for a,b in zip(ordered,ordered[1:])),
        'no overlapping claimed/gate/publication storage')
    return spans


def data_check(inputs,records,functions):
    spans=globals_check(inputs['image'],records)
    # Globals were exhaustively bound above, never disguise them as runtime calls.
    filtered={n:r|{'reference_targets':{s:a for s,a in r['reference_targets'].items()
        if s not in GLOBALS}} for n,r in records.items()}
    constants,tables,runtime=c.data_bindings(inputs['object'],inputs['image'],filtered,functions,RUNTIME)
    require(set(runtime)==RUNTIME and not tables,'exact external boundary set; no indirect dispatch table')
    expected={'anon.5f2396cd0f73852b79ba16fa154e009e.0':b'ParallelHash',
        'anon.3a19b6b51e69661c8cb0ff666193b4ce.0':bytes(168),
        'anon.3a19b6b51e69661c8cb0ff666193b4ce.1':b'\x80'}
    for name in functions:
        if name.endswith(('5State7initial','5Waves3new')):
            expected['switch.table.'+name]=b''.join(v.to_bytes(8,'little') for v in (168,136,168,136))
    for name,value in expected.items():
        require(name in constants and constants[name]['bytes']==len(value) and
            c.previous.readonly(inputs['image'],constants[name]['rva'],len(value))==value,
            'exact concurrent rate/framing/padding constant')
    return dict(globals=spans,constants=constants,runtime_boundaries=runtime)


def handlers_check(records):
    mappings={}
    for name in records:
        if not name.startswith('?dtor$'):continue
        parent=name.split('@?0?',1)[1].removesuffix('@4HA')
        require(parent in records and any(m['symbol']==name and m['target_rva']==records[name]['rva']
            for m in records[parent].get('metadata',[])),'actual parent invokes exact bound funclet')
        mappings[name]=parent
    require(len(mappings)==4 and any(n.startswith('?dtor$55@') for n in mappings),
        'all four actual handlers; listing dtor54 not accepted')
    return mappings


def inspect_route(base,root,mutate=False):
    import windows_enclave_parallel_concurrent_models as models
    spec=inventory.specification(inventory.SPEC.read_bytes())
    inputs,sources=inventory.load(base,root,spec['concurrent'])
    prior_inputs,_=inventory.load(base,root,spec['avx2'])
    functions=c.previous.inventory(inputs['object']);inventory.functions_check(functions,spec['concurrent'])
    prior=c.previous.inventory(prior_inputs['object'])
    records=c.previous.bind_all(inputs['object'],inputs['image'],functions)
    old_records=c.previous.bind_all(prior_inputs['object'],prior_inputs['image'],prior)
    ir=inputs['ir'].decode();old_ir=prior_inputs['ir'].decode()
    exact,changed=c.reuse.exact_reuse(functions,prior,ir,old_ir)
    constants=reuse.constant_contract(inputs['object'],inputs['image'],records,functions,exact)
    require(constants==reuse.constant_contract(prior_inputs['object'],prior_inputs['image'],
        old_records,prior,exact),'every exactly reused helper constant equals sequential evidence')
    assigned,corroborated=assignments(functions,exact)
    n=names(functions);bodies={r:functions[name][0] for r,name in n.items()}
    size=instructions(bodies)
    abis=abi_reuse(functions,ir,prior,old_ir,changed)
    selected=reuse.selected_scheduler(inputs,base)
    composition=models.compose(functions,n,ir)
    for report in selected.values():
        require(report['image_sha256']==digest(inputs['image']),'fresh selected same-image replay')
    count=0
    if mutate:
        for role,code in bodies.items():
            for at in range(len(code)):
                bad=bytearray(code);bad[at]^=1
                try:instructions(bodies|{role:bad})
                except ValueError:count+=1
                else:raise AssertionError('accepted concurrent instruction mutant')
    return dict(object_sha256=digest(inputs['object']),image_sha256=digest(inputs['image']),
        source_sha256=sources,assignments=assigned,corroborating_reviews=corroborated,
        exact_helper_count=len(exact),changed_abi=abis,remaining_handlers=handlers_check(records),
        reachable=inventory.reachability(records,spec['concurrent']['roots']),unassigned=[],
        distinct_semantics={r:v['contract'] for r,v in TABLES.items()},
        distinct_body_bytes=size,distinct_instruction_mutants_rejected=count,
        data_bindings=data_check(inputs,records,functions),caller_lifetime_composition=composition,
        selected_reviews_replayed={n:r['status'] for n,r in selected.items()},
        conditional_rust_family_review_complete=True,whole_image_qualified=False,
        prerequisites=list(PRECONDITIONS))


def inspect(base,root,mutate=False):
    # Exact helper reuse is accepted only after replaying completed Pass A.
    previous=sequential.inspect(base,root,mutate)
    route=inspect_route(base,root,mutate)
    return dict(schema=1,status='AUTHOR_CONDITIONAL_PARALLELHASH_CONCURRENT_ROUTE',
        completion_package=7,pass_number=3,pass_complete=True,completion_package_closed=False,
        whole_image_qualified=False,independently_verified=False,new_native_run=False,
        release_gate_changed=False,shared_runtime_window_package=8,route=route,
        sequential_review_replayed=previous['status'],
        remaining=['combined package-07 reconciliation (Pass C)',
            'pre-existing whole-image/runtime/window obligations in package 08'],
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}|{Path(__file__)})})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('saved_directory',type=Path)
    parser.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    parser.add_argument('--mutate',action='store_true');args=parser.parse_args()
    print(json.dumps(inspect(args.saved_directory,args.source_root,args.mutate),indent=2))
