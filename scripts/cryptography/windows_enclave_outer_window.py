"""Original nineteen-image outer reclamation and worker-entry reconciliation.

Checks the returning Brynja boundary, not arbitrary exceptions, SDK depth or
loaded-module attestation. A known worker prefix is never a full window bound.
"""
from pathlib import Path
import sys

import windows_enclave_stack_bridge as bridge
import windows_enclave_sequential_c as sequential
import windows_enclave_wrapper_return as concurrent

require,digest=bridge.require,bridge.digest
WRAPPERS={
    'sequential':('PublicLockedFrame','register-cleanup-nospill/baseline/window_rust_x64.obj',
        sequential.WRAPPER,'d0bac93439c8013339ed6a63a2a8a038e9b12d7c65399b599d507a9431f597ea'),
    'concurrent':('PublicStackFrame','scheduler-register-nospill/frame.obj',
        '68d4731bc3f45d373050c9e8563740aa5c355574e10512a6939eca999dbcedae',
        concurrent.BODIES['wrapper'][2]),
}
LAYOUT={
    'sequential':dict(body=0xb2,clear=0x107,readback=0x11d,dirty=0x12c,finish=0x135,
        restore=0x142,final=0x150,ret=0x187,body_name='PublicRustBody'),
    'concurrent':dict(body=0xae,clear=0x104,readback=0x116,dirty=0x125,finish=0x12d,
        restore=0x143,final=0x15a,ret=0x191,body_name='PublicStackBody'),
}


def dominates(edges,entry,required,target):
    """Deleting a required instruction must disconnect entry from target."""
    todo=[entry];seen=set()
    while todo:
        at=todo.pop()
        if at==required or at in seen:continue
        require(at in edges,'complete CFG for dominance')
        if at==target:return False
        seen.add(at);todo.extend(edges[at])
    return True


def instructions(code,rva,lane):
    require(lane in LAYOUT,'known wrapper layout')
    plan=LAYOUT[lane];edges,transfers=bridge.worker.decode.graph(code,rva,[])
    def exact(at,raw):
        wanted=bytes.fromhex(raw);cursor=at;actual=b''
        while len(actual)<len(wanted):
            require(cursor in code,'complete wrapper instruction sequence')
            chunk=code[cursor][0];actual+=chunk;cursor+=len(chunk)
        require(actual==wanted,'reviewed wrapper instruction sequence')
    exact(0,'55488bec48894d10')
    exact(8,'48c74520000000004c8bd3b8010000000fa281e10000001c81f90000001c')
    exact(0x28,'33c90f01d083e00683f806')
    exact(0x35,'48c7452001000000498bda4533d2')
    exact(0x43,'48c7c020400100')
    exact(0x4f,'482be0488bc5482500f0ffff482d00100000')
    exact(0xf7,'498da2e0efffff')
    exact(plan['clear']-2,'33c0')
    exact(plan['clear'],'4989024983c2084c3bd2')
    exact(plan['readback']-3,'4533c9')
    exact(plan['readback'],'4d0b0a4983c2084c3bd2')
    exact(plan['dirty']-3,'4d85c9')
    for start in (0xbf,plan['final']):
        exact(start,'48837d20007403c5f877660fefc0660fefc9660fefd2660fefdb660fefe4660fefed')
    exact(0xe1,'33c033c933d24533c94533d24533db')
    exact(plan['final']+34,'33c933d24533c04533c94533d24533db488d65005dc3')
    # Both loop bodies execute before their backward test; the exact guarded
    # range and loop stride are checked separately, not inferred by dominance.
    for loop in (plan['clear'],plan['readback']):
        branch=loop+10
        require(code[branch][0]==bytes.fromhex('72f4') and edges[branch][0]==loop,
            'exact full-word backward clear/readback loop')
    require(set(transfers)=={0x4a,0x7c,plan['body'],plan['finish'],plan['restore']},
        'only the five reviewed wrapper calls')
    require([at for at,(_,text) in code.items() if text=='retq']==[plan['ret']],
        'single wrapper return')
    required=[plan['clear'],plan['readback'],plan['restore']]
    required += [0xc9+i*4 for i in range(6)]
    required += [plan['final']+10+i*4 for i in range(6)]
    require(all(dominates(edges,0,at,plan['ret']) for at in required),
        'every normal return traverses window/readback and both vector clears')
    require(dominates(edges,0,plan['dirty'],plan['finish']),
        'finish callback cannot bypass readback decision')
    clean=plan['dirty']+len(code[plan['dirty']][0])
    require(dominates(edges,0,clean,plan['finish']) and
        not dominates(edges,0,plan['body'],plan['ret']),
        'only clean branch may finish; denied admission still reclaims')
    return dict(checked_return=plan['ret'],mandatory_instructions=required,
        normal_return_order=['worker returns or admission denies','volatile register clear',
            'entire window zero','entire window readback','conditional finish','restore attempt',
            'final volatile register clear','public result return'])


def geometry(rbp,entry_offset,known_prefix):
    require(type(rbp) is int and 81952<rbp<(1<<64)-4096 and rbp%16==0,
        'bounded aligned original wrapper frame')
    require(entry_offset in (-104,-216) and type(known_prefix) is int and known_prefix<=0,
        'reviewed worker entry and signed prefix')
    high=(rbp&-4096)-4096;low=high-65536;bootstrap=low-4128
    require(rbp-81952<=bootstrap-8 and high+4096<=rbp,'probe covers local bootstrap and guards')
    require(low<=high+entry_offset+known_prefix<high,'known worker chain fits clear span')
    return dict(window_bytes=high-low,body_entry_from_high=-40,
        worker_entry_from_high=entry_offset,worker_entry_residue=(high+entry_offset)%32,
        known_low_from_high=entry_offset+known_prefix,clear_words=8192,
        clear_first_from_low=0,clear_last_from_low=65528,
        bootstrap_from_low=bootstrap-low,full_stack_bound_proven=False)


def body_scan(data,image,entry,name,ins):
    raw,refs,targets=bridge.bind(data,image,name,entry)
    code=bridge.worker.decode.body(image,dict(rva=entry,size=len(raw)),ins)
    if name=='PublicRustBody':
        sequential.check_body(name,raw,refs)
        scans=bridge.worker.flow.inspect(code,entry,[],set())
        require(all(v['local_low']==-56 for v in scans),'sequential body actual frame')
        selected=[(v['site'],v['target'],v['entry_offset']) for v in scans[0]['calls']
            if v['target']==targets['RetainedWork']]
        require(selected==[(454,targets['RetainedWork'],-64),(627,targets['RetainedWork'],-64)],
            'both retained worker calls after real 56-byte body frame')
        return dict(frame_bytes=56,worker_entry_from_high=-104,roots=['RetainedWork'],
            worker_calls=selected,other_calls_remain_separate=True)
    require(name=='PublicStackBody' and len(raw)==340 and
        digest(raw)==concurrent.BODIES['body'][2],'exact original concurrent outer body')
    # This body restores RSP through R11. Use its exact emitted prologue and
    # epilogue, not an invented generic frame rule or absent-unwind assumption.
    require(raw[:19]==bytes.fromhex('4c8bdc49895b1049897318574881eca0000000') and
        raw[319:]==bytes.fromhex('4c8d9c24a0000000498b5b18498b7320498be35fc3'),
        'complete 168-byte concurrent save/allocation/restore')
    _,calls=bridge.worker.decode.graph(code,entry,[])
    require(all(19<=at<319 and call['kind']=='call' for at,call in calls.items()),
        'every concurrent call occurs after allocation and before restoration')
    selected=[]
    for at,name in ((255,'PrivateWaveRoot'),(283,'PrivateWaveLeaf')):
        require(calls[at]['target']==targets[name] and
            any(v['offset']==at+1 and v['symbol']==name for v in refs),'same root/leaf incoming edge')
        selected.append((at,targets[name],-176))
    return dict(frame_bytes=168,worker_entry_from_high=-216,
        roots=['PrivateWaveRoot','PrivateWaveLeaf'],worker_calls=selected,
        other_calls_remain_separate=True)


def join_prefixes(report,stack):
    """Join actual entry residues, never substituting a known prefix for a bound."""
    records=report['records'];prior=stack['records']
    require(len(records)==len(prior)==19,'complete outer/worker population')
    require(len({v['route'] for v in records})==19 and
        len({v['route'] for v in prior})==19,'unique outer/worker population')
    indexed={v['route']:v for v in prior}
    require(set(indexed)=={v['route'] for v in records},'same outer/worker routes')
    for row in records:
        saved=indexed[row['route']]
        require(row['image_sha256']==saved['image_sha256'] and
            row['disassembly_sha256']==saved['disassembly_sha256'],'same original code and decoder input')
        offset=row['body']['worker_entry_from_high'];residue=offset%32
        extra={'RetainedTokenWord'} if row['route']=='mod.rs::open' else set()
        require(set(row['body']['roots'])|extra==set(saved['roots']),'complete actual incoming roots')
        for name in extra:
            require(all(v['complete_stack_bytes']==0 and not v['unresolved_boundaries']
                for v in saved['roots'][name].values()),'separate zero-frame token leaf')
        row['separate_non_worker_roots']=sorted(extra)
        roots={}
        for name in row['body']['roots']:
            result=saved['roots'][name][str(residue)]
            leaf=row['route']=='parallel_concurrent/mod.rs::open_avx2' and name=='PrivateWaveLeaf'
            if leaf:
                require(not result['unresolved_boundaries'] and
                    result['complete_stack_bytes']==-result['known_prefix_low'],
                    'closed leaf bound remains distinct from its enclosing scheduler')
            else:
                require(result['complete_stack_bytes'] is None and result['unresolved_boundaries'],
                    'remaining SDK/OS suffixes cannot become a complete stack bound')
            roots[name]=dict(geometry=geometry(0x100000,offset,result['known_prefix_low']),
                closed_worker_leaf=leaf,unresolved_boundaries=result['unresolved_boundaries'])
        row['actual_entry_prefixes']=roots
    report['maximum_known_prefix_from_window_high']=max(
        -v['geometry']['known_low_from_high'] for row in records
        for v in row['actual_entry_prefixes'].values())
    return report


def collect(base,disassembly):
    records=[]
    for row in bridge.worker.workers.catalog.catalog():
        lane='sequential' if 'object' in row else 'concurrent'
        name,path,object_sha,body_sha=WRAPPERS[lane]
        image=(base/row['image']).read_bytes();wrapper=(base/path).read_bytes()
        require(digest(image)==row['sha256'] and digest(wrapper)==object_sha,'actual image/wrapper identity')
        raw,refs=bridge.caller.function(wrapper,name)
        require(digest(raw)==body_sha,'complete reviewed wrapper body')
        bound=bridge.caller.pe.bind(wrapper,image,name)
        text=(disassembly/(row['sha256']+'.txt')).read_text(encoding='utf-8')
        ins=bridge.worker.decode.parse(text)
        code=bridge.worker.decode.body(image,bound,ins)
        contract=instructions(code,bound['rva'],lane)
        native=(base/row.get('object','scheduler-register-nospill/concurrent.obj')).read_bytes()
        require(digest(native)==row.get('object_sha256',bridge.retirement.C_OBJECT),'original C object')
        body=body_scan(native,image,bound['call_target_rvas'][LAYOUT[lane]['body_name']],LAYOUT[lane]['body_name'],ins)
        data,_=bridge.worker.workers.load(base,row);_,workers=bridge.worker.workers.bind(data,image)
        require([v[1] for v in body['worker_calls']]==[workers[n]['rva'] for n in
            (['RetainedWork']*2 if lane=='sequential' else body['roots'])],'exact reviewed worker connections')
        if lane=='sequential':
            c_review=sequential.inspect(native,image,wrapper)
            require(c_review['wrapper_rva']==bound['rva'],'same whole C scaffold binding')
        else:
            for role in ('body','finish','restore'):
                symbol,size,sha=concurrent.BODIES[role]
                candidate,_,_=bridge.bind(native,image,symbol,bound['call_target_rvas'][symbol])
                require(len(candidate)==size and digest(candidate)==sha,'reviewed concurrent postclear C body')
        records.append(dict(route=row['route'],image_sha256=digest(image),wrapper_object_sha256=digest(wrapper),
            wrapper_body_sha256=body_sha,wrapper_rva=bound['rva'],body=body,contract=contract,
            disassembly_sha256=digest(text.encode()),memory_clear_bytes=65536,
            complete_stack_bound_proven=False,whole_image_qualified=False))
    return dict(schema=1,status='AUTHOR_OUTER_RETURN_AND_WORKER_ENTRY_RECONCILIATION',records=records,
        normal_return_boundary_bound=True,arbitrary_exception_cleanup_qualified=False,
        whole_image_qualified=False,completion_package_closed=False,release_gate_changed=False,
        new_native_enclave_run=False,source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')})})
