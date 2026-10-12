"""Join original worker CALLs to complete C adapters and saved SDK exports.

This is offline author stack geometry, not loaded-IAT attestation or cleanup
qualification. Fatal termination and SDK effects retain symbolic suffixes;
neither becomes a zero-depth normal return. Input/lifetime semantics remain
the prerequisite family reviews, not an inference from stack instructions.
"""
import copy
from pathlib import Path
import sys

import windows_enclave_stack_review as worker
import windows_enclave_caller_binding as caller
import windows_enclave_retirement_review as retirement
import windows_enclave_sdk_return as sdk
import windows_enclave_stack_sdk as sdk_stack

require,digest=worker.require,worker.digest
FATAL={'PublicProbeAbort','PrivateWaveAbort'}
EXPORTS={'EnclaveCopyIntoEnclave','EnclaveCopyOutOfEnclave','CallEnclave'}


def identity(identities,name,address):
    require(type(address) is int and 0<address<1<<32,'bounded actual target RVA')
    require(name not in identities or identities[name]==address,'consistent symbol target identity')
    identities[name]=address


def bind(data,image,name,rva):
    """Use the incoming edge, not a potentially ambiguous ICF byte search."""
    raw,refs=caller.function(data,name)
    rows,_=caller.pe.linked(image)
    owners=[r for r in rows if r['rva']<=rva and
        rva+len(raw)<=r['rva']+min(len(r['code']),r['virtual_size'])]
    require(len(owners)==1 and owners[0]['flags']&0xa0000020==0x20000020,
        'complete C body in nonwritable executable storage')
    linked=sdk.mapped(rows,rva,len(raw));normalized=bytearray(linked)
    identities={};occupied=set()
    for ref in refs:
        at=ref['offset']
        require(0<=at<=len(raw)-4 and not occupied.intersection(range(at,at+4)),
            'bounded disjoint relocation operands')
        occupied.update(range(at,at+4))
        address=rva+at+4+ref['trailing']+int.from_bytes(linked[at:at+4],'little',signed=True)-ref['addend']
        identity(identities,ref['symbol'],address)
        normalized[at:at+4]=raw[at:at+4]
    require(bytes(normalized)==raw,'complete original C body matches linked bytes')
    return raw,refs,identities


def transfer(raw,refs,call,targets):
    at=call['site'];indirect=call['target'] is None
    width=2 if indirect else 1
    selected=[r for r in refs if r['offset']==at+width]
    require(len(selected)==1 and selected[0]['addend']==selected[0]['trailing']==0,
        'one exact zero-addend transfer relocation')
    symbol=selected[0]['symbol']
    expected=b'\xff\x15'+bytes(4) if indirect else (
        b'\xe8' if call['kind']=='call' else b'\xe9')+bytes(4)
    require(raw[at:at+len(expected)]==expected,'exact direct or RIP-relative import CALL encoding')
    if indirect:
        require(call['kind']=='call' and symbol=='__imp_CallEnclave','only named scheduler import CALL')
    else:require(call['target']==targets[symbol],'decoded CALL agrees with original COFF target')
    return symbol


def fatal(raw,refs):
    require(raw==bytes.fromhex('b907000000cd29c3') and not refs,
        'complete exact fast-fail helper; no normal-return substitution')
    # The synthetic tail represents an unresolved termination boundary, NOT a
    # machine JMP or a return. Keep the saved trailing RET outside normal paths.
    return dict(incoming_bytes=32,fatal_boundary=True,scans=[dict(entry_residue=r,
        local_low=0,normal_returns=[],terminal_traps=[5],calls=[dict(site=5,kind='tail',
            targets=['boundary:fatal:int29'],entry_offset=0,allocated_outgoing_bytes=None,
            termination_not_machine_tail=True)]) for r in (8,24)])


def import_node(image,saved_sdk,name,rva,table):
    rows,functions=caller.pe.linked(image)
    require(name in EXPORTS and name in table.get('vertdll.dll',{}),'reviewed named SDK import')
    slot=table['vertdll.dll'][name]
    body=sdk.thunk(rows,functions,rva,slot)
    address=sdk.export(saved_sdk,name)
    require(address==sdk.status.sdk.BODIES[name][0],'same reviewed SDK export body')
    record=dict(thunk_rva=rva,thunk_hex=body,iat_rva=slot,sdk_export_rva=address)
    node=dict(incoming_bytes=32,scans=[dict(entry_residue=r,local_low=0,calls=[dict(
        site=0,kind='tail',targets=['boundary:sdk:'+name],entry_offset=0,
        allocated_outgoing_bytes=None)]) for r in (8,24)])
    return node,record


def inspect(base,row,old,text,saved_sdk):
    require(old['route']==row['route'] and old['image_sha256']==row['sha256'],
        'same original worker route and signed image')
    image=(base/row['image']).read_bytes()
    require(digest(image)==row['sha256'],'original signed application bytes')
    data=(base/row.get('object','scheduler-register-nospill/concurrent.obj')).read_bytes()
    require(digest(data)==row.get('object_sha256',retirement.C_OBJECT),'original native object identity')
    require(digest(text.encode())==old['disassembly_sha256'],'same retained decoded application')
    nodes=copy.deepcopy(old['function_geometry']);identities={};seeds=set()
    for node in nodes.values():
        for scan in node['scans']:
            for edge in scan['calls']:
                for target in edge['targets']:
                    if target.startswith('boundary:'):
                        name=target.removeprefix('boundary:')
                        require(name.startswith(('Public','Private')),'named original C boundary')
                        identity(identities,name,edge['target']);seeds.add(name)
                edge['targets']=[v.removeprefix('boundary:') for v in edge['targets']]
    require(seeds,'nonempty actual C boundary population')
    instructions=worker.decode.parse(text);queue=sorted(seeds);records={};imports={}
    table=sdk.imports(image)
    while queue:
        name=queue.pop(0)
        if name in records:continue
        require(name not in nodes,'disjoint C and worker populations')
        rva=identities[name];raw,refs,targets=bind(data,image,name,rva)
        for symbol,address in targets.items():identity(identities,symbol,address)
        code=worker.decode.body(image,dict(rva=rva,size=len(raw)),instructions)
        node=fatal(raw,refs) if name in FATAL else dict(incoming_bytes=32,
            scans=worker.flow.inspect(code,rva,[],set()))
        if name not in FATAL:
            for scan in node['scans']:
                for edge in scan['calls']:
                    target=transfer(raw,refs,edge,targets)
                    if target=='__imp_CallEnclave':
                        require(table.get('vertdll.dll',{}).get('CallEnclave')==targets[target],
                            'indirect scheduler call uses exact named IAT slot')
                        export=sdk.export(saved_sdk,'CallEnclave')
                        require(export==sdk.status.sdk.BODIES['CallEnclave'][0],'reviewed CallEnclave export')
                        imports[target]=dict(iat_rva=targets[target],sdk_export_rva=export)
                        edge['targets']=['boundary:sdk:CallEnclave']
                    elif target in EXPORTS:
                        thunk,record=import_node(image,saved_sdk,target,targets[target],table)
                        imports[target]=record;nodes['import:'+target]=thunk
                        edge['targets']=['import:'+target]
                    else:
                        require(target.startswith(('Public','Private')) or target=='scheduler_complete',
                            'no unreviewed C transfer closure')
                        queue.append(target);edge['targets']=[target]
        nodes[name]=node
        records[name]=dict(rva=rva,bytes=len(raw),object_body_sha256=digest(raw),
            reference_targets=targets,fatal_boundary=name in FATAL,scans=node['scans'])
    composed=worker.composition.compose(nodes)
    roots={name:composed[name] for name in old['roots']}
    require(all(not name.startswith(('boundary:Public','boundary:Private'))
        for variants in roots.values() for result in variants.values()
        for name in result['unresolved_boundaries']),'all incoming C boundaries joined')
    return dict(route=row['route'],image_sha256=digest(image),native_object_sha256=digest(data),
        disassembly_sha256=digest(text.encode()),seed_boundaries=sorted(seeds),c_bodies=records,
        imports=imports,roots=roots,function_geometry=nodes,
        complete_protected_window_bound_proven=False,loaded_iat_attested=False)


def collect(base,root,disassembly):
    previous=worker.collect(base,root,disassembly)
    saved_sdk=(base/'sdk-system32-review/vertdll.dll').read_bytes()
    sdk_review=sdk.sdk_review.inspect(saved_sdk)
    sdk_geometry=sdk_stack.inspect(saved_sdk,
        (disassembly/(digest(saved_sdk)+'.txt')).read_text(encoding='utf-8'))
    rows=worker.workers.catalog.catalog()
    require(len(rows)==len(previous['records'])==19,'complete frozen route population')
    records=[inspect(base,row,old,(disassembly/(row['sha256']+'.txt')).read_text(encoding='utf-8'),
        saved_sdk) for row,old in zip(rows,previous['records'])]
    for record in records:
        nodes=sdk_stack.join(record['function_geometry'],sdk_geometry['function_geometry'])
        composed=worker.composition.compose(nodes)
        record['roots']={name:composed[name] for name in record['roots']}
        record['function_geometry']=nodes
    return dict(schema=1,status='AUTHOR_C_TRANSPORT_STACK_JOIN_WITH_EXPLICIT_SDK_SUFFIXES',
        records=records,sdk_review=sdk_review,sdk_geometry=sdk_geometry,whole_image_qualified=False,
        completion_package_closed=False,new_native_enclave_run=False,release_gate_changed=False,
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted({Path(m.__file__)
            for n,m in sys.modules.items() if n.startswith('windows_enclave_')})})
