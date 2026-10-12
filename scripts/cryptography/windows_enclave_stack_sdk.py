"""Saved SDK software-stack prefix; diagnostic/OS suffixes stay explicit.

All twelve bodies are already individually pinned and reviewed. This connects
their actual normal CALL/tail geometry without claiming a loaded module, kernel
stack, arbitrary exception path, TLS erasure, or a complete protected window.
"""
import windows_enclave_stack_review as worker
import windows_enclave_sdk_status as status

require,digest=worker.require,worker.digest


def boundary(site,target):
    return dict(site=site,kind='tail',targets=[target],entry_offset=0,
        allocated_outgoing_bytes=None,os_transition_not_machine_tail=True)


def syscall(raw,name):
    require(name in ('copy_syscall_stub','call_syscall_stub') and
        raw==bytes.fromhex(status.sdk.BODIES[name][1]),'exact reviewed syscall stub')
    # No software PUSH/CALL/RSP adjustment; retain the OS transition as an
    # unknown effect/depth, not a zero-depth leaf. The saved RET follows it.
    return [dict(entry_residue=r,local_low=0,normal_returns=[10],terminal_traps=[],
        calls=[boundary(8,'boundary:os:'+name)]) for r in (8,24)]


def inspect(image,text):
    reviewed=status.inspect(image)
    code=worker.decode.parse(text);population=status.sdk.BODIES|status.BODIES
    addresses={rva:'sdk:'+name for name,(rva,_) in population.items()}
    require(len(addresses)==len(population),'distinct complete SDK bodies')
    nodes={};records={}
    for name,(rva,hexcode) in population.items():
        raw=bytes.fromhex(hexcode)
        body=worker.decode.body(image,dict(rva=rva,size=len(raw)),code)
        scans=syscall(raw,name) if name.endswith('_syscall_stub') else worker.flow.inspect(body,rva,[],set())
        if not name.endswith('_syscall_stub'):
            for scan in scans:
                for edge in scan['calls']:
                    require(edge['target'] is not None,'no unbound indirect SDK call')
                    if edge['target']==status.DEEP_DIAGNOSTIC_RVA:
                        require(name=='diagnostic_entry' and edge['site']==43,
                            'only exact reviewed diagnostic suffix')
                        edge['targets']=['boundary:sdk:diagnostic_retry']
                    else:
                        require(edge['target'] in addresses,'all SDK transfers assigned')
                        edge['targets']=[addresses[edge['target']]]
                if scan['terminal_traps']:
                    require(name=='set_last_error' and scan['terminal_traps']==[23] and
                        scan['local_low']==0,'only exact reviewed SDK debug trap')
                    scan['calls'].append(boundary(23,'boundary:os:debug_trap'))
        nodes['sdk:'+name]=dict(incoming_bytes=32,scans=scans)
        records[name]=dict(rva=rva,bytes=len(raw),body_sha256=digest(raw),scans=scans)
    composed=worker.composition.compose(nodes)
    return dict(image_sha256=digest(image),disassembly_sha256=digest(text.encode()),
        bodies=records,function_geometry=nodes,composed=composed,
        thread_relative_writes=reviewed['thread_relative_writes'],
        diagnostic_depth_proven=False,kernel_storage_qualified=False,loaded_module_identity_proven=False)


def join(nodes,sdk_nodes):
    require(not set(nodes).intersection(sdk_nodes),'separate application and SDK namespaces')
    count=0
    for node in nodes.values():
        for scan in node['scans']:
            for edge in scan['calls']:
                for index,target in enumerate(edge['targets']):
                    if target.startswith('boundary:sdk:'):
                        actual=target.removeprefix('boundary:')
                        require(actual in sdk_nodes,'bound saved SDK target is present')
                        edge['targets'][index]=actual;count+=1
    require(count,'nonempty application/SDK join')
    return nodes|sdk_nodes
