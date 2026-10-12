"""Executable design criterion, NOT implementation or release qualification.

A proposed secret worker must have no reachable SDK/import/unassigned transfer.
The explicit fatal trap remains outside normal-return erasure. Current workers
are expected to reject; changing this model does not authorize existing images.
"""
from windows_enclave_outer_window import require


def compute_closure(nodes,roots):
    require(isinstance(nodes,dict) and nodes and isinstance(roots,list) and roots
        and len(roots)==len(set(roots)),'nonempty explicit compute population')
    pending=list(roots);seen=set();fatal=False
    while pending:
        name=pending.pop()
        require(isinstance(name,str) and name,'explicit compute target')
        if name=='boundary:fatal:int29':
            fatal=True
            continue
        require(not name.startswith(('sdk:','import:','boundary:')),
            'secret compute cannot enter SDK/import/unknown boundary: '+name)
        require(name in nodes,'missing compute callee: '+name)
        if name in seen:continue
        seen.add(name);node=nodes[name];scans=node.get('scans')
        require(isinstance(scans,list),'explicit compute scans')
        residues={v.get('entry_residue') for v in scans}
        require(len(scans)==len(residues) and (residues=={8,24} or
            (node.get('runtime_summary') is True and residues=={0,8,16,24})),
            'both complete compute entry residues or reviewed four-residue runtime summary')
        for scan in scans:
            require(isinstance(scan.get('calls'),list),'explicit complete compute transfers')
            for call in scan['calls']:
                targets=call.get('targets')
                require(isinstance(targets,list) and targets and all(isinstance(v,str) for v in targets)
                    and len(targets)==len(set(targets)),'all compute call alternatives assigned')
                pending.extend(targets)
    return dict(functions=sorted(seen),sdk_free_call_graph=True,
        fatal_trap_possible=fatal,stack_bound_proven=False,implementation_qualified=False)
