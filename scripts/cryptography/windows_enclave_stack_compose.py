"""Acyclic normal-call stack composition with symbolic external boundaries.

Offsets are relative to a function's incoming RSP (including its return slot).
A call adds its return slot; a tail transfer does not. No external boundary is
assigned zero depth: the report retains a prefix plus an unknown suffix. This
does not establish cleanup, stack-argument contents, or exception unwinding.
"""
from windows_enclave_stack_decode import require


def compose(nodes):
    require(nodes,'nonempty normal-call population')
    active=set();cache={};incoming={}

    def argument_area(name,visiting):
        require(name not in visiting,'no recursive tail argument closure')
        if name in incoming:return incoming[name]
        node=nodes[name];need=node.get('incoming_bytes',32)
        require(type(need) is int and need>=0,'explicit incoming argument capacity')
        for scan in node['scans']:
            for call in scan['calls']:
                if call['kind']!='tail':continue
                for target in call['targets']:
                    if target in nodes:need=max(need,argument_area(target,visiting|{name}))
        incoming[name]=need;return need

    def walk(name,residue):
        key=(name,residue)
        require(key not in active,'no recursive cumulative call graph')
        if key in cache:return cache[key]
        active.add(key);node=nodes[name]
        selected=[s for s in node['scans'] if s['entry_residue']==residue]
        require(len(selected)==1,'one stack state for each entry residue')
        scan=selected[0];low=scan['local_low'];witness=[dict(function=name,local_low=low)]
        boundaries={}
        for call in scan['calls']:
            require(call['targets'] and len(call['targets'])==len(set(call['targets'])),
                'nonempty distinct explicitly assigned call alternatives')
            offset=call['entry_offset'];child_residue=(residue+offset)%32
            require(call['kind'] in ('call','tail') and type(offset) is int and offset<=0 and
                (call['kind']!='tail' or offset==0),'bounded call/tail entry offset')
            for target in call['targets']:
                edge=dict(function=name,site=call['site'],kind=call['kind'],target=target,
                    entry_offset=offset)
                if target not in nodes:
                    require(target.startswith('boundary:'),'unassigned callee is never zero depth')
                    child_low=0;child_witness=[]
                    pending={target:dict(prefix_low=0,path=[])}
                else:
                    need=argument_area(target,set())
                    if call['kind']=='call':
                        require(call['allocated_outgoing_bytes']>=need,
                            'caller allocation covers callee home and explicit leaf arguments')
                    child=walk(target,child_residue)
                    child_low=child['known_prefix_low'];child_witness=child['deepest_known_path']
                    pending=child['unresolved_boundaries']
                if offset+child_low<low:
                    low=offset+child_low;witness=[edge]+child_witness
                for boundary,obligation in pending.items():
                    candidate=dict(prefix_low=offset+obligation['prefix_low'],
                        path=[edge]+obligation['path'],unknown_suffix_depth=True)
                    if boundary not in boundaries or candidate['prefix_low']<boundaries[boundary]['prefix_low']:
                        boundaries[boundary]=candidate
        active.remove(key)
        result=dict(known_prefix_low=low,deepest_known_path=witness,
            unresolved_boundaries=dict(sorted(boundaries.items())),
            finite_transitive_bound_proven=not boundaries,
            complete_stack_bytes=-low if not boundaries else None,
            incoming_argument_bytes=argument_area(name,set()))
        cache[key]=result;return result

    return {name:{str(s['entry_residue']):walk(name,s['entry_residue']) for s in node['scans']}
        for name,node in sorted(nodes.items())}
