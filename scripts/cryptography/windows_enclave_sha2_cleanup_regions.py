"""Finite normal-CFG descriptor validity for saved clearing callers.

Direct stores include partial/overlapping and computed writes. Indirect effects
and helper/ABI contracts must be joined separately; this is not a general x86
memory model or a claim of individual frame erasure.
"""
import re
import windows_enclave_sha2_narrow_cfg as n
import windows_enclave_sha2_failstop as guards
o,g,s=n.o,n.g,n.s


def loop(lines,graph,seed,skip,head,end,index,address,size,extra=(),vector=False):
    """Complete emitted zeroizer loop, including both distinct advance paths."""
    reg='esi' if index=='rsi' else 'edi'
    pointer,length=address
    expected=[f'xorl %{reg}, %{reg}',*extra,f'cmpq ${size}, %{index}',
        'jne '+head,'jmp '+end,skip+':',f'addq $16, %{index}',
        f'cmpq ${size}, %{index}','je '+end,head+':',
        f'movq {pointer}, %rcx','testq %rcx, %rcx','je '+skip,
        f'movq {length}, %rdx','testq %rdx, %rdx','je '+skip]
    if vector:expected+=['vzeroupper']
    expected+=['callq '+s.ZERO,f'addq $16, %{index}',f'cmpq ${size}, %{index}','jne '+head]
    last=o.unique(lines,end+':');actual=lines[seed:last]
    s.require([v for v in actual if not v.startswith('.p2align')]==expected,
              'complete bounded cleanup loop and paired pointer/length loads')
    guards.single_entry(graph,seed,last-1)
    s.require(size in (64,128),'assigned four/eight-lane descriptor extent')
    at=seed+actual.index('callq '+s.ZERO)
    return dict(seed=seed,read=seed+actual.index(f'movq {pointer}, %rcx'),call=at,
        exit=last,index_offsets=list(range(0,size,16)),null_and_empty_skipped=True)


def copy(bodies,name,first,last,source,destination,size,graph):
    from windows_enclave_sha2_simd_moves import trace
    lines=s.lines(bodies[name]);a=o.unique(lines,first);b=a+o.unique(lines[a:],last)
    result=trace('\n'.join(lines[a:b+1]),first,last,source,destination,size)
    n.straight(graph,a,b)
    return result|dict(first_line=a,last_line=b)


def lifetime(lines,graph,bases,regions,initializers,reads,indexed=None,flags=(),guarded=None,edge_initializers=None):
    """Track initialized descriptor regions and output-drop guard flags together.

Reads occur before the instruction; a final construction store establishes its
region only after that instruction. Every other overlapping direct write kills
the fact. A copied region is only initialized when its source is already valid.
"""
    indexed=indexed or {};guarded=guarded or {};edge_initializers=edge_initializers or {}
    names=tuple(regions);positions={k:i for i,k in enumerate(names)}
    todo=[(0,frozenset(),tuple(None for _ in flags))];seen=set();before={}
    writes=set();read_sites=set();guarded_sites=set();initialized_edges=set()
    while todo:
        at,valid,flag_values=todo.pop();key=(at,valid,flag_values)
        if key in seen:continue
        seen.add(key);s.require(at in graph,'closed descriptor-lifetime CFG')
        before.setdefault(at,set()).add((valid,flag_values))
        required=set(reads.get(at,()))
        for root,flag in guarded.get(at,()):
            value=flag_values[flags.index(flag)] if flag is not None else 1
            s.require(value in (0,1),'initialized bool guard for invoked descriptor cleanup')
            if value:required.add(root)
            guarded_sites.add(at)
        s.require(required<=valid,'clearing descriptor read before construction or after overwrite')
        if required:read_sites.add(at)
        op,args=o.source.instruction(lines[at]);new=set(valid);new_flags=list(flag_values)
        span=None if op=='callq' else o.source.store_span(op,args,bases)
        if span==o.source.INDEXED_FRAME:span=indexed.get(at,span)
        if span:
            for root,area in regions.items():
                if o.source.cells.overlaps(span,area):new.discard(root);writes.add(at)
            for i,flag in enumerate(flags):
                if o.source.cells.overlaps(span,(flag,flag+1)):
                    match=re.fullmatch(r'movb \$([01]), '+str(flag)+r'\(%rbx\)',lines[at])
                    new_flags[i]=int(match[1]) if match else None
        for root,source in initializers.get(at,()):
            s.require(root in positions and (source is None or source in valid),
                      'descriptor copy requires its original initialized source')
            new.add(root)
        for dest in graph[at]:
            next_valid=set(new)
            for root,source in edge_initializers.get((at,dest),()):
                s.require(root in positions and (source is None or source in new),
                          'conditional result requires the original initialized source')
                next_valid.add(root);initialized_edges.add((at,dest))
            todo.append((dest,frozenset(next_valid),tuple(new_flags)))
    s.require(set(reads)<=before.keys() and set(initializers)<=before.keys() and set(guarded)<=before.keys(),
              'all descriptor lifetime events are reachable')
    s.require(initialized_edges==set(edge_initializers),'all conditional initialization edges are real and reachable')
    result=dict(reachable_states=len(seen),direct_write_sites=sorted(writes),
        required_read_sites=sorted(read_sites),guarded_invoke_sites=sorted(guarded_sites))
    if edge_initializers:result['conditional_initialization_edges']=sorted(initialized_edges)
    return result,before
