"""Narrow SDK initialization arguments and pre-descriptor storage reuse.

Shared runtime memory/stack contracts stay open. Ordinary memset is not
qualified as volatile erasure, and no private compiler-frame erasure is claimed.
"""
import windows_enclave_sha2_narrow_admission as a
p,n,o,s=a.p,a.n,a.o,a.s
JOBS=(('memset',3936,None,896),('memcpy',2912,3936,1024),('memcpy',4192,864,2048),
      ('memset',6688,None,1344),('memcpy',10792,2912,1024),('memcpy',8032,3936,2752))


def inspect(bodies,assembly,prior):
    previous=prior['simd_narrow_admission_interfaces'];normal=prior['simd_descriptor_normal_effects']
    descriptors=prior['simd_dynamic_clearing_descriptors']
    s.require(previous['original_admission_authority_and_tail_arguments_joined'] is True and
              all(prior[k][v] is True for k,v in a.PREREQUISITES),'current narrow admission and allocation reviews')
    name,lines,states,edges=a.prepare(bodies,assembly)
    first,last,_=p.result.d.constructor(bodies,name,'simd256',edges)
    s.require(descriptors['construction']==[first,last],'same narrow output descriptor construction')
    reached=n.g.reachable(edges,first)
    sites=[i for i,line in enumerate(lines) if line in ('callq memcpy','callq memset')]
    s.require(len(sites)==len(JOBS),'complete six narrow SDK initialization calls')
    protected=[dict(root='resident-frame',span=v) for v in ([88,96],[152,160],[544,864],[240,272])]
    layout={'frame':dict(root='resident-frame',offset=0,bounds=[0,11992])};calls=[];mapped=[]
    for at,(target,dest,source,size) in zip(sites,JOBS,strict=True):
        s.require(lines[at]=='callq '+target and at not in reached,
                  'no normal path from output construction re-enters narrow setup')
        roots={}
        for reg,offset in [('rcx',dest)]+([] if source is None else [('rdx',source)]):
            roots[reg]=n.trace(lines,states,at,reg,lambda site,loc:site>=0 and isinstance(loc,str) and
                              lines[site]==f'leaq {offset}(%rbx), %{loc}')
        count=states[at]['r8'];s.require(len(count)==1,'one narrow SDK count definition')
        count_at=next(iter(count));s.require(lines[count_at]==f'movl ${size}, %r8d','exact narrow SDK extent')
        n.straight(edges,count_at,at)
        effects=[['writes','frame',dest,dest+size]]
        if source is None:
            value=states[at]['rdx'];s.require(len(value)==1 and lines[next(iter(value))]=='xorl %edx, %edx',
                                            'narrow initialization fill is zero')
        else:
            s.require(not p.p.cells.overlaps((dest,dest+size),(source,source+size)),'narrow memcpy ranges disjoint')
            effects.append(['reads','frame',source,source+size])
        call=dict(line=at,target=target,role='sdk_initialization',bytes=size,pointer_origins=roots,footprints=effects)
        calls.append(call);mapped+=p.exclude(p.footprints(call),protected,layout)
    p.bind_calls(lines,calls)
    s.require({(v['line'],v['target']) for v in calls}<=
              {(v['line'],v['target']) for v in previous['remaining_narrow_calls']},'six unassigned narrow SDK calls')
    assigned=normal['assigned']+previous['assigned']+calls
    remaining=p.inventory(lines,assigned+normal['terminal_calls'])
    return dict(function=name,assigned=calls,mapped_effects=mapped,protected_live_setup_objects=protected,
        descriptor_construction=[first,last],remaining_narrow_calls=remaining,
        assigned_narrow_returning_interfaces=len(assigned),setup_arguments_and_temporal_noninterference_checked=True,
        shared_runtime_calls=previous['shared_runtime_calls']+[dict(line=v['line'],target=v['target']) for v in calls],
        SDK_memory_semantics_and_stack_contracts_still_required=True,memset_is_volatile_erasure=False,
        whole_frame_qualified=False,shared_completion_package=8,shared_prerequisites=previous['shared_prerequisites'])
