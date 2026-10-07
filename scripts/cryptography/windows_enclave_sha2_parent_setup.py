"""Six wide-parent SDK memory-call arguments and temporal descriptor reuse.

This closes private argument/region composition, not SDK implementation or
stack qualification. The linked memcpy/memset targets and their runtime/ABI
contracts remain mandatory shared package-8 obligations; no empty effect or
volatile-erasure guarantee is assigned to an ordinary memory runtime call.
"""
import windows_enclave_sha2_parent_outputs as output
p,n,o,s=output.p,output.n,output.o,output.s
# target, destination, source (None for fill), bytes
JOBS=(('memset',1376,None,896),('memcpy',352,1376,1024),
      ('memcpy',1632,4640,2560),('memset',7200,None,1280),
      ('memcpy',11780,352,1024),('memcpy',8480,1376,3264))


def inspect(bodies,assembly,prior):
    physical=prior['simd_physical_allocation_lifetimes'];previous=prior['simd_parent_authority_effects']
    normal=prior['simd_descriptor_normal_effects'];outputs=prior['simd_parent_output_effects']
    descriptors=prior['simd_dynamic_clearing_descriptors']
    s.require(physical['conditional_physical_separation'] is True and
        physical['constructor_result_and_worker_use_joined'] is True and
        previous['operation_original_owner_result_and_authority_callers_joined'] is True and
        outputs['parent_output_transfer_and_cleanup_arguments_checked'] is True and
        descriptors['normal_direct_descriptor_write_lifetimes_checked'] is True,
        'fresh allocation, authority and descriptor lifetime reviews')
    name,lines,edges,states,_=output.prepare(bodies,assembly)
    first,last,_=output.child.d.constructor(bodies,name,'simd512',edges)
    s.require(descriptors['construction']==[first,last],'same original descriptor construction')
    reached=n.g.reachable(edges,first)
    sites=[i for i,v in enumerate(lines) if v in ('callq memcpy','callq memset')]
    s.require(len(sites)==len(JOBS),'complete wide-parent SDK memory-call population')
    calls=[];mapped=[]
    layout={'parent':dict(root='resident-frame',offset=0,bounds=[0,12984])}
    # Input descriptors and operation-result owner slot are already live here;
    # output descriptor regions are constructed later in the same frame.
    protected=[dict(root='resident-frame',span=span) for span in ([64,72],[88,96],[192,352],[120,138])]
    for at,(target,dest,source,size) in zip(sites,JOBS,strict=True):
        s.require(lines[at]=='callq '+target and at not in reached,
                  'no normal path from output descriptor construction re-enters setup')
        roots={}
        for reg,offset in [('rcx',dest)]+([] if source is None else [('rdx',source)]):
            roots[reg]=n.trace(lines,states,at,reg,lambda site,loc:site>=0 and isinstance(loc,str) and
                              lines[site]==f'leaq {offset}(%rbx), %{loc}')
        count=states[at]['r8'];s.require(len(count)==1,'one actual SDK count definition')
        at_count=next(iter(count));s.require(lines[at_count]==f'movl ${size}, %r8d','exact SDK copy/fill width')
        n.straight(edges,at_count,at)
        effects=[['writes','parent',dest,dest+size]]
        if source is None:
            value=states[at]['rdx'];s.require(len(value)==1 and lines[next(iter(value))]=='xorl %edx, %edx',
                                            'initialization fills with zero')
        else:
            s.require(not p.p.cells.overlaps((dest,dest+size),(source,source+size)),
                      'memcpy source and destination are disjoint')
            effects.append(['reads','parent',source,source+size])
        call=dict(line=at,target=target,role='sdk_initialization',bytes=size,pointer_origins=roots,footprints=effects)
        calls.append(call);mapped+=p.exclude(p.footprints(call),protected,layout)
    p.bind_calls(lines,calls)
    keys={(v['line'],v['target']) for v in calls}
    s.require(keys<={(v['line'],v['target']) for v in previous['remaining_parent_calls']},
              'six previously unassigned SDK calls')
    assigned=normal['parent']['assigned']+outputs['assigned']+previous['assigned']+calls
    remaining=p.inventory(lines,assigned)
    return dict(function=name,assigned=calls,assigned_parent_call_count=len(assigned),
        protected_live_setup_objects=protected,mapped_effects=mapped,descriptor_construction=[first,last],
        remaining_parent_calls=remaining,setup_arguments_extents_and_temporal_noninterference_checked=True,
        shared_runtime_calls=[dict(line=v['line'],target=v['target']) for v in calls],
        SDK_memory_semantics_and_stack_contracts_still_required=True,
        memset_is_volatile_erasure=False,whole_frame_qualified=False,
        shared_completion_package=8,shared_prerequisites=physical['prerequisites'])
